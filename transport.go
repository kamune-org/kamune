package kamune

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/kamune-org/kamune/internal/clock"
	"github.com/kamune-org/kamune/internal/enigma"
	"github.com/kamune-org/kamune/pkg/storage"
)

// closeFrameTimeout bounds how long [Transport.Close] waits for its close frame
// to be sent. It leaves room for a full frame already being written on a slow
// link, while a peer that stops reading holds Close up only this long.
const closeFrameTimeout = 5 * time.Second

// connDropErrors are [Conn] read errors that mean the connection was closed
// locally, closed by the peer, or dropped by the network.
var connDropErrors = []error{
	ErrConnClosed,
	io.EOF,
	io.ErrUnexpectedEOF,
	io.ErrClosedPipe,
	net.ErrClosed,
	syscall.ECONNRESET,
	syscall.ECONNABORTED,
	syscall.EPIPE,
}

// isConnDrop reports whether err means the connection is gone.
func isConnDrop(err error) bool {
	for _, target := range connDropErrors {
		if errors.Is(err, target) {
			return true
		}
	}
	return false
}

// isTimeout reports whether err is a deadline/timeout error, either from
// [os.ErrDeadlineExceeded] or from a [net.Error] with Timeout() true.
func isTimeout(err error) bool {
	switch {
	case errors.Is(err, os.ErrDeadlineExceeded):
		return true
	default:
		ne, ok := errors.AsType[net.Error](err)
		return ok && ne.Timeout()
	}
}

// Transport handles encrypted message exchange with route-based dispatch.
//
// A Transport that receives a frame it must not process further closes its
// connection. A failed inner signature, a route that is not a session route,
// or [RouteCloseTransport] deletes the resumption row. A decrypt failure, a
// duplicate or a gap, and a connection drop touch the row and leave it. A
// compare-and-swap conflict leaves a newer row in place. Every later Receive
// returns the same error, and Send fails with [ErrConnClosed]. Only
// [RouteCloseTransport] tells the peer. In the other cases the peer sees the
// connection drop.
//
// Closing a Transport deletes its resumption row. A compare-and-swap conflict
// leaves a newer row in place. A session without persistence stores no row.
type Transport struct {
	conn         Conn
	acceptedMeta any
	termErr      error
	clock        clock.Clock
	serde        *signedSerde
	encoder      *enigma.Enigma
	decoder      *enigma.Enigma
	mu           *sync.Mutex
	remotePeer   *storage.Peer
	storage      *storage.Storage
	sessionID    string
	exporter     []byte
	closeTimeout time.Duration
	resGen       uint64
	sendSequence uint64
	recvSequence uint64
	resRelease   sync.Once
	sendMu       sync.Mutex
	recvMu       sync.Mutex
	resDropped   atomic.Bool
	resRole      storage.ResumeRole
	resumed      bool
	resHeld      bool
}

func newTransport(
	conn Conn,
	serde *signedSerde,
	sessionID string,
	encoder, decoder *enigma.Enigma,
) *Transport {
	return &Transport{
		conn:         conn,
		mu:           &sync.Mutex{},
		encoder:      encoder,
		decoder:      decoder,
		sessionID:    sessionID,
		serde:        serde,
		closeTimeout: closeFrameTimeout,
	}
}

// Receive reads and decrypts the next message from the connection.
// It populates the dst, returns the metadata and any error.
func (t *Transport) Receive(dst Transferable) (*Metadata, error) {
	metadata, message, err := t.ReceivePayload()
	if err != nil {
		return nil, err
	}
	if err := proto.Unmarshal(message, dst); err != nil {
		return nil, fmt.Errorf("deserializing message: %w", err)
	}
	return metadata, nil
}

// ReceivePayload reads and decrypts the next message and returns the verified
// protobuf bytes without unmarshalling them into a caller type.
//
// It returns [ErrReceiveTimeout] when the read deadline passes before any byte
// of the next frame has arrived; the caller may retry. A connection that drops
// or times out part-way through a frame yields [ErrConnClosed].
//
// ReceivePayload and Receive are safe for concurrent use. Calls are served one
// at a time in wire order, and each frame goes to exactly one caller.
func (t *Transport) ReceivePayload() (*Metadata, []byte, error) {
	// Hold recvMu from the read through the sequence check, so that frames read
	// by concurrent callers are checked in the order they arrived.
	t.recvMu.Lock()
	defer t.recvMu.Unlock()

	if err := t.terminated(); err != nil {
		return nil, nil, err
	}

	payload, err := t.conn.ReadBytes()
	switch {
	case err == nil: // continue
	case isConnDrop(err):
		t.touchResumption()
		return nil, nil, ErrConnClosed
	case isTimeout(err):
		return nil, nil, ErrReceiveTimeout
	default:
		return nil, nil, fmt.Errorf("reading payload: %w", err)
	}

	decrypted, err := t.decoder.Decrypt(payload)
	if err != nil {
		return nil, nil, t.terminate(
			fmt.Errorf("decrypting payload: %w", err), true,
		)
	}

	metadata, message, err := t.serde.verify(decrypted)
	if err != nil {
		return nil, nil, t.terminate(
			fmt.Errorf("deserializing: %w", err), false,
		)
	}

	// Validate per-message sequence number to detect duplicates, missing, or
	// out-of-order messages.
	seq := metadata.SequenceNum()
	t.mu.Lock()
	expected := t.recvSequence + 1
	if seq != expected {
		t.mu.Unlock()
		// A duplicate or gap violates the ordered, reliable Conn contract. The
		// session cannot safely continue because a missing frame may have
		// carried stateful protocol or application data.
		if seq < expected {
			return nil, nil, t.terminate(fmt.Errorf(
				"%w: duplicate message seq %d, expected %d",
				ErrOutOfSync, seq, expected,
			), true)
		}
		return nil, nil, t.terminate(fmt.Errorf(
			"%w: missing messages, got seq %d, expected %d",
			ErrOutOfSync, seq, expected,
		), true)
	}
	t.recvSequence = seq
	t.mu.Unlock()

	route := metadata.Route()
	if err := t.checkRoute(route); err != nil {
		return nil, nil, t.terminate(err, false)
	}
	if route == RouteCloseTransport {
		// The peer will send nothing more; close the session so that no frame
		// queued behind the close is processed.
		return nil, nil, t.terminate(ErrPeerDisconnected, false)
	}

	return metadata, message, nil
}

// Send encrypts and sends a message with the specified route.
//
// An error wrapping [ErrConnClosed] means the connection is gone, for example
// because a write failed part-way through the frame; the caller must not retry
// on this Transport.
func (t *Transport) Send(message Transferable, route Route) (*Metadata, error) {
	if !route.IsValid() {
		return nil, fmt.Errorf("%w: %s", ErrInvalidRoute, route)
	}
	if err := t.checkRoute(route); err != nil {
		return nil, err
	}
	if err := t.terminated(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrConnClosed, err)
	}

	// Keep sequence allocation, serialization, and the frame write in the same
	// critical section. Otherwise concurrent callers can put later sequence
	// numbers on the wire first, or a serialization failure can create a gap.
	t.sendMu.Lock()
	defer t.sendMu.Unlock()

	seq := t.sendSequence + 1
	payload, metadata, err := t.serde.serialize(message, route, seq)
	if err != nil {
		return nil, fmt.Errorf("serializing: %w", err)
	}

	if err := t.conn.WriteBytes(t.encoder.Encrypt(payload)); err != nil {
		return nil, fmt.Errorf("writing: %w", err)
	}
	t.sendSequence = seq

	return metadata, nil
}

// Close ends the session and closes the transport connection. It sends a
// [RouteCloseTransport] frame before closing (best-effort — if the send fails,
// it closes directly) and deletes the session's resumption row, whether or not
// the frame could be sent, so neither side can resume the session afterwards.
// To keep a session resumable after its connection drops, as when Receive
// returns [ErrConnClosed], use [Transport.CloseAbort] instead. It returns nil
// when Receive has already closed the transport.
//
// Closing a generation whose stored row is newer is a compare-and-swap conflict
// and leaves that row in place. A session without persistence stores no row.
//
// Close waits at most 5 seconds for the close frame to be sent, including the
// wait for a Send already in progress, and then closes the connection whether
// or not the frame went out. A peer that stops reading cannot hold it up for
// longer. A peer that does not get the frame in time sees the connection drop,
// as [ErrConnClosed] rather than [ErrPeerDisconnected].
//
// The frame is written from a goroutine that ends when the write does. Closing
// the connection ends a pending write on a network connection. A [Conn] whose
// Close does not, such as one accepted from a relay listener, which shares the
// listener's link to the relay, keeps that goroutine until the pending write
// completes or the link fails.
func (t *Transport) Close() error {
	t.zeroExporter()
	if t.terminated() != nil {
		_ = t.conn.Close()
		return nil
	}

	sent := make(chan error, 1)
	go func() {
		_, err := t.Send(Bytes(nil), RouteCloseTransport)
		sent <- err
	}()
	timer := time.NewTimer(t.closeTimeout)
	defer timer.Stop()
	select {
	case <-sent:
	case <-timer.C:
		// Closing the connection below ends a stuck write on a network
		// connection, and the goroutine then returns. See the doc comment for
		// Conns whose Close does not.
	}
	// The session is over even if the peer never got the close frame, so it
	// must not be resumed.
	t.endResumption()
	return t.conn.Close()
}

// CloseAbort closes the underlying connection abruptly without transmitting a
// [RouteCloseTransport] frame or deleting the resumption row. It touches the
// row, so the session can still be resumed. Used when a connection drops or
// fails keepalive.
func (t *Transport) CloseAbort() error {
	t.zeroExporter()
	t.touchResumption()
	return t.conn.Close()
}

// Resumed reports whether this session continued an earlier one.
func (t *Transport) Resumed() bool { return t.resumed }

// ExportKeyingMaterial derives length bytes for label and context. After Close,
// CloseAbort, or termination it returns [ErrConnClosed].
func (t *Transport) ExportKeyingMaterial(
	label string, context []byte, length int,
) ([]byte, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.termErr != nil || len(t.exporter) == 0 {
		return nil, ErrConnClosed
	}
	return exportKeyingMaterial(t.exporter, label, context, length)
}

func (t *Transport) zeroExporter() {
	t.mu.Lock()
	defer t.mu.Unlock()
	for i := range t.exporter {
		t.exporter[i] = 0
	}
	t.exporter = nil
}

// terminate records err as the terminal error of t, unless one is already
// recorded, wipes the exporter, closes the connection and returns err.
//keepState false deletes the resumption row at t.resGen. keepState true
// touches that row and leaves it, for a failure anyone on the path can cause.
// The exporter is wiped in this critical section. zeroExporter takes t.mu
// itself, so calling it here would deadlock.
func (t *Transport) terminate(err error, keepState bool) error {
	t.mu.Lock()
	first := t.termErr == nil
	if first {
		t.termErr = err
		for i := range t.exporter {
			t.exporter[i] = 0
		}
		t.exporter = nil
	}
	t.mu.Unlock()
	_ = t.conn.Close()
	if first {
		if keepState {
			t.touchResumption()
		} else {
			t.endResumption()
		}
	}
	return err
}

// endResumption deletes the resumption row at t.resGen.
func (t *Transport) endResumption() {
	if t.storage == nil || t.sessionID == "" || t.resGen == 0 {
		return
	}
	err := t.storage.DeleteResumption(t.sessionID, t.resRole, t.resGen)
	if err != nil && !errors.Is(err, storage.ErrNoResumption) &&
		!errors.Is(err, storage.ErrResumptionConflict) {
		slog.Error("delete resumption", slog.Any("error", err))
	}
	t.releaseResumption()
}

// touchResumption slides the idle window of the row at t.resGen.
func (t *Transport) touchResumption() {
	if t.storage == nil || t.sessionID == "" || t.resGen == 0 {
		return
	}
	at := time.Now()
	if t.clock != nil {
		at = t.clock.Now()
	}
	err := t.storage.TouchResumption(t.sessionID, t.resRole, t.resGen, at)
	if err != nil && !errors.Is(err, storage.ErrNoResumption) &&
		!errors.Is(err, storage.ErrResumptionConflict) {
		slog.Error("touch resumption", slog.Any("error", err))
	}
	t.releaseResumption()
}

// holdResumption keeps this transport's row out of session sweeps.
func (t *Transport) holdResumption() {
	if t.storage == nil || t.sessionID == "" || t.resGen == 0 {
		return
	}
	t.storage.HoldResumption(t.sessionID)
	t.resHeld = true
}

// releaseResumption drops the hold from holdResumption, once.
func (t *Transport) releaseResumption() {
	if !t.resHeld {
		return
	}
	t.resRelease.Do(func() {
		t.storage.ReleaseResumption(t.sessionID)
		t.resDropped.Store(true)
	})
}

// dropIfUnreleased closes a transport whose handler returned without Close,
// CloseAbort, or terminate. The hold would otherwise pin the row past idle and
// max age. A release that already ran is left alone, so a Close that deleted
// the row is not followed by a touch.
func (t *Transport) dropIfUnreleased() {
	if t == nil || !t.resHeld || t.resDropped.Load() {
		return
	}
	_ = t.CloseAbort()
}

// terminated returns the terminal error of t, or nil while t is usable.
func (t *Transport) terminated() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.termErr
}

func (t *Transport) checkRoute(route Route) error {
	if !route.isSessionRoute() {
		return fmt.Errorf("%w: %s", ErrUnexpectedRoute, route)
	}
	return nil
}

// SetDeadline sets the read and write deadlines on the underlying connection.
func (t *Transport) SetDeadline(tm time.Time) error {
	return t.conn.SetDeadline(tm)
}

// SessionID returns the unique identifier for this session.
func (t *Transport) SessionID() string { return t.sessionID }

// AcceptedMeta returns the value copied from the accepted connection.
func (t *Transport) AcceptedMeta() any { return t.acceptedMeta }

func (t *Transport) takeAcceptedMeta(cn Conn) {
	if m, ok := cn.(AcceptedMeta); ok {
		t.acceptedMeta = m.AcceptedMeta()
	}
}

// RemotePeer returns the remote peer's identity (name, public key, and app
// version) as authenticated in the handshake.
func (t *Transport) RemotePeer() *storage.Peer { return t.remotePeer }
