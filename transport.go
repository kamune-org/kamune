package kamune

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"sync"
	"syscall"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/kamune-org/kamune/internal/enigma"
	"github.com/kamune-org/kamune/pkg/storage"
)

// closeFrameTimeout bounds how long Transport.Close waits for its close frame
// to be sent. It leaves room for a full frame already being written on a
// slow link, while a peer that stops reading holds Close up only this long.
const closeFrameTimeout = 5 * time.Second

// connDropErrors are Conn read errors that mean the connection was closed
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
// os.ErrDeadlineExceeded or from a net.Error with Timeout() true.
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
// A Transport that receives a frame it must not process further (one that
// fails decryption or signature verification, is out of sequence, carries a
// route not allowed in the current phase, or is RouteCloseTransport) closes
// its connection and invalidates the session's resumption tokens, so the
// session cannot be resumed. Every later Receive returns the same error, and
// Send fails with ErrConnClosed. Only RouteCloseTransport tells the peer; in
// the other cases the peer sees the connection drop, and an attempt to resume
// it fails.
//
// A Transport invalidates only the tokens it is responsible for (see
// [Transport.Close]). Once a resumption of its session on another
// Transport has stored new tokens, ending this one leaves them alone. A
// resumption without persistence ([ServeWithoutPersistence] or
// [DialWithoutPersistence]) stores none; then ending a Transport that it
// replaced still keeps the resumed session from being resumed again.
type Transport struct {
	conn           Conn
	acceptedMeta   any
	termErr        error
	serde          *signedSerde
	encoder        *enigma.Enigma
	decoder        *enigma.Enigma
	mu             *sync.Mutex
	remotePeer     *storage.Peer
	storage        *storage.Storage
	sessionID      string
	resumptionRoot []byte
	// tokens are the stored resumption tokens of the session that t
	// invalidates when it ends (see [Transport.invalidateResumptionTokens]).
	tokens       [][]byte
	recvSequence uint64
	sendSequence uint64
	closeTimeout time.Duration
	sendMu       sync.Mutex
	recvMu       sync.Mutex
	established  bool
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

// ReceivePayload reads and decrypts the next message and returns the
// verified protobuf bytes without unmarshalling them into a caller type.
//
// It returns ErrReceiveTimeout when the read deadline passes before any byte
// of the next frame has arrived; the caller may retry. A connection that drops
// or times out part-way through a frame yields ErrConnClosed.
//
// ReceivePayload and Receive are safe for concurrent use. Calls are served one
// at a time in wire order, and each frame goes to exactly one caller.
func (t *Transport) ReceivePayload() (*Metadata, []byte, error) {
	// Hold recvMu from the read through the sequence check, so that frames
	// read by concurrent callers are checked in the order they arrived.
	t.recvMu.Lock()
	defer t.recvMu.Unlock()

	if err := t.terminated(); err != nil {
		return nil, nil, err
	}

	payload, err := t.conn.ReadBytes()
	switch {
	case err == nil: // continue
	case isConnDrop(err):
		return nil, nil, ErrConnClosed
	case isTimeout(err):
		return nil, nil, ErrReceiveTimeout
	default:
		return nil, nil, fmt.Errorf("reading payload: %w", err)
	}

	decrypted, err := t.decoder.Decrypt(payload)
	if err != nil {
		return nil, nil, t.terminate(
			fmt.Errorf("decrypting payload: %w", err),
		)
	}

	metadata, message, err := t.serde.verify(decrypted)
	if err != nil {
		return nil, nil, t.terminate(fmt.Errorf("deserializing: %w", err))
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
			))
		}
		return nil, nil, t.terminate(fmt.Errorf(
			"%w: missing messages, got seq %d, expected %d",
			ErrOutOfSync, seq, expected,
		))
	}
	t.recvSequence = seq
	t.mu.Unlock()

	route := metadata.Route()
	if !route.IsValid() {
		return nil, nil, fmt.Errorf("%w: %s", ErrInvalidRoute, route)
	}
	if err := t.checkRoute(route); err != nil {
		return nil, nil, t.terminate(err)
	}
	if route == RouteCloseTransport {
		// The peer will send nothing more; close the session so that no
		// frame queued behind the close is processed.
		return nil, nil, t.terminate(ErrPeerDisconnected)
	}

	return metadata, message, nil
}

// Send encrypts and sends a message with the specified route.
//
// An error wrapping ErrConnClosed means the connection is gone, for example
// because a write failed part-way through the frame; the caller must not
// retry on this Transport.
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
// RouteCloseTransport frame before closing (best-effort — if the send fails,
// it closes directly) and invalidates the session's resumption tokens,
// whether or not the frame could be sent, so neither side can resume the
// session afterwards. To keep a session resumable after its connection
// drops, as when Receive returns ErrConnClosed, use [Transport.CloseAbort]
// instead. It returns nil when Receive has already closed the transport.
//
// The tokens invalidated are those this transport stored, or, for a
// resumed transport that stored none, those left of the session it
// resumed. Once a resumption of the session on another transport has
// stored new tokens, closing this one leaves them alone, so closing a
// transport that a resumption replaced does not end the resumed session.
//
// Without persistence this does not hold. A resumption by a server built
// with [ServeWithoutPersistence], or a dialer built with
// [DialWithoutPersistence], stores no new tokens, so every transport of
// the session on that side holds tokens that are still stored. Closing
// any of them, including one that a later resumption replaced,
// invalidates the session's tokens: the resumed transport keeps working,
// but its session cannot be resumed again once it drops. End a replaced
// transport with [Transport.CloseAbort] instead. That keeps the session
// resumable only when the peer resumed it without persistence as well: a
// peer that stores new tokens holds ones that this side does not know.
//
// Close waits at most 5 seconds for the close frame to be sent, including
// the wait for a Send already in progress, and then closes the connection
// whether or not the frame went out. A peer that stops reading cannot hold
// it up for longer. A peer that does not get the frame in time sees the
// connection drop, as ErrConnClosed rather than ErrPeerDisconnected.
//
// The frame is written from a goroutine that ends when the write does.
// Closing the connection ends a pending write on a network connection. A
// Conn whose Close does not, such as one accepted from a relay listener,
// which shares the listener's link to the relay, keeps that goroutine until
// the pending write completes or the link fails.
func (t *Transport) Close() error {
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
		// connection, and the goroutine then returns. See the doc
		// comment for Conns whose Close does not.
	}
	// The session is over even if the peer never got the close frame, so
	// it must not be resumed.
	t.invalidateResumptionTokens()
	return t.conn.Close()
}

// CloseAbort closes the underlying connection abruptly without transmitting a
// RouteCloseTransport frame or invalidating resumption tokens, so the session
// can still be resumed. Used when a connection drops or fails keepalive.
func (t *Transport) CloseAbort() error {
	return t.conn.Close()
}

// terminate records err as the terminal error of t, unless one is already
// recorded, closes the connection and returns err. The first call also
// invalidates the session's resumption tokens: the session ended on a frame
// that must not be processed, so it must not be resumed either.
func (t *Transport) terminate(err error) error {
	t.mu.Lock()
	first := t.termErr == nil
	if first {
		t.termErr = err
	}
	t.mu.Unlock()
	_ = t.conn.Close()
	if first {
		t.invalidateResumptionTokens()
	}
	return err
}

// terminated returns the terminal error of t, or nil while t is usable.
func (t *Transport) terminated() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.termErr
}

func (t *Transport) checkRoute(route Route) error {
	ok := route.isChallengeRoute()
	if t.established {
		ok = route.isSessionRoute()
	}
	if !ok {
		return fmt.Errorf("%w: %s", ErrUnexpectedRoute, route)
	}
	return nil
}

// invalidateResumptionTokens deletes the session's stored resumption tokens
// if they are still those of t.tokens. A resumption of the session that
// stored new tokens since replaced them, and they are left alone. It never
// creates the session: when the session is not in storage, for example
// because the user deleted it, there is nothing to invalidate.
func (t *Transport) invalidateResumptionTokens() {
	if t.storage == nil || t.sessionID == "" || len(t.tokens) == 0 {
		return
	}
	_, err := t.storage.DeleteListIfContains(
		t.sessionID, storage.ResumptionTokensKey, t.tokens,
	)
	if err != nil {
		slog.Error(
			"invalidate resumption tokens", slog.Any("error", err),
		)
	}
}

// remainingResumptionTokens returns the tokens left of the session
// sessionID after one was used to resume it. The resumed transport
// invalidates them when it ends, unless it stores new ones.
func remainingResumptionTokens(
	store *storage.Storage, sessionID string,
) [][]byte {
	tokens, err := store.GetList(sessionID, storage.ResumptionTokensKey)
	if err != nil {
		slog.Error("read resumption tokens", slog.Any("error", err))
	}
	return tokens
}

func persistEstablishedSession(
	store *storage.Storage, t *Transport, setEstablished bool,
) {
	t.storage = store
	if store == nil {
		return
	}
	var peerKey []byte
	if t.remotePeer != nil {
		peerKey = t.remotePeer.PublicKey
	}
	tokens := t.deriveResumptionTokens()
	err := store.PutSessionResumption(
		t.sessionID,
		peerKey,
		tokens,
		setEstablished,
	)
	if err != nil {
		slog.Error("persist resumption state", slog.Any("error", err))
		return
	}
	t.tokens = tokens
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
// version) as established during the introduction phase.
func (t *Transport) RemotePeer() *storage.Peer { return t.remotePeer }

// setResumptionRoot derives and stores the resumption root from the MLKEM
// shared secret and session ID. Called after a successful Challenge Exchange.
func (t *Transport) setResumptionRoot(sharedSecret []byte) {
	root, err := enigma.Derive(
		sharedSecret,
		[]byte(t.sessionID),
		[]byte(resumptionRootInfo),
		resumptionTokenSize,
	)
	if err != nil {
		// Derive only fails on invalid parameters; this should never happen.
		slog.Error("derive resumption root", slog.Any("error", err))
		return
	}
	t.resumptionRoot = root
}

// deriveResumptionTokens returns N resumption tokens derived from the session's
// resumption root. Each token is a 32-byte HKDF-SHA512 output. Returns nil if
// the resumption root has not been set (e.g. pre- Established).
func (t *Transport) deriveResumptionTokens() [][]byte {
	if t.resumptionRoot == nil {
		return nil
	}
	tokens := make([][]byte, resumptionTokenCount)
	for i := range tokens {
		info := make([]byte, len(resumptionTokenInfo)+4)
		copy(info, resumptionTokenInfo)
		binary.BigEndian.PutUint32(info[len(resumptionTokenInfo):], uint32(i))
		token, err := enigma.Derive(
			t.resumptionRoot, nil, info, resumptionTokenSize,
		)
		if err != nil {
			slog.Error("derive resumption token", slog.Any("error", err))
			return nil
		}
		tokens[i] = token
	}
	return tokens
}
