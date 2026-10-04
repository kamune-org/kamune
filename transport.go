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
	recvSequence   uint64
	sendSequence   uint64
	sendMu         sync.Mutex
	recvMu         sync.Mutex
	established    bool
}

func newTransport(
	conn Conn,
	serde *signedSerde,
	sessionID string,
	encoder, decoder *enigma.Enigma,
) *Transport {
	return &Transport{
		conn:      conn,
		mu:        &sync.Mutex{},
		encoder:   encoder,
		decoder:   decoder,
		sessionID: sessionID,
		serde:     serde,
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

// Close closes the transport connection. It sends a RouteCloseTransport frame
// before closing (best-effort — if the send fails, it closes directly) and,
// once the frame is sent, invalidates the session's resumption tokens. It
// returns nil when Receive has already closed the transport.
func (t *Transport) Close() error {
	if t.terminated() != nil {
		_ = t.conn.Close()
		return nil
	}
	_, err := t.Send(Bytes(nil), RouteCloseTransport)
	if err == nil {
		t.invalidateResumptionTokens()
	}
	return t.conn.Close()
}

// CloseAbort closes the underlying connection abruptly without transmitting a
// RouteCloseTransport frame or invalidating resumption tokens. Used when a
// connection drops or fails keepalive.
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

func (t *Transport) invalidateResumptionTokens() {
	if t.storage == nil || t.sessionID == "" {
		return
	}
	err := t.storage.SetMeta(
		t.sessionID,
		storage.NewByteSlicesMeta(storage.ResumptionTokensKey, nil),
	)
	if err != nil {
		slog.Error(
			"invalidate resumption tokens", slog.Any("error", err),
		)
	}
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
	err := store.PutSessionResumption(
		t.sessionID,
		peerKey,
		t.deriveResumptionTokens(),
		setEstablished,
	)
	if err != nil {
		slog.Error("persist resumption state", slog.Any("error", err))
	}
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
