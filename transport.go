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

	"google.golang.org/protobuf/proto"

	"github.com/kamune-org/kamune/internal/enigma"
	"github.com/kamune-org/kamune/pkg/storage"
)

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
type Transport struct {
	conn           Conn
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
	payload, err := t.conn.ReadBytes()
	switch {
	case err == nil: // continue
	case errors.Is(err, io.EOF):
		return nil, ErrConnClosed
	case isTimeout(err):
		return nil, ErrReceiveTimeout
	default:
		return nil, fmt.Errorf("reading payload: %w", err)
	}

	decrypted, err := t.decoder.Decrypt(payload)
	if err != nil {
		return nil, fmt.Errorf("decrypting payload: %w", err)
	}

	metadata, message, err := t.serde.verify(decrypted)
	if err != nil {
		return nil, fmt.Errorf("deserializing: %w", err)
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
		_ = t.conn.Close()
		if seq < expected {
			return nil, fmt.Errorf(
				"%w: duplicate message seq %d, expected %d",
				ErrOutOfSync, seq, expected,
			)
		}
		return nil, fmt.Errorf(
			"%w: missing messages, got seq %d, expected %d",
			ErrOutOfSync, seq, expected,
		)
	}
	t.recvSequence = seq
	t.mu.Unlock()

	route := metadata.Route()
	if !route.IsValid() {
		return nil, fmt.Errorf("%w: %s", ErrInvalidRoute, route)
	}
	if err := t.checkRoute(route); err != nil {
		_ = t.conn.Close()
		return nil, err
	}
	if route == RouteCloseTransport {
		t.invalidateResumptionTokens()
		return nil, ErrPeerDisconnected
	}
	if err := proto.Unmarshal(message, dst); err != nil {
		return nil, fmt.Errorf("deserializing message: %w", err)
	}

	return metadata, nil
}

// Send encrypts and sends a message with the specified route.
func (t *Transport) Send(message Transferable, route Route) (*Metadata, error) {
	if !route.IsValid() {
		return nil, fmt.Errorf("%w: %s", ErrInvalidRoute, route)
	}
	if err := t.checkRoute(route); err != nil {
		return nil, err
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
// before closing (best-effort — if the send fails, it closes directly).
func (t *Transport) Close() error {
	_, err := t.Send(Bytes(nil), RouteCloseTransport)
	if err == nil {
		t.invalidateResumptionTokens()
	}
	return t.conn.Close()
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

// SessionID returns the unique identifier for this session.
func (t *Transport) SessionID() string { return t.sessionID }

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
