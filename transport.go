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
	sessionID      string
	resumptionRoot []byte
	recvSequence   uint64
	sendSequence   uint64
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

	metadata, err := t.serde.deserialize(decrypted, dst)
	if err != nil {
		return nil, fmt.Errorf("deserializing: %w", err)
	}

	// Check for protocol-level routes before sequence validation.
	switch metadata.Route() {
	case RouteCloseTransport:
		return nil, ErrPeerDisconnected
	case RoutePing:
		// Ping is handled externally by the application; return
		// metadata for the caller to respond with a pong.
	}

	// Validate per-message sequence number to detect duplicates, missing, or
	// out-of-order messages.
	seq := metadata.SequenceNum()
	t.mu.Lock()
	expected := t.recvSequence + 1
	if seq != expected {
		t.mu.Unlock()
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

	return metadata, nil
}

// Send encrypts and sends a message with the specified route.
func (t *Transport) Send(message Transferable, route Route) (*Metadata, error) {
	if !route.IsValid() {
		return nil, fmt.Errorf("%w: %s", ErrInvalidRoute, route)
	}

	t.mu.Lock()
	t.sendSequence++
	seq := t.sendSequence
	t.mu.Unlock()

	payload, metadata, err := t.serde.serialize(message, route, seq)
	if err != nil {
		return nil, fmt.Errorf("serializing: %w", err)
	}

	if err := t.conn.WriteBytes(t.encoder.Encrypt(payload)); err != nil {
		return nil, fmt.Errorf("writing: %w", err)
	}

	return metadata, nil
}

// Close closes the transport connection. It sends a RouteCloseTransport frame
// before closing (best-effort — if the send fails, it closes directly).
func (t *Transport) Close() error {
	_, _ = t.Send(Bytes(nil), RouteCloseTransport)
	return t.conn.Close()
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
