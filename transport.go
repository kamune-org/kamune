package kamune

import (
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/kamune-org/kamune/internal/enigma"
	"github.com/kamune-org/kamune/pkg/storage"
)

var (
	ErrConnClosed         = errors.New("connection has been closed")
	ErrInvalidSignature   = errors.New("invalid signature")
	ErrVerificationFailed = errors.New("verification failed")
	ErrMessageTooLarge    = errors.New("message is too large")
	ErrOutOfSync          = errors.New("peers are out of sync")
	ErrUnexpectedRoute    = errors.New("unexpected route received")
	ErrInvalidRoute       = errors.New("invalid route")
)

// Transport handles encrypted message exchange with route-based dispatch.
type Transport struct {
	conn         Conn
	serde        *signedSerde
	store        *storage.Storage
	encoder      *enigma.Enigma
	decoder      *enigma.Enigma
	mu           *sync.Mutex
	sessionID    string
	recvSequence uint64
	sendSequence uint64
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

// Close closes the transport connection.
func (t *Transport) Close() error { return t.conn.Close() }

// SessionID returns the unique identifier for this session.
func (t *Transport) SessionID() string { return t.sessionID }

// Store returns the storage associated with this transport.
func (t *Transport) Store() *storage.Storage { return t.store }

// RemotePublicKey returns the remote peer's public key.
func (t *Transport) RemotePublicKey() []byte { return t.serde.remote }
