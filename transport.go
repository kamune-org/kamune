package kamune

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/kamune-org/kamune/internal/enigma"
	"github.com/kamune-org/kamune/pkg/storage"
)

const pingDataSize = 8

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
	conn         Conn
	serde        *signedSerde
	encoder      *enigma.Enigma
	decoder      *enigma.Enigma
	mu           *sync.Mutex
	remotePeer   *storage.Peer
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

// Ping sends a keep-alive ping to the remote peer and waits for a pong
// response within the given timeout. The ping carries random data for
// freshness; the pong MUST echo it back.
func (t *Transport) Ping(timeout time.Duration) error {
	tok := make([]byte, pingDataSize)
	_, _ = rand.Read(tok)

	if _, err := t.Send(Bytes(tok), RoutePing); err != nil {
		return fmt.Errorf("send ping: %w", err)
	}

	_ = t.conn.SetDeadline(time.Now().Add(timeout))
	defer func() { _ = t.conn.SetDeadline(time.Time{}) }()

	r := Bytes(nil)
	if _, err := t.Receive(r); err != nil {
		return fmt.Errorf("await pong: %w", err)
	}

	if string(r.GetValue()) != string(tok) {
		return fmt.Errorf("%w: ping/pong token mismatch", ErrVerificationFailed)
	}
	return nil
}

// Pong sends a pong response echoing the data from a received ping.
func (t *Transport) Pong(data []byte) error {
	_, err := t.Send(Bytes(data), RoutePong)
	return err
}

// SessionID returns the unique identifier for this session.
func (t *Transport) SessionID() string { return t.sessionID }

// RemotePeer returns the remote peer's identity (name, public key, and app
// version) as established during the introduction phase.
func (t *Transport) RemotePeer() *storage.Peer { return t.remotePeer }
