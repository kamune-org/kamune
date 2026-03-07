package kamune

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"sync"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/kamune-org/kamune/internal/box/pb"
	"github.com/kamune-org/kamune/internal/enigma"
	"github.com/kamune-org/kamune/pkg/attest"
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

type underlyingTransport struct {
	conn    Conn
	encConn Conn
	attest  attest.Attester
	remote  attest.PublicKey
	id      attest.Identifier
	storage *storage.Storage
}

func newUnderlyingTransport(
	conn, encConn Conn,
	remote attest.PublicKey,
	attest attest.Attester,
	storage *storage.Storage,
) *underlyingTransport {
	return &underlyingTransport{
		conn:    conn,
		encConn: encConn,
		remote:  remote,
		attest:  attest,
		storage: storage,
		id:      storage.Algorithm().Identitfier(),
	}
}

func (ut *underlyingTransport) serialize(
	msg Transferable, route Route, sequence uint64,
) ([]byte, *Metadata, error) {
	message, err := proto.Marshal(msg)
	if err != nil {
		return nil, nil, fmt.Errorf("marshalling message: %w", err)
	}
	sig, err := ut.attest.Sign(message)
	if err != nil {
		return nil, nil, fmt.Errorf("signing: %w", err)
	}

	md := &pb.Metadata{
		ID:        rand.Text(),
		Timestamp: timestamppb.Now(),
		Sequence:  sequence,
	}
	st := &pb.SignedTransport{
		Data:      message,
		Signature: sig,
		Metadata:  md,
		Padding:   padding(maxPadding),
		Route:     route.ToProto(),
	}
	payload, err := proto.Marshal(st)
	if err != nil {
		return nil, nil, fmt.Errorf("marshalling transport: %w", err)
	}

	return payload, &Metadata{md, route}, nil
}

func (ut *underlyingTransport) deserialize(
	payload []byte, dst Transferable,
) (*Metadata, Route, uint64, error) {
	var st pb.SignedTransport
	if err := proto.Unmarshal(payload, &st); err != nil {
		return nil, RouteInvalid, 0, fmt.Errorf("unmarshalling transport: %w", err)
	}

	msg := st.GetData()
	if ok := ut.id.Verify(ut.remote, msg, st.Signature); !ok {
		return nil, RouteInvalid, 0, ErrInvalidSignature
	}
	if err := proto.Unmarshal(msg, dst); err != nil {
		return nil, RouteInvalid, 0, fmt.Errorf("unmarshalling message: %w", err)
	}

	route := RouteFromProto(st.GetRoute())
	seq := st.GetMetadata().GetSequence()
	return &Metadata{st.GetMetadata(), route}, route, seq, nil
}

// Transport handles encrypted message exchange with route-based dispatch.
type Transport struct {
	*underlyingTransport
	encoder         *enigma.Enigma
	decoder         *enigma.Enigma
	mu              *sync.Mutex
	sessionID       string
	sharedSecret    []byte
	remotePublicKey []byte
	remoteSalt      []byte
	localSalt       []byte
	recvSequence    uint64
	sendSequence    uint64
	isInitiator     bool
}

func newTransport(
	ut *underlyingTransport,
	sessionID string,
	encoder, decoder *enigma.Enigma,
) *Transport {
	return &Transport{
		mu:                  &sync.Mutex{},
		encoder:             encoder,
		decoder:             decoder,
		sessionID:           sessionID,
		underlyingTransport: ut,
	}
}

// Receive reads and decrypts the next message from the connection.
// It returns the metadata, the route of the received message, and any error.
func (t *Transport) Receive(dst Transferable) (*Metadata, error) {
	md, _, err := t.ReceiveWithRoute(dst)
	return md, err
}

// ReceiveWithRoute reads and decrypts the next message, returning both
// the metadata and the route of the received message.
func (t *Transport) ReceiveWithRoute(
	dst Transferable,
) (*Metadata, Route, error) {
	payload, err := t.conn.ReadBytes()
	switch {
	case err == nil: // continue
	case errors.Is(err, io.EOF):
		return nil, RouteInvalid, ErrConnClosed
	default:
		return nil, RouteInvalid, fmt.Errorf("reading payload: %w", err)
	}

	decrypted, err := t.decryptPayload(payload)
	if err != nil {
		return nil, RouteInvalid, fmt.Errorf("decrypting payload: %w", err)
	}

	metadata, route, seq, err := t.deserialize(decrypted, dst)
	if err != nil {
		return nil, RouteInvalid, fmt.Errorf("deserializing: %w", err)
	}

	// Validate per-message sequence number to detect
	// duplicates, missing, or out-of-order messages.
	t.mu.Lock()
	expected := t.recvSequence + 1
	if seq != expected {
		t.mu.Unlock()
		if seq < expected {
			return nil, RouteInvalid, fmt.Errorf(
				"%w: duplicate message seq %d, expected %d",
				ErrOutOfSync, seq, expected,
			)
		}
		return nil, RouteInvalid, fmt.Errorf(
			"%w: missing messages, got seq %d, expected %d",
			ErrOutOfSync, seq, expected,
		)
	}
	t.recvSequence = seq
	t.mu.Unlock()

	return metadata, route, nil
}

// ReceiveExpecting reads a message and validates that it matches the expected
// route.
func (t *Transport) ReceiveExpecting(
	dst Transferable, expected Route,
) (*Metadata, error) {
	md, route, err := t.ReceiveWithRoute(dst)
	if err != nil {
		return nil, err
	}
	if route != expected {
		return nil, fmt.Errorf(
			"%w: expected %s, got %s", ErrUnexpectedRoute, expected, route,
		)
	}
	return md, nil
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

	payload, metadata, err := t.serialize(message, route, seq)
	if err != nil {
		return nil, fmt.Errorf("serializing: %w", err)
	}
	encrypted, err := t.encryptPayload(payload)
	if err != nil {
		return nil, fmt.Errorf("encrypting payload: %w", err)
	}

	if err := t.conn.WriteBytes(encrypted); err != nil {
		return nil, fmt.Errorf("writing: %w", err)
	}

	return metadata, nil
}

// SessionID returns the unique identifier for this session.
func (t *Transport) SessionID() string { return t.sessionID }

// Close closes the transport connection.
func (t *Transport) Close() error {
	return t.conn.Close()
}

// Store returns the storage associated with this transport.
func (t *Transport) Store() *storage.Storage { return t.storage }

// RemotePublicKey returns the remote peer's public key.
func (t *Transport) RemotePublicKey() []byte {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.remotePublicKey
}

// SetRemotePublicKey sets the remote peer's public key for session tracking.
func (t *Transport) SetRemotePublicKey(key []byte) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.remotePublicKey = key
}

// SetInitiator marks whether this transport is the initiator.
func (t *Transport) SetInitiator(isInitiator bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.isInitiator = isInitiator
}

// SetSecrets stores the cryptographic secrets for potential session resumption.
func (t *Transport) SetSecrets(sharedSecret, localSalt, remoteSalt []byte) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.sharedSecret = sharedSecret
	t.localSalt = localSalt
	t.remoteSalt = remoteSalt
}

func readSignedTransport(c Conn) (*pb.SignedTransport, Route, error) {
	payload, err := c.ReadBytes()
	if err != nil {
		return nil, RouteInvalid, fmt.Errorf("reading payload: %w", err)
	}
	var st pb.SignedTransport
	if err := proto.Unmarshal(payload, &st); err != nil {
		return nil, RouteInvalid, fmt.Errorf("unmarshalling transport: %w", err)
	}
	return &st, RouteFromProto(st.GetRoute()), nil
}

func (t *Transport) decryptPayload(payload []byte) ([]byte, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	decrypted, err := t.decoder.Decrypt(payload)
	if err != nil {
		return nil, fmt.Errorf("decrypting: %w", err)
	}
	return decrypted, nil
}

func (t *Transport) encryptPayload(payload []byte) ([]byte, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	return t.encoder.Encrypt(payload), nil
}
