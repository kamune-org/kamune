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
	"github.com/kamune-org/kamune/pkg/ratchet"
)

var (
	ErrConnClosed         = errors.New("connection has been closed")
	ErrInvalidSignature   = errors.New("invalid signature")
	ErrVerificationFailed = errors.New("verification failed")
	ErrMessageTooLarge    = errors.New("message is too large")
	ErrOutOfSync          = errors.New("peers are out of sync")
)

type plainTransport struct {
	conn    Conn
	attest  attest.Attester
	remote  attest.PublicKey
	id      attest.Identifier
	storage *Storage
}

func newPlainTransport(
	conn Conn,
	remote attest.PublicKey,
	attest attest.Attester,
	storage *Storage,
) *plainTransport {
	return &plainTransport{
		conn:    conn,
		remote:  remote,
		attest:  attest,
		storage: storage,
		id:      storage.algorithm.Identitfier(),
	}
}

func (pt *plainTransport) serialize(msg Transferable) ([]byte, *Metadata, error) {
	message, err := proto.Marshal(msg)
	if err != nil {
		return nil, nil, fmt.Errorf("marshalling message: %w", err)
	}
	sig, err := pt.attest.Sign(message)
	if err != nil {
		return nil, nil, fmt.Errorf("signing: %w", err)
	}

	md := &pb.Metadata{
		ID:        rand.Text(),
		Timestamp: timestamppb.Now(),
	}
	st := &pb.SignedTransport{
		Data:      message,
		Signature: sig,
		Metadata:  md,
		Padding:   padding(maxPadding),
	}
	payload, err := proto.Marshal(st)
	if err != nil {
		return nil, nil, fmt.Errorf("marshalling transport: %w", err)
	}

	return payload, &Metadata{md}, nil
}

func (pt *plainTransport) deserialize(
	payload []byte, dst Transferable,
) (*Metadata, error) {
	var st pb.SignedTransport
	if err := proto.Unmarshal(payload, &st); err != nil {
		return nil, fmt.Errorf("unmarshalling transport: %w", err)
	}

	msg := st.GetData()
	if ok := pt.id.Verify(pt.remote, msg, st.Signature); !ok {
		return nil, ErrInvalidSignature
	}
	if err := proto.Unmarshal(msg, dst); err != nil {
		return nil, fmt.Errorf("unmarshalling message: %w", err)
	}

	return &Metadata{st.GetMetadata()}, nil
}

type Transport struct {
	*plainTransport
	encoder *enigma.Enigma
	decoder *enigma.Enigma
	// ratchet is nil initially (before bootstrap/handshake) and only set after
	// the handshake completes.
	ratchet   *ratchet.Ratchet
	mu        *sync.Mutex
	sessionID string

	ratchetThreshold uint64
}

func newTransport(
	pt *plainTransport,
	sessionID string,
	encoder, decoder *enigma.Enigma,
	ratchetThreshold uint64,
) *Transport {
	return &Transport{
		plainTransport:   pt,
		sessionID:        sessionID,
		encoder:          encoder,
		decoder:          decoder,
		mu:               &sync.Mutex{},
		ratchetThreshold: ratchetThreshold,
	}
}

func (t *Transport) Receive(dst Transferable) (*Metadata, error) {
	payload, err := t.conn.ReadBytes()
	switch {
	case err == nil: // continue
	case errors.Is(err, io.EOF):
		return nil, ErrConnClosed
	default:
		return nil, fmt.Errorf("reading payload: %w", err)
	}

	decrypted, err := decryptPayload(t, payload)
	if err != nil {
		return nil, fmt.Errorf("decrypting payload: %w", err)
	}

	metadata, err := t.deserialize(decrypted, dst)
	if err != nil {
		return nil, fmt.Errorf("deserializing: %w", err)
	}

	return metadata, nil
}

func (t *Transport) Send(message Transferable) (*Metadata, error) {
	payload, metadata, err := t.serialize(message)
	if err != nil {
		return nil, fmt.Errorf("serializing: %w", err)
	}
	encrypted, err := encryptPayload(t, payload)
	if err != nil {
		return nil, fmt.Errorf("encrypting payload: %w", err)
	}

	if err := t.conn.WriteBytes(encrypted); err != nil {
		return nil, fmt.Errorf("writing: %w", err)
	}

	return metadata, nil
}

func (t *Transport) SessionID() string { return t.sessionID }

func (t *Transport) Close() error { return t.conn.Close() }

func readSignedTransport(c Conn) (*pb.SignedTransport, error) {
	payload, err := c.ReadBytes()
	if err != nil {
		return nil, fmt.Errorf("reading payload: %w", err)
	}
	var st pb.SignedTransport
	if err := proto.Unmarshal(payload, &st); err != nil {
		return nil, fmt.Errorf("unmarshalling transport: %w", err)
	}
	return &st, nil
}

func decryptPayload(t *Transport, payload []byte) ([]byte, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.ratchet == nil {
		decrypted, err := t.decoder.Decrypt(payload)
		if err != nil {
			return nil, fmt.Errorf("decrypting: %w", err)
		}
		return decrypted, nil
	}

	var ratchet pb.Ratchet
	if err := proto.Unmarshal(payload, &ratchet); err != nil {
		return nil, fmt.Errorf("unmarshalling ratchet: %w", err)
	}

	if dh := ratchet.GetDh(); dh != nil {
		if err := t.ratchet.SetTheirPublic(dh, t.sessionID); err != nil {
			return nil, fmt.Errorf("setting their public key: %w", err)
		}
	}

	decrypted, err := t.ratchet.Decrypt(ratchet.GetCiphertext())
	if err != nil {
		return nil, fmt.Errorf("ratchet decrypt: %w", err)
	}
	return decrypted, nil
}

func encryptPayload(t *Transport, payload []byte) ([]byte, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.ratchet == nil {
		return t.encoder.Encrypt(payload), nil
	}

	// Snapshot send counter before possible ratchet step (number of messages in
	// previous chain)
	pn := t.ratchet.Sent()

	// If we have reached the threshold, initiate a new DH ratchet before
	// encrypting so the receiver will update its DH state prior to
	// attempting decryption (the receiver processes Dh before decrypt).
	var pub []byte
	var err error
	if pn >= t.ratchetThreshold {
		pub, err = t.ratchet.InitiateRatchet(t.sessionID)
		if err != nil {
			return nil, fmt.Errorf("initiating ratchet: %w", err)
		}
	}

	// Encrypt with the (possibly updated) send chain
	ct, err := t.ratchet.Encrypt(payload)
	if err != nil {
		return nil, fmt.Errorf("ratchet encrypt: %w", err)
	}
	ns := t.ratchet.Sent()

	ratchet := &pb.Ratchet{Dh: pub, Pn: pn, Ns: ns, Ciphertext: ct}
	data, err := proto.Marshal(ratchet)
	if err != nil {
		return nil, fmt.Errorf("marshalling ratchet: %w", err)
	}

	return data, nil
}
