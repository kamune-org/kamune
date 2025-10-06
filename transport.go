package kamune

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"sync/atomic"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/kamune-org/kamune/internal/box/pb"
	"github.com/kamune-org/kamune/internal/enigma"
	"github.com/kamune-org/kamune/pkg/attest"
)

var (
	ErrConnClosed         = errors.New("connection has been closed")
	ErrInvalidSignature   = errors.New("invalid signature")
	ErrVerificationFailed = errors.New("verification failed")
	ErrMessageTooLarge    = errors.New("message is too large")
	ErrOutOfSync          = errors.New("peers are out of sync")
)

type plainTransport struct {
	conn           Conn
	attest         attest.Attester
	remote         attest.PublicKey
	id             attest.Identifier
	sent, received atomic.Uint64
}

func newPlainTransport(
	conn Conn,
	remote attest.PublicKey,
	attest attest.Attester,
	id attest.Identifier,
) *plainTransport {
	return &plainTransport{
		conn:   conn,
		remote: remote,
		attest: attest,
		id:     id,
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
		Sequence:  pt.sent.Add(1),
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
) (*Metadata, uint64, error) {
	var st pb.SignedTransport
	if err := proto.Unmarshal(payload, &st); err != nil {
		return nil, 0, fmt.Errorf("unmarshalling transport: %w", err)
	}

	msg := st.GetData()
	if !pt.id.Verify(pt.remote, msg, st.Signature) {
		return nil, 0, ErrInvalidSignature
	}
	if err := proto.Unmarshal(msg, dst); err != nil {
		return nil, 0, fmt.Errorf("unmarshalling message: %w", err)
	}

	return &Metadata{st.GetMetadata()}, pt.received.Add(1), nil
}

type Transport struct {
	*plainTransport
	sessionID string
	encoder   *enigma.Enigma
	decoder   *enigma.Enigma
}

func newTransport(
	pt *plainTransport,
	sessionID string,
	encoder, decoder *enigma.Enigma,
) *Transport {
	return &Transport{
		plainTransport: pt,
		sessionID:      sessionID,
		encoder:        encoder,
		decoder:        decoder,
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
	decrypted, err := t.decoder.Decrypt(payload)
	if err != nil {
		return nil, fmt.Errorf("decrypting: %w", err)
	}
	metadata, seq, err := t.deserialize(decrypted, dst)
	if err != nil {
		return nil, fmt.Errorf("deserializing: %w", err)
	}

	if metadata.SequenceNum() != seq {
		// TODO(h.yazdani): Messages in a specific time window or a sequence frame
		//  can and should be accepted. A more elegant approach is needed to take
		//  these into consideration.
		return nil, ErrOutOfSync
	}

	return metadata, nil
}

func (t *Transport) Send(message Transferable) (*Metadata, error) {
	payload, metadata, err := t.serialize(message)
	if err != nil {
		return nil, fmt.Errorf("serializing: %w", err)
	}
	encrypted := t.encoder.Encrypt(payload)
	if err := t.conn.WriteBytes(encrypted); err != nil {
		return nil, fmt.Errorf("writing: %w", err)
	}

	return metadata, nil
}

func (t *Transport) SessionID() string { return t.sessionID }

func (t *Transport) Close() error { return t.conn.Close() }
