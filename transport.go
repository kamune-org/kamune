package kamune

import (
	"errors"
	"fmt"
	"io"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/hossein1376/kamune/internal/box/pb"
	"github.com/hossein1376/kamune/internal/enigma"
	"github.com/hossein1376/kamune/pkg/attest"
)

var (
	ErrConnClosed         = errors.New("connection has been closed")
	ErrInvalidSignature   = errors.New("invalid signature")
	ErrVerificationFailed = errors.New("verification failed")
	ErrMessageTooLarge    = errors.New("message is too large")
)

type plainTransport struct {
	conn   *Conn
	attest *attest.Attest
	remote *attest.PublicKey
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
	md := &pb.Metadata{Timestamp: timestamppb.Now()}
	st := &pb.SignedTransport{
		Data:      message,
		Signature: sig,
		Metadata:  md,
		Padding:   padding(messagePadding),
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

	// TODO(h.yazdani): Messages in a specific time window or a sequence frame
	//  can and should be accepted.

	msg := st.GetData()
	if !attest.Verify(pt.remote, msg, st.Signature) {
		return nil, ErrInvalidSignature
	}
	if err := proto.Unmarshal(msg, dst); err != nil {
		return nil, fmt.Errorf("unmarshalling message: %w", err)
	}

	return &Metadata{st.GetMetadata()}, nil
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
	payload, err := t.conn.Read()
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
	encrypted := t.encoder.Encrypt(payload)
	if err := t.conn.Write(encrypted); err != nil {
		return nil, fmt.Errorf("writing: %w", err)
	}

	return metadata, nil
}

func (t *Transport) Close() error { return t.conn.Close() }

func (t *Transport) SessionID() string { return t.sessionID }
