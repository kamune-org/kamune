package kamune

import (
	"errors"
	"fmt"
	"io"
	"sync/atomic"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/hossein1376/kamune/internal/box/pb"
	"github.com/hossein1376/kamune/internal/enigma"
	"github.com/hossein1376/kamune/pkg/attest"
)

const (
	maxTransportSize = 10 * 1024
	challengeSize    = 32
	introducePadding = 512
	messagePadding   = 128
	handshakePadding = 32
)

var (
	ErrInvalidSignature   = errors.New("invalid signature")
	ErrInvalidSeqNumber   = errors.New("invalid message sequence number")
	ErrVerificationFailed = errors.New("verification failed")
	ErrConnClosedByRemote = errors.New("peer has closed the connection")
)

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
	seqNum := t.received.Load()
	payload, err := t.conn.Read()
	switch {
	case err == nil:
	case errors.Is(err, io.EOF):
		return nil, ErrConnClosedByRemote
	default:
		return nil, fmt.Errorf("reading payload: %w", err)
	}
	decrypted, err := t.decoder.Decrypt(payload, seqNum)
	if err != nil {
		return nil, fmt.Errorf("decrypting: %w", err)
	}
	meta, err := t.deserialize(decrypted, dst, seqNum)
	if err != nil {
		return nil, fmt.Errorf("deserializing: %w", err)
	}
	t.received.Add(1)

	return meta, nil
}

func (t *Transport) Send(message Transferable) (*Metadata, error) {
	seqNum := t.sent.Load()
	payload, metadata, err := t.serialize(message, seqNum)
	if err != nil {
		return nil, fmt.Errorf("serializing: %w", err)
	}
	encrypted := t.encoder.Encrypt(payload, seqNum)
	if err := t.conn.Write(encrypted); err != nil {
		return nil, fmt.Errorf("writing: %w", err)
	}
	t.sent.Add(1)

	return metadata, nil
}

func (t *Transport) Close() error {
	return t.conn.Close()
}

func (t *Transport) SessionID() string {
	return t.sessionID
}

type plainTransport struct {
	conn     Conn
	sent     atomic.Uint64
	received atomic.Uint64
	attest   *attest.Attest
	remote   *attest.PublicKey
}

func (pt *plainTransport) serialize(
	msg Transferable, seq uint64,
) ([]byte, *Metadata, error) {
	message, err := proto.Marshal(msg)
	if err != nil {
		return nil, nil, fmt.Errorf("marshalling message: %w", err)
	}
	sig, err := pt.attest.Sign(message)
	if err != nil {
		return nil, nil, fmt.Errorf("signing: %w", err)
	}
	md := &pb.Metadata{Sequence: seq, Timestamp: timestamppb.Now()}
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
	payload []byte, dst Transferable, seq uint64,
) (*Metadata, error) {
	var st pb.SignedTransport
	if err := proto.Unmarshal(payload, &st); err != nil {
		return nil, fmt.Errorf("unmarshalling transport: %w", err)
	}
	if st.GetMetadata().GetSequence() != seq {
		return nil, ErrInvalidSeqNumber
	}
	msg := st.GetData()
	if !attest.Verify(pt.remote, msg, st.Signature) {
		return nil, ErrInvalidSignature
	}
	if err := proto.Unmarshal(msg, dst); err != nil {
		return nil, fmt.Errorf("unmarshalling message: %w", err)
	}

	return &Metadata{st.GetMetadata()}, nil
}
