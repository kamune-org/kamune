package kamune

import (
	"crypto/rand"
	"fmt"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/kamune-org/kamune/internal/box/pb"
	"github.com/kamune-org/kamune/pkg/attest"
)

// signedSerde provides serialize/deserialize functionalities, with baked-in
// signature enforcement.
type signedSerde struct {
	attest *attest.Attest
	remote []byte
}

func newSignedSerde(remote []byte, attest *attest.Attest) *signedSerde {
	return &signedSerde{
		remote: remote,
		attest: attest,
	}
}

func (s *signedSerde) serialize(
	msg Transferable, route Route, sequence uint64,
) ([]byte, *Metadata, error) {
	message, err := proto.Marshal(msg)
	if err != nil {
		return nil, nil, fmt.Errorf("marshalling message: %w", err)
	}
	sig, err := s.attest.Sign(message)
	if err != nil {
		return nil, nil, fmt.Errorf("signing: %w", err)
	}

	md := &pb.Metadata{
		ID:        rand.Text(),
		Timestamp: timestamppb.Now(),
		Sequence:  sequence,
		Route:     route.ToProto(),
	}
	st := &pb.SignedTransport{
		Data:      message,
		Signature: sig,
		Metadata:  md,
		Padding:   padding(maxPadding),
	}
	payload, err := proto.Marshal(st)
	if err != nil {
		return nil, nil, fmt.Errorf("marshalling data: %w", err)
	}

	return payload, &Metadata{md}, nil
}

func (s *signedSerde) deserialize(
	payload []byte, dst Transferable,
) (*Metadata, error) {
	var st pb.SignedTransport
	if err := proto.Unmarshal(payload, &st); err != nil {
		return nil, fmt.Errorf("unmarshalling data: %w", err)
	}

	msg := st.GetData()
	if ok := s.attest.Verify(s.remote, msg, st.Signature); !ok {
		return nil, ErrInvalidSignature
	}
	if err := proto.Unmarshal(msg, dst); err != nil {
		return nil, fmt.Errorf("unmarshalling message: %w", err)
	}

	return &Metadata{st.GetMetadata()}, nil
}

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
