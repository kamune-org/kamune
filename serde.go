package kamune

import (
	"crypto/rand"
	"fmt"
	mathrand "math/rand/v2"

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
	if len(message) > int(maxTransportSize) {
		return nil, nil, ErrMessageTooLarge
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
	}
	payload, err := padSignedTransport(st)
	if err != nil {
		return nil, nil, fmt.Errorf("padding signed transport: %w", err)
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

// readSignedTransport reads raw bytes from a Conn and unmarshals them
// into a SignedTransport protobuf message, without signature verification.
// Signature verification is deferred to the serde for each direction.
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

// padSignedTransport marshals st with bucketed padding per §12.7. The natural
// bucket is the smallest bucket that fits the unpadded size; a random bump
// (0-3) is applied independently per message and capped at the last bucket. If
// the unpadded size already exceeds the last bucket, padding is left empty.
func padSignedTransport(st *pb.SignedTransport) ([]byte, error) {
	st.Padding = nil
	baseSize := proto.Size(st)
	target := selectBucketSize(baseSize)
	if baseSize >= target {
		return proto.Marshal(st)
	}
	const worstCaseOverhead = 4
	padLen := max(target-baseSize-worstCaseOverhead, 0)
	for range 4 {
		overhead := 1 + varintSize(padLen)
		newPadLen := max(target-baseSize-overhead, 0)
		if newPadLen == padLen {
			break
		}
		padLen = newPadLen
	}
	st.Padding = randomBytes(padLen)
	return proto.Marshal(st)
}

// varintSize returns the number of bytes needed to encode n as a base-128
// varint (protobuf length prefix).
func varintSize(n int) int {
	size := 1
	for n >= 128 {
		n >>= 7
		size++
	}
	return size
}

// naturalBucketIndex returns the index of the smallest bucket whose target size
// is >= baseSize. If baseSize exceeds all buckets, the last bucket index is
// returned.
func naturalBucketIndex(baseSize int) int {
	for i, size := range paddingBuckets {
		if baseSize <= size {
			return i
		}
	}
	return len(paddingBuckets) - 1
}

// selectBump returns a random bump level (0-3) according to  bumpProbabilities.
// Index 0 corresponds to "stay", index 3 to "+3".
func selectBump() int {
	total := 0
	for _, p := range bumpProbabilities {
		total += p
	}
	n := mathrand.IntN(total)
	for i, p := range bumpProbabilities {
		if n < p {
			return i
		}
		n -= p
	}
	return len(bumpProbabilities) - 1
}

// selectBucketSize returns the padding bucket size for a given base size,
// applying a random cross-bucket bump capped at the last bucket.
func selectBucketSize(baseSize int) int {
	idx := naturalBucketIndex(baseSize)
	idx += selectBump()
	if idx >= len(paddingBuckets) {
		idx = len(paddingBuckets) - 1
	}
	return paddingBuckets[idx]
}
