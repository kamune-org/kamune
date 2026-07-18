package kamune

import (
	"crypto/rand"
	"encoding/binary"
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
	md := &pb.Metadata{
		ID:        rand.Text(),
		Timestamp: timestamppb.Now(),
		Sequence:  sequence,
		Route:     route.ToProto(),
	}
	metadataBytes, err := proto.Marshal(md)
	if err != nil {
		return nil, nil, fmt.Errorf("marshalling metadata: %w", err)
	}

	sig, err := s.attest.Sign(signingInput(metadataBytes, message))
	if err != nil {
		return nil, nil, fmt.Errorf("signing: %w", err)
	}

	st := &pb.SignedTransport{
		Data:      message,
		Signature: sig,
		Metadata:  metadataBytes,
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
	metadataBytes := st.GetMetadata()
	if ok := s.attest.Verify(
		s.remote, signingInput(metadataBytes, msg), st.Signature,
	); !ok {
		return nil, ErrInvalidSignature
	}

	var md pb.Metadata
	if err := proto.Unmarshal(metadataBytes, &md); err != nil {
		return nil, fmt.Errorf("unmarshalling metadata: %w", err)
	}
	if err := proto.Unmarshal(msg, dst); err != nil {
		return nil, fmt.Errorf("unmarshalling message: %w", err)
	}

	return &Metadata{&md}, nil
}

// signingInput constructs the domain-separated signing input per RFC002 §5.1:
// "kamune/transport-sign/v1" || varint(len(metadata)) || metadata || data
func signingInput(metadataBytes, data []byte) []byte {
	varintLen := binary.MaxVarintLen64
	input := make(
		[]byte, 0,
		len(transportSignInfo)+varintLen+len(metadataBytes)+len(data),
	)
	input = append(input, transportSignInfo...)
	input = binary.AppendUvarint(input, uint64(len(metadataBytes)))
	input = append(input, metadataBytes...)
	input = append(input, data...)
	return input
}

// routeFromST extracts the route from a SignedTransport's opaque metadata
// bytes. Used for pre-verification route dispatch (introduction/resume).
func routeFromST(st *pb.SignedTransport) (Route, error) {
	var md pb.Metadata
	if err := proto.Unmarshal(st.GetMetadata(), &md); err != nil {
		return RouteInvalid, fmt.Errorf("unmarshalling metadata: %w", err)
	}
	return RouteFromProto(md.GetRoute()), nil
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
