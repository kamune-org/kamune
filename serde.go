package kamune

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math"
	mathrand "math/rand/v2"

	"google.golang.org/protobuf/encoding/protowire"
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
	metadata, msg, err := s.verify(payload)
	if err != nil {
		return nil, err
	}
	if err := proto.Unmarshal(msg, dst); err != nil {
		return nil, fmt.Errorf("unmarshalling message: %w", err)
	}

	return metadata, nil
}

func (s *signedSerde) verify(payload []byte) (*Metadata, []byte, error) {
	var st pb.SignedTransport
	if err := proto.Unmarshal(payload, &st); err != nil {
		return nil, nil, fmt.Errorf("unmarshalling data: %w", err)
	}

	msg := st.GetData()
	metadataBytes := st.GetMetadata()
	if ok := s.attest.Verify(
		s.remote, signingInput(metadataBytes, msg), st.Signature,
	); !ok {
		return nil, nil, ErrInvalidSignature
	}

	var md pb.Metadata
	if err := proto.Unmarshal(metadataBytes, &md); err != nil {
		return nil, nil, fmt.Errorf("unmarshalling metadata: %w", err)
	}

	return &Metadata{&md}, msg, nil
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

// paddingField is the protobuf field number of SignedTransport.Padding.
const paddingField protowire.Number = 4

// padSignedTransport marshals st with bucketed padding per §12.7. The natural
// bucket is the smallest bucket that fits the unpadded size; a random bump
// (0-3) is applied independently per message and capped at the last bucket. If
// the unpadded size already exceeds the last bucket, padding is left empty.
//
// The padding is appended as raw Padding field records instead of being set on
// st, so that every gap of two or more bytes is filled exactly (see
// paddingRecords).
func padSignedTransport(st *pb.SignedTransport) ([]byte, error) {
	st.Padding = nil
	b, err := proto.Marshal(st)
	if err != nil {
		return nil, err
	}
	target := bucketTarget(len(b), selectBucketIndex(len(b)))
	return appendPadding(b, target-len(b)), nil
}

// bucketTarget returns the padded size for an envelope of baseSize bytes in
// bucket idx. No protobuf field encodes to a single byte, so when the bucket
// is exactly one byte larger than baseSize the next bucket is used. Only
// baseSize == frameTargetSize-1 is left one byte short of its bucket; a
// serialized user message cannot reach that size.
func bucketTarget(baseSize, idx int) int {
	if paddingBuckets[idx]-baseSize == 1 && idx < len(paddingBuckets)-1 {
		idx++
	}
	return paddingBuckets[idx]
}

// appendPadding appends Padding field records with random content to b,
// encoding to exactly gap bytes. It returns b unchanged when gap is not
// positive or cannot be filled.
func appendPadding(b []byte, gap int) []byte {
	records, ok := paddingRecords(gap)
	if !ok {
		return b
	}
	for _, n := range records {
		b = protowire.AppendTag(b, paddingField, protowire.BytesType)
		b = protowire.AppendBytes(b, randomBytes(n))
	}
	return b
}

// paddingRecords returns the content lengths of the Padding field records
// whose encodings add up to exactly gap bytes. A record costs a one-byte tag,
// a varint length and the content. A single record fits every gap of two or
// more bytes except those that fall between two varint widths (130, 16387,
// ...). For those, an empty two-byte record goes first, and the last record,
// whose value a decoder keeps, carries the content. A gap of one byte cannot
// be filled.
func paddingRecords(gap int) ([]int, bool) {
	if gap <= 0 {
		return nil, gap == 0
	}
	if n, ok := paddingContentLen(gap); ok {
		return []int{n}, true
	}
	if n, ok := paddingContentLen(gap - paddingRecordSize(0)); ok {
		return []int{0, n}, true
	}
	return nil, false
}

// paddingContentLen returns the content length of the Padding record that
// encodes to exactly size bytes, if there is one.
func paddingContentLen(size int) (int, bool) {
	tag := protowire.SizeTag(paddingField)
	for width := 1; width <= protowire.SizeVarint(math.MaxUint64); width++ {
		n := size - tag - width
		if n < 0 {
			break
		}
		if protowire.SizeVarint(uint64(n)) == width {
			return n, true
		}
	}
	return 0, false
}

// paddingRecordSize returns the encoded size of a Padding record holding n
// content bytes.
func paddingRecordSize(n int) int {
	return protowire.SizeTag(paddingField) + protowire.SizeBytes(n)
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

// selectBucketIndex returns the padding bucket index for a given base size,
// applying a random cross-bucket bump capped at the last bucket.
func selectBucketIndex(baseSize int) int {
	return min(
		naturalBucketIndex(baseSize)+selectBump(), len(paddingBuckets)-1,
	)
}
