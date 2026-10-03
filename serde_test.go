package kamune

import (
	"crypto/rand"
	"math"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/kamune-org/kamune/internal/box/pb"
	"github.com/kamune-org/kamune/pkg/attest"
)

func TestNaturalBucketIndex(t *testing.T) {
	cases := []struct {
		baseSize int
		want     int
	}{
		{0, 0},
		{1, 0},
		{512, 0},
		{513, 1},
		{1024, 1},
		{1025, 2},
		{4096, 2},
		{4097, 3},
		{16_384, 3},
		{16_385, 4},
		{32_768, 4},
		{32_769, 5},
		{frameTargetSize, 5},
		{frameTargetSize + 1, 5},
	}
	for _, tc := range cases {
		t.Run("", func(t *testing.T) {
			a := require.New(t)
			a.Equal(tc.want, naturalBucketIndex(tc.baseSize))
		})
	}
}

func TestSelectBump_Distribution(t *testing.T) {
	a := require.New(t)
	const iterations = 10000
	hits := make([]int, len(bumpProbabilities))
	for range iterations {
		hits[selectBump()]++
	}
	for i, want := range bumpProbabilities {
		got := hits[i] * 100 / iterations
		diff := got - want
		if diff < 0 {
			diff = -diff
		}
		a.LessOrEqual(diff, 3, "bump level %d: got %d%%, want ~%d%%", i, got, want)
	}
}

func TestSelectBucketIndex_CappedAtLastBucket(t *testing.T) {
	a := require.New(t)
	last := len(paddingBuckets) - 1
	for range 1000 {
		a.Equal(last, selectBucketIndex(paddingBuckets[last]))
	}
}

func TestSelectBucketIndex_AlwaysAtLeastBase(t *testing.T) {
	a := require.New(t)
	sizes := []int{0, 1, 100, 500, 512, 513, 1024, 4096, 16_384}
	for _, base := range sizes {
		for range 100 {
			got := paddingBuckets[selectBucketIndex(base)]
			a.GreaterOrEqual(got, base)
			a.LessOrEqual(got, frameTargetSize)
		}
	}
}

func TestPaddingField_MatchesDescriptor(t *testing.T) {
	a := require.New(t)
	fields := (&pb.SignedTransport{}).ProtoReflect().Descriptor().Fields()
	a.Equal(paddingField, fields.ByName("Padding").Number())
}

// TestPaddingRecords_FillEveryGap checks that every gap of two or more bytes,
// including those between two varint widths, is filled exactly.
func TestPaddingRecords_FillEveryGap(t *testing.T) {
	a := require.New(t)
	records, ok := paddingRecords(0)
	a.True(ok)
	a.Empty(records)
	_, ok = paddingRecords(1)
	a.False(ok)

	for gap := 2; gap <= math.MaxUint16; gap++ {
		records, ok := paddingRecords(gap)
		a.True(ok, "gap %d", gap)
		size := 0
		for _, n := range records {
			size += paddingRecordSize(n)
		}
		a.Equal(gap, size, "gap %d", gap)
	}
}

// TestBucketTarget_EveryBaseSizeLandsOnBucket checks that every reachable
// envelope size, in every bucket the bump can pick, pads to a bucket size
// exactly.
func TestBucketTarget_EveryBaseSizeLandsOnBucket(t *testing.T) {
	a := require.New(t)
	// frameTargetSize-1 is the one size that cannot be padded: it would need
	// a one-byte field. Serialized user messages are far below it.
	for base := 0; base < frameTargetSize-1; base++ {
		for idx := naturalBucketIndex(base); idx < len(paddingBuckets); idx++ {
			target := bucketTarget(base, idx)
			a.Contains(paddingBuckets, target)
			records, ok := paddingRecords(target - base)
			if !ok {
				a.Failf("unpaddable", "base %d bucket %d", base, idx)
			}
			size := base
			for _, n := range records {
				size += paddingRecordSize(n)
			}
			if size != target {
				a.Failf("off bucket", "base %d: got %d, want %d",
					base, size, target)
			}
		}
	}
}

// transportOfSize returns a SignedTransport whose unpadded encoding is
// exactly size bytes.
func transportOfSize(t *testing.T, size int) *pb.SignedTransport {
	t.Helper()
	a := require.New(t)
	for sig := range 3 {
		for data := max(size-8, 0); data <= size; data++ {
			st := &pb.SignedTransport{
				Data:      make([]byte, data),
				Signature: make([]byte, sig),
			}
			if proto.Size(st) == size {
				return st
			}
		}
	}
	a.FailNow("no SignedTransport of size", "%d", size)
	return nil
}

// TestPadSignedTransport_VarintBoundaryGaps pads envelopes whose gap to the
// natural bucket is 1, 2, 130 or 16387 bytes, which a single Padding field
// cannot fill.
func TestPadSignedTransport_VarintBoundaryGaps(t *testing.T) {
	sizes := []int{
		511, 510, 382, 1023, 894, 3966, 16_254, 16_381, 32_638,
		frameTargetSize - 2,
		frameTargetSize - 130,
		frameTargetSize - 16_387,
	}
	for _, size := range sizes {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			a := require.New(t)
			for range 20 {
				st := transportOfSize(t, size)
				data := st.GetData()
				payload, err := padSignedTransport(st)
				a.NoError(err)
				a.Contains(paddingBuckets, len(payload))

				var got pb.SignedTransport
				a.NoError(proto.Unmarshal(payload, &got))
				a.Equal(data, got.GetData())
			}
		})
	}
}

func TestPadSignedTransport_LandsOnBucket(t *testing.T) {
	a := require.New(t)
	att, err := attest.New()
	a.NoError(err)
	sizes := []int{0, 32, 500, 2000, 10_000}
	for _, keySize := range sizes {
		t.Run("", func(t *testing.T) {
			a := require.New(t)
			hs := &pb.Handshake{
				Key:        make([]byte, keySize),
				Salt:       make([]byte, handshakeSaltSize),
				SessionKey: "0123456789",
			}
			msg, err := proto.Marshal(hs)
			a.NoError(err)
			a.LessOrEqual(len(msg), int(maxTransportSize))

			sig, err := att.Sign(msg)
			a.NoError(err)
			mdBytes, err := proto.Marshal(&pb.Metadata{
				ID:       "0123456789012345678901",
				Sequence: 1,
				Route:    7,
			})
			a.NoError(err)
			st := &pb.SignedTransport{
				Data:      msg,
				Signature: sig,
				Metadata:  mdBytes,
			}
			payload, err := padSignedTransport(st)
			a.NoError(err)
			a.Contains(paddingBuckets, len(payload),
				"payload size must land on a bucket boundary")

			roundtrip := &pb.SignedTransport{}
			a.NoError(proto.Unmarshal(payload, roundtrip))
			a.Equal(sig, roundtrip.GetSignature())
			a.Equal(msg, roundtrip.GetData())
		})
	}
}

func TestPadSignedTransport_NoPaddingWhenBaseExceedsAllBuckets(t *testing.T) {
	a := require.New(t)
	att, err := attest.New()
	a.NoError(err)

	msg := make([]byte, frameTargetSize+1024)
	_, _ = rand.Read(msg)
	sig, err := att.Sign(msg)
	a.NoError(err)

	mdBytes, err := proto.Marshal(&pb.Metadata{ID: "x"})
	a.NoError(err)
	st := &pb.SignedTransport{
		Data:      msg,
		Signature: sig,
		Metadata:  mdBytes,
	}
	payload, err := padSignedTransport(st)
	a.NoError(err)
	a.Greater(len(payload), frameTargetSize)
	a.Nil(st.GetPadding())
}
