package kamune

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/kamune-org/kamune/internal/box/pb"
	"github.com/kamune-org/kamune/pkg/attest"
)

func TestVarintSize(t *testing.T) {
	cases := []struct {
		n    int
		want int
	}{
		{0, 1},
		{1, 1},
		{127, 1},
		{128, 2},
		{16_383, 2},
		{16_384, 3},
		{2_097_151, 3},
		{2_097_152, 4},
	}
	for _, tc := range cases {
		t.Run("", func(t *testing.T) {
			a := require.New(t)
			a.Equal(tc.want, varintSize(tc.n))
		})
	}
}

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

func TestSelectBucketSize_CappedAtLastBucket(t *testing.T) {
	a := require.New(t)
	last := len(paddingBuckets) - 1
	for range 1000 {
		got := selectBucketSize(paddingBuckets[last])
		a.LessOrEqual(got, paddingBuckets[last])
		a.GreaterOrEqual(got, paddingBuckets[last])
	}
}

func TestSelectBucketSize_AlwaysAtLeastBase(t *testing.T) {
	a := require.New(t)
	sizes := []int{0, 1, 100, 500, 512, 513, 1024, 4096, 16_384}
	for _, base := range sizes {
		for range 100 {
			got := selectBucketSize(base)
			a.GreaterOrEqual(got, base)
			a.LessOrEqual(got, frameTargetSize)
		}
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
			st := &pb.SignedTransport{
				Data:      msg,
				Signature: sig,
				Metadata: &pb.Metadata{
					ID:       "0123456789012345678901",
					Sequence: 1,
					Route:    7,
				},
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

	st := &pb.SignedTransport{
		Data:      msg,
		Signature: sig,
		Metadata:  &pb.Metadata{ID: "x"},
	}
	payload, err := padSignedTransport(st)
	a.NoError(err)
	a.Greater(len(payload), frameTargetSize)
	a.Nil(st.GetPadding())
}
