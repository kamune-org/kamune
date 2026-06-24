package kamune

import (
	"math"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/kamune-org/kamune/internal/box/pb"
	"github.com/kamune-org/kamune/pkg/attest"
)

// TestTransport_PadToBucket asserts that serialize produces payloads
// that land on a bucket boundary and never exceed frameTargetSize.
func TestTransport_PadToBucket(t *testing.T) {
	a := require.New(t)
	att, err := attest.New()
	a.NoError(err)
	serde := newSignedSerde(att.MarshalPublicKey(), att)

	cases := []struct {
		name string
		msg  proto.Message
	}{
		{"tiny", &pb.Handshake{SessionKey: "x"}},
		{
			"small",
			&pb.Handshake{
				Key:        make([]byte, 1024),
				Salt:       make([]byte, saltSize),
				SessionKey: "0123456789",
			},
		},
		{
			"medium",
			&pb.Handshake{
				Key:        make([]byte, 16*1024),
				Salt:       make([]byte, saltSize),
				SessionKey: "0123456789",
			},
		},
		{
			"near_max",
			&pb.Handshake{
				Key:        make([]byte, int(maxTransportSize)-64),
				Salt:       make([]byte, saltSize),
				SessionKey: "0123456789",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			payload, _, err := serde.serialize(tc.msg, RouteExchangeMessages, 1)
			a.NoError(err)
			a.LessOrEqual(
				len(payload), frameTargetSize,
				"payload (%d bytes) must fit frameTargetSize (%d)",
				len(payload), frameTargetSize,
			)
			a.Contains(paddingBuckets, len(payload),
				"payload size must land on a bucket boundary")
		})
	}
}

// TestTransport_EncryptFitsUint16 asserts that the largest bucket
// plus encryption overhead equals math.MaxUint16.
func TestTransport_EncryptFitsUint16(t *testing.T) {
	a := require.New(t)
	a.Equal(
		math.MaxUint16-encryptionOverhead, frameTargetSize,
		"sanity: frameTargetSize + encryptionOverhead == math.MaxUint16",
	)
	a.Equal(
		frameTargetSize, paddingBuckets[len(paddingBuckets)-1],
		"sanity: last bucket must be frameTargetSize",
	)
	a.LessOrEqual(
		frameTargetSize+encryptionOverhead, math.MaxUint16,
		"last bucket + AEAD must fit math.MaxUint16",
	)
}
