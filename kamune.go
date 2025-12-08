// Package kamune provides secure communication over untrusted networks.
package kamune

import (
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/kamune-org/kamune/internal/box/pb"
	"github.com/kamune-org/kamune/pkg/attest"
)

const (
	// must be less than or equal to 65535 ([math.MaxUint16])
	maxTransportSize        = 50 * 1024
	saltSize                = 16
	sessionIDLength         = 30
	challengeSize           = 32
	maxPadding              = 256
	defaultRatchetThreshold = 10

	c2s = "client-to-server"
	s2c = "server-to-client"
)

var _ uint16 = maxTransportSize

type (
	PublicKey      = attest.PublicKey
	RemoteVerifier func(store *Storage, peer *Peer) (err error)
	HandlerFunc    func(t *Transport) error
)

type Transferable interface {
	proto.Message
}

func Bytes(b []byte) *wrapperspb.BytesValue {
	return &wrapperspb.BytesValue{Value: b}
}

type Metadata struct {
	pb *pb.Metadata
}

func (m Metadata) ID() string { return m.pb.GetID() }

func (m Metadata) Timestamp() time.Time { return m.pb.Timestamp.AsTime() }

func (m Metadata) SequenceNum() uint64 { return m.pb.GetSequence() }
