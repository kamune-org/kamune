// Package kamune provides secure communication over untrusted networks.
package kamune

import (
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/hossein1376/kamune/internal/box/pb"
	"github.com/hossein1376/kamune/pkg/attest"
)

const (
	// must be less than or equal to 65535 ([math.MaxUint16])
	maxTransportSize = 10 * 1024
	saltSize         = 16
	sessionIDLength  = 30
	challengeSize    = 32
	introducePadding = 512
	messagePadding   = 128
	handshakePadding = 32

	c2s = "client-to-server"
	s2c = "server-to-client"
)

type (
	PublicKey      = attest.PublicKey
	RemoteVerifier func(store *Storage, key PublicKey) (err error)
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
