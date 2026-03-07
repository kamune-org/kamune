// Package kamune provides secure communication over untrusted networks.
package kamune

import (
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/kamune-org/kamune/internal/box/pb"
	"github.com/kamune-org/kamune/pkg/attest"
	"github.com/kamune-org/kamune/pkg/storage"
)

const (
	// Domain separation labels for handshake message encryption.
	handshakeC2SInfo = "kamune/handshake/client-to-server/v1"
	handshakeS2CInfo = "kamune/handshake/server-to-client/v1"

	// Domain separation labels for reconnect message encryption.
	reconnectC2SInfo = "kamune/reconnect/c2s/v1"
	reconnectS2CInfo = "kamune/reconnect/s2c/v1"

	// Must be less than or equal to 65535 ([math.MaxUint16]).
	maxTransportSize = 50 * 1024

	saltSize        = 16
	sessionIDLength = 20
	challengeSize   = 32
	maxPadding      = 256
)

var _ uint16 = maxTransportSize

type (
	PublicKey      = attest.PublicKey
	RemoteVerifier func(store *storage.Storage, peer *storage.Peer) error
	HandlerFunc    func(t *Transport) error
)

// Transferable is the interface for messages that can be sent over a transport.
type Transferable interface {
	proto.Message
}

// Bytes creates a BytesValue wrapper for sending raw bytes.
func Bytes(b []byte) *wrapperspb.BytesValue {
	return &wrapperspb.BytesValue{Value: b}
}

// Metadata contains metadata about a received message.
type Metadata struct {
	pb    *pb.Metadata
	route Route
}

// ID returns the unique message ID.
func (m Metadata) ID() string { return m.pb.GetID() }

// Timestamp returns the time the message was sent.
func (m Metadata) Timestamp() time.Time { return m.pb.Timestamp.AsTime() }

// SequenceNum returns the per-message sequence number.
func (m Metadata) SequenceNum() uint64 { return m.pb.GetSequence() }

// Route returns the route associated with this message.
func (m Metadata) Route() Route { return m.route }

// protoMarshal marshals a protobuf message to bytes.
func protoMarshal(msg Transferable) ([]byte, error) {
	return proto.Marshal(msg)
}

// protoUnmarshal unmarshals bytes into a protobuf message.
func protoUnmarshal(data []byte, msg Transferable) error {
	return proto.Unmarshal(data, msg)
}
