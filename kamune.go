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
	sessionIDLength         = 20
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
	pb *pb.Metadata
}

// ID returns the unique message ID.
func (m Metadata) ID() string { return m.pb.GetID() }

// Timestamp returns the time the message was sent.
func (m Metadata) Timestamp() time.Time { return m.pb.Timestamp.AsTime() }

// SequenceNum returns the message sequence number.
func (m Metadata) SequenceNum() uint64 { return m.pb.GetSequence() }

// protoMarshal marshals a protobuf message to bytes.
func protoMarshal(msg Transferable) ([]byte, error) {
	return proto.Marshal(msg)
}

// protoUnmarshal unmarshals bytes into a protobuf message.
func protoUnmarshal(data []byte, msg Transferable) error {
	return proto.Unmarshal(data, msg)
}

// ResumptionConfig contains configuration for session resumption.
type ResumptionConfig struct {
	// Enabled controls whether session resumption is enabled.
	Enabled bool

	// MaxSessionAge is the maximum age of a session that can be resumed.
	MaxSessionAge time.Duration

	// PersistSessions controls whether sessions are persisted to storage.
	PersistSessions bool
}

// DefaultResumptionConfig returns the default resumption configuration.
func DefaultResumptionConfig() ResumptionConfig {
	return ResumptionConfig{
		Enabled:         true,
		MaxSessionAge:   24 * time.Hour,
		PersistSessions: true,
	}
}
