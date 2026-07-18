// Package kamune provides secure communication over untrusted networks.
package kamune

import (
	"math"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/kamune-org/kamune/internal/box/pb"
	"github.com/kamune-org/kamune/pkg/storage"
)

const (
	// reservedProtocolOverhead is the bytes the protocol reserves per
	// message for signature, metadata, AEAD tag, and minimum padding.
	reservedProtocolOverhead = 4 * 1024

	// encryptionOverhead is the number of bytes added by the AEAD
	// (XChaCha20-Poly1305): 24-byte nonce + 16-byte tag.
	encryptionOverhead = 40

	// frameTargetSize is the maximum pre-encryption size for a padded
	// SignedTransport. After encryption, the wire payload is frameTargetSize +
	// encryptionOverhead, which must fit in math.MaxUint16 (the wire format's
	// hard upper bound).
	frameTargetSize = math.MaxUint16 - encryptionOverhead

	// maxTransportSize is the protocol's user-message cap. It is derived as
	// math.MaxUint16 - reservedProtocolOverhead.
	maxTransportSize = math.MaxUint16 - reservedProtocolOverhead

	// sessionIDLength is the length of the session ID.
	sessionIDLength = 24

	// Handshake domain separation labels.
	handshakeInfo    = "kamune/handshake/v1"
	handshakeC2SInfo = "kamune/handshake/client-to-server/v1/"
	handshakeS2CInfo = "kamune/handshake/server-to-client/v1/"

	// Handshake constants.
	handshakeSaltSize      = 16
	handshakeChallengeSize = 32

	// Transport signing domain separation label (RFC002).
	transportSignInfo = "kamune/transport-sign/v1"

	// Resumption domain separation labels.
	resumptionRootInfo  = "kamune/resumption-root/v1"
	resumptionTokenInfo = "kamune/resumption/token/v1/"

	// Resumption constants.
	resumptionGracePeriod = 24 * time.Hour
	resumptionTokenCount  = 20
	resumptionTokenSize   = 32
)

// Bucket sizes for the bucketed padding scheme (pre-encryption target sizes in
// bytes). Bucket 6 lands on frameTargetSize so the encrypted wire payload fits
// exactly in math.MaxUint16.
var paddingBuckets = []int{
	512,
	1024,
	4 * 1024,
	16 * 1024,
	32 * 1024,
	frameTargetSize,
}

// Cross-bucket bump probabilities (per §12.7). The distribution is used to
// select a random bump level: 0 = stay, 1 = +1, 2 = +2, 3 = +3. Probabilities
// must sum to 100.
var bumpProbabilities = []int{80, 15, 4, 1}

type (
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
	pb *pb.Metadata
}

// ID returns the unique message ID.
func (m Metadata) ID() string { return m.pb.GetID() }

// Timestamp returns the time the message was sent.
func (m Metadata) Timestamp() time.Time { return m.pb.Timestamp.AsTime() }

// SequenceNum returns the per-message sequence number.
func (m Metadata) SequenceNum() uint64 { return m.pb.GetSequence() }

// Route returns the route associated with this message.
func (m Metadata) Route() Route { return RouteFromProto(m.pb.GetRoute()) }
