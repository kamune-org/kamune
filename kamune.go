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

	// transportReserve is the headroom kept below math.MaxUint16 for a
	// Conn that wraps every kamune frame again before it puts its own
	// 2-byte length prefix on the wire. The relay transport adds a
	// relay Frame envelope (8 bytes) and an HPKE tag (16 bytes); the
	// rest is margin.
	transportReserve = 64

	// maxFrameSize is the largest frame kamune hands to a Conn. It
	// leaves transportReserve bytes below math.MaxUint16 (the wire
	// format's hard upper bound).
	maxFrameSize = math.MaxUint16 - transportReserve

	// frameTargetSize is the maximum pre-encryption size for a padded
	// SignedTransport. After encryption, the frame is frameTargetSize +
	// encryptionOverhead, which equals maxFrameSize.
	frameTargetSize = maxFrameSize - encryptionOverhead

	// maxTransportSize is the protocol's user-message cap. It is derived as
	// maxFrameSize - reservedProtocolOverhead.
	maxTransportSize = maxFrameSize - reservedProtocolOverhead

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
// bytes). Bucket 6 lands on frameTargetSize so the encrypted frame is exactly
// maxFrameSize and still fits math.MaxUint16 after relay wrapping.
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
	// RemoteVerifier decides whether to accept a peer. It runs during the
	// handshake, after the peer's introduction has arrived and before the
	// session is established; an error rejects the peer. It may wait for a
	// user's decision for up to the verify timeout (see
	// [ServeWithVerifyTimeout] and [DialWithVerifyTimeout]), and an accept
	// that comes later counts as a rejection.
	//
	// The handshake can still fail after the verifier accepts, for example
	// when the peer gives up. A verifier should therefore not store the peer
	// itself; store it once the session is established, in the [HandlerFunc]
	// or after [Dialer.Dial] returns, from [Transport.RemotePeer].
	//
	// A [Server] runs the verifier for each introduction it receives and
	// does not limit how many runs are in progress at once, apart from the
	// per-source cap of [ServeWithMaxPendingPerSource]. A verifier that
	// prompts a user should limit its open prompts itself, for example by
	// rejecting an unknown peer while a prompt is open.
	//
	// The verifier runs only in a cold handshake, the one with
	// introductions. Neither side runs it when a session is resumed: the
	// server then accepts a dialer that proves it holds the key stored for
	// the session, as long as that peer is still in storage. An application
	// that must verify every connection, for example by asking its user
	// each time, should turn resumption off with [ServeWithResumeEnabled];
	// see there for the details.
	RemoteVerifier func(store *storage.Storage, peer *storage.Peer) error

	// HandlerFunc receives each session a [Server] establishes.
	HandlerFunc func(t *Transport) error
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
