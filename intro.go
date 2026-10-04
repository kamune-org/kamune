package kamune

import (
	"fmt"
	"unicode"
	"unicode/utf8"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/kamune-org/kamune/internal/box/pb"
	"github.com/kamune-org/kamune/pkg/attest"
	"github.com/kamune-org/kamune/pkg/storage"
)

// MaxPeerNameLength is the longest name, in bytes, that a peer may introduce
// itself with. See [ValidatePeerName].
const MaxPeerNameLength = 64

// ValidatePeerName checks a name that a peer introduces itself with. It
// returns an error wrapping [ErrInvalidPeerName] when name is longer than
// [MaxPeerNameLength] bytes, is not valid UTF-8, or holds a code point that
// can change how the name, or the text shown around it, looks:
//   - control characters (C0, DEL and C1), such as line breaks and the
//     escape character that starts terminal escape sequences;
//   - line and paragraph separators;
//   - format characters, which include the bidirectional controls that
//     reorder text and invisible ones such as the zero-width space, the
//     byte order mark and tag characters.
//
// The zero-width non-joiner and joiner (U+200C and U+200D) are allowed, as
// Persian and other scripts and emoji sequences need them. An empty name is
// valid.
//
// The server and the dialer reject an introduction whose name fails this
// check before the [RemoteVerifier] runs, and [ServeWithServerName] and
// [DialWithClientName] reject such a local name. Applications can use it to
// check names that users type. A peer's name is its own claim and proves
// nothing about its identity, which only the key fingerprint shows.
func ValidatePeerName(name string) error {
	if len(name) > MaxPeerNameLength {
		return fmt.Errorf(
			"%w: %d bytes, the limit is %d",
			ErrInvalidPeerName, len(name), MaxPeerNameLength,
		)
	}
	if !utf8.ValidString(name) {
		return fmt.Errorf("%w: not valid UTF-8", ErrInvalidPeerName)
	}
	for i, r := range name {
		if !allowedNameRune(r) {
			return fmt.Errorf(
				"%w: code point %U at byte %d", ErrInvalidPeerName, r, i,
			)
		}
	}
	return nil
}

// allowedNameRune reports whether r may appear in a peer's name. See
// [ValidatePeerName].
func allowedNameRune(r rune) bool {
	switch {
	case r == '\u200C', r == '\u200D':
		return true
	case unicode.IsControl(r):
		return false
	default:
		return !unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp)
	}
}

// sendIntroduction sends an identity introduction message to the peer.
// This is the first message exchanged in a new connection.
func sendIntroduction(
	conn Conn, at *attest.Attest, name, version string,
) error {
	intro := &pb.Introduce{
		Name:       name,
		PublicKey:  at.MarshalPublicKey(),
		AppVersion: version,
	}
	message, err := proto.Marshal(intro)
	if err != nil {
		return fmt.Errorf("marshalling intro: %w", err)
	}

	md := &pb.Metadata{
		Timestamp: timestamppb.Now(),
		Route:     RouteIdentity.ToProto(),
	}
	metadataBytes, err := proto.Marshal(md)
	if err != nil {
		return fmt.Errorf("marshalling metadata: %w", err)
	}

	sig, err := at.Sign(signingInput(metadataBytes, message))
	if err != nil {
		return fmt.Errorf("signing message: %w", err)
	}

	st := &pb.SignedTransport{
		Data:      message,
		Signature: sig,
		Metadata:  metadataBytes,
	}
	payload, err := padSignedTransport(st)
	if err != nil {
		return fmt.Errorf("padding signed transport: %w", err)
	}

	if err := conn.WriteBytes(payload); err != nil {
		return fmt.Errorf("writing: %w", err)
	}

	return nil
}

// receiveIntroduction parses an introduction message from a signed transport.
// It validates the signature and the peer's name (see [ValidatePeerName]) and
// extracts the peer's identity and version.
func receiveIntroduction(st *pb.SignedTransport) (*storage.Peer, string, error) {
	r, err := routeFromST(st)
	if err != nil {
		return nil, "", fmt.Errorf("extracting route: %w", err)
	}
	if r != RouteIdentity {
		return nil, "", fmt.Errorf(
			"%w: expected %s, got %s",
			ErrUnexpectedRoute, RouteIdentity, r,
		)
	}

	var introduce pb.Introduce
	msg := st.GetData()
	if err := proto.Unmarshal(msg, &introduce); err != nil {
		return nil, "", fmt.Errorf("deserializing: %w", err)
	}

	remote := introduce.GetPublicKey()
	if !attest.Verify(
		remote, signingInput(st.GetMetadata(), msg), st.GetSignature(),
	) {
		return nil, "", ErrInvalidSignature
	}
	if err := ValidatePeerName(introduce.GetName()); err != nil {
		return nil, "", err
	}

	peer := &storage.Peer{
		Name:       introduce.GetName(),
		PublicKey:  remote,
		AppVersion: introduce.GetAppVersion(),
	}

	return peer, introduce.GetAppVersion(), nil
}
