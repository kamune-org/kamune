package kamune

import (
	"fmt"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/kamune-org/kamune/internal/box/pb"
	"github.com/kamune-org/kamune/pkg/attest"
	"github.com/kamune-org/kamune/pkg/storage"
)

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
// It validates the signature and extracts the peer's identity and version.
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

	peer := &storage.Peer{
		Name:       introduce.GetName(),
		PublicKey:  remote,
		AppVersion: introduce.GetAppVersion(),
	}

	return peer, introduce.GetAppVersion(), nil
}
