package kamune

import (
	"fmt"

	"google.golang.org/protobuf/proto"

	"github.com/kamune-org/kamune/internal/box/pb"
	"github.com/kamune-org/kamune/pkg/attest"
)

// sendResumeRequest sends a ResumeRequest through the HPKE tunnel. The request
// contains the session ID and a resumption token.
func sendResumeRequest(
	conn Conn, at *attest.Attest, sessionID string, token []byte,
) error {
	req := &pb.ResumeRequest{
		SessionID: sessionID,
		Token:     token,
	}
	message, err := proto.Marshal(req)
	if err != nil {
		return fmt.Errorf("marshalling resume request: %w", err)
	}

	md := &pb.Metadata{
		Route: RouteResumeRequest.ToProto(),
	}
	metadataBytes, err := proto.Marshal(md)
	if err != nil {
		return fmt.Errorf("marshalling metadata: %w", err)
	}

	sig, err := at.Sign(signingInput(metadataBytes, message))
	if err != nil {
		return fmt.Errorf("signing resume request: %w", err)
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

// receiveResumeAccept reads and parses a ResumeAccept from the HPKE tunnel,
// verifying the signature against the server's public key. Returns whether
// resumption was accepted and any rejection reason.
func receiveResumeAccept(
	conn Conn, remote []byte,
) (accepted bool, reason string, err error) {
	st, err := readSignedTransport(conn)
	if err != nil {
		return false, "", fmt.Errorf("reading resume accept: %w", err)
	}

	r, err := routeFromST(st)
	if err != nil {
		return false, "", fmt.Errorf("extracting route: %w", err)
	}
	if r != RouteResumeAccept {
		return false, "", fmt.Errorf(
			"%w: expected %s, got %s", ErrUnexpectedRoute, RouteResumeAccept, r,
		)
	}

	if !attest.Verify(
		remote, signingInput(st.GetMetadata(), st.GetData()), st.GetSignature(),
	) {
		return false, "", ErrInvalidSignature
	}

	var accept pb.ResumeAccept
	if err := proto.Unmarshal(st.GetData(), &accept); err != nil {
		return false, "", fmt.Errorf("deserializing resume accept: %w", err)
	}

	return accept.GetAccepted(), accept.GetReason(), nil
}

// sendResumeAccept signs and sends a ResumeAccept response through the HPKE
// tunnel.
func sendResumeAccept(conn Conn, at *attest.Attest, accepted bool) error {
	var reason string
	if !accepted {
		reason = "resumption not available"
	}
	resp := &pb.ResumeAccept{
		Accepted: accepted,
		Reason:   reason,
	}
	message, err := proto.Marshal(resp)
	if err != nil {
		return fmt.Errorf("marshalling resume accept: %w", err)
	}

	md := &pb.Metadata{
		Route: RouteResumeAccept.ToProto(),
	}
	metadataBytes, err := proto.Marshal(md)
	if err != nil {
		return fmt.Errorf("marshalling metadata: %w", err)
	}

	sig, err := at.Sign(signingInput(metadataBytes, message))
	if err != nil {
		return fmt.Errorf("signing resume accept: %w", err)
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
