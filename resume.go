package kamune

import (
	"crypto/hmac"
	"crypto/sha512"
	"fmt"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/kamune-org/kamune/internal/box/pb"
	"github.com/kamune-org/kamune/pkg/attest"
	"github.com/kamune-org/kamune/pkg/storage"
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
	return parseResumeAccept(st, remote)
}

func parseResumeAccept(
	st *pb.SignedTransport, remote []byte,
) (accepted bool, reason string, err error) {
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

const (
	defaultResumeIdle   = 24 * time.Hour
	defaultResumeMaxAge = 7 * 24 * time.Hour
)

type resumeLockKey struct {
	store *storage.Storage
	sid   string
}

// resumeHold is one session's resume mutex. refs counts goroutines that
// have observed the entry and not yet finished TryLock or Unlock, so the
// entry is not deleted in that window.
type resumeHold struct {
	mu   sync.Mutex
	refs int
}

var (
	resumeMu    sync.Mutex
	resumeHolds = map[resumeLockKey]*resumeHold{}
)

// tryResumeLock locks one in-process resume of sid. The returned function
// releases the lock and drops the map entry once nobody holds it.
func tryResumeLock(store *storage.Storage, sid string) (func(), bool) {
	key := resumeLockKey{store: store, sid: sid}
	resumeMu.Lock()
	h := resumeHolds[key]
	if h == nil {
		h = &resumeHold{}
		resumeHolds[key] = h
	}
	h.refs++
	resumeMu.Unlock()

	if !h.mu.TryLock() {
		releaseResume(key, h)
		return nil, false
	}
	return func() {
		h.mu.Unlock()
		releaseResume(key, h)
	}, true
}

func releaseResume(key resumeLockKey, h *resumeHold) {
	resumeMu.Lock()
	h.refs--
	if h.refs == 0 {
		cur := resumeHolds[key]
		if cur == h {
			delete(resumeHolds, key)
		}
	}
	resumeMu.Unlock()
}

func binderKey(res []byte) ([]byte, error) {
	return expandLabel(res, "res binder", nil, hashLen)
}

func resPSK(res []byte) ([]byte, error) {
	return expandLabel(res, "res psk", nil, hashLen)
}

func macSHA512(key, msg []byte) []byte {
	m := hmac.New(sha512.New, key)
	_, _ = m.Write(msg)
	return m.Sum(nil)
}
