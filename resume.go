package kamune

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/sha3"

	"github.com/kamune-org/kamune/internal/box/pb"
	"github.com/kamune-org/kamune/internal/enigma"
	"github.com/kamune-org/kamune/pkg/attest"
	"github.com/kamune-org/kamune/pkg/ratchet"
)

const (
	resumeChallengeSize = 32
	resumeTimeout       = 30 * time.Second
)

var (
	ErrResumptionNotSupported = errors.New("session resumption not supported")
	ErrResumptionFailed       = errors.New("session resumption failed")
	ErrChallengeVerifyFailed  = errors.New("challenge verification failed")
	ErrSequenceMismatch       = errors.New("sequence number mismatch")
	ErrSessionTooOld          = errors.New("session is too old to resume")
)

// ResumableSession contains all the information needed to resume a session.
type ResumableSession struct {
	SessionID       string
	RemotePublicKey []byte
	LocalPublicKey  []byte
	SharedSecret    []byte
	LocalSalt       []byte
	RemoteSalt      []byte
	SendSequence    uint64
	RecvSequence    uint64
	Phase           SessionPhase
	IsInitiator     bool
	RatchetState    []byte // Serialized ratchet state
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// SessionResumer handles session resumption for both client and server.
type SessionResumer struct {
	storage        *Storage
	sessionManager *SessionManager
	attester       attest.Attester
	maxSessionAge  time.Duration
}

// NewSessionResumer creates a new session resumer.
func NewSessionResumer(
	storage *Storage,
	sessionManager *SessionManager,
	attester attest.Attester,
	maxAge time.Duration,
) *SessionResumer {
	if maxAge <= 0 {
		maxAge = 24 * time.Hour
	}
	return &SessionResumer{
		storage:        storage,
		sessionManager: sessionManager,
		attester:       attester,
		maxSessionAge:  maxAge,
	}
}

// CanResume checks if a session can be resumed with the given peer.
func (sr *SessionResumer) CanResume(
	remotePublicKey []byte,
) (bool, *SessionState, error) {
	state, err := sr.sessionManager.LoadSessionByPublicKey(remotePublicKey)
	if err != nil {
		if errors.Is(err, ErrSessionNotFound) {
			return false, nil, nil
		}
		return false, nil, err
	}

	// Check if session is too old
	if state.Phase != PhaseEstablished {
		return false, nil, nil
	}

	// Must have shared secret for resumption
	if len(state.SharedSecret) == 0 {
		return false, nil, nil
	}

	return true, state, nil
}

// InitiateResumption starts the resumption process as a client.
func (sr *SessionResumer) InitiateResumption(
	conn Conn, state *SessionState,
) (*Transport, error) {
	// Generate a challenge
	challenge := make([]byte, resumeChallengeSize)
	if _, err := rand.Read(challenge); err != nil {
		return nil, fmt.Errorf("generating challenge: %w", err)
	}

	// Create reconnect request
	req := &pb.ReconnectRequest{
		SessionId:        state.SessionID,
		LastPhase:        state.Phase.ToProto(),
		LastSendSequence: state.SendSequence,
		LastRecvSequence: state.RecvSequence,
		RemotePublicKey:  sr.attester.PublicKey().Marshal(),
		ResumeChallenge:  challenge,
	}

	// Send the reconnect request (unencrypted but signed)
	if err := sr.sendSignedMessage(conn, req, RouteReconnect); err != nil {
		return nil, fmt.Errorf("sending reconnect request: %w", err)
	}

	// Receive response
	var resp pb.ReconnectResponse
	route, err := sr.receiveSignedMessage(conn, &resp, state.RemotePublicKey)
	if err != nil {
		return nil, fmt.Errorf("receiving reconnect response: %w", err)
	}
	if route != RouteReconnect {
		return nil, fmt.Errorf(
			"%w: expected %s, got %s", ErrUnexpectedRoute, RouteReconnect, route,
		)
	}

	if !resp.Accepted {
		return nil, fmt.Errorf("%w: %s", ErrResumptionFailed, resp.ErrorMessage)
	}

	// Verify the server's challenge response
	expectedResponse := sr.computeChallengeResponse(challenge, state.SharedSecret)
	if subtle.ConstantTimeCompare(resp.ChallengeResponse, expectedResponse) != 1 {
		return nil, ErrChallengeVerifyFailed
	}

	// Compute our response to the server's challenge
	clientChallengeResponse := sr.computeChallengeResponse(
		resp.ServerChallenge, state.SharedSecret,
	)

	// Determine the sequence numbers to use
	resumeSendSeq, resumeRecvSeq := sr.reconcileSequences(
		state.SendSequence,
		state.RecvSequence,
		resp.ServerRecvSequence,
		resp.ServerSendSequence,
	)

	// Send verification
	verify := &pb.ReconnectVerify{
		ChallengeResponse: clientChallengeResponse,
		Verified:          true,
	}
	if err := sr.sendSignedMessage(conn, verify, RouteReconnect); err != nil {
		return nil, fmt.Errorf("sending verification: %w", err)
	}

	// Receive completion
	var complete pb.ReconnectComplete
	route, err = sr.receiveSignedMessage(conn, &complete, state.RemotePublicKey)
	if err != nil {
		return nil, fmt.Errorf("receiving completion: %w", err)
	}
	if route != RouteReconnect {
		return nil, fmt.Errorf(
			"%w: expected %s, got %s", ErrUnexpectedRoute, RouteReconnect, route,
		)
	}

	if !complete.Success {
		return nil, fmt.Errorf(
			"%w: %s", ErrResumptionFailed, complete.ErrorMessage,
		)
	}

	// Create the transport with restored state
	transport, err := sr.restoreTransport(
		conn, state, resumeSendSeq, resumeRecvSeq,
	)
	if err != nil {
		return nil, fmt.Errorf("restoring transport: %w", err)
	}

	return transport, nil
}

// HandleResumption handles an incoming resumption request as a server.
func (sr *SessionResumer) HandleResumption(
	conn Conn, req *pb.ReconnectRequest,
) (*Transport, error) {
	// Look up the session by the client's public key
	state, err := sr.sessionManager.LoadSessionByPublicKey(req.RemotePublicKey)
	if err != nil {
		if err := sr.sendRejectResponse(conn, "session not found"); err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("loading session: %w", err)
	}

	// Verify session ID matches
	if state.SessionID != req.SessionId {
		if err := sr.sendRejectResponse(conn, "session ID mismatch"); err != nil {
			return nil, err
		}
		return nil, ErrSessionMismatch
	}

	// Verify the session is in a resumable state
	if state.Phase != PhaseEstablished {
		if err := sr.sendRejectResponse(conn, "session not established"); err != nil {
			return nil, err
		}
		return nil, ErrResumptionNotSupported
	}

	// Generate server challenge
	serverChallenge := make([]byte, resumeChallengeSize)
	if _, err := rand.Read(serverChallenge); err != nil {
		return nil, fmt.Errorf("generating server challenge: %w", err)
	}

	// Compute response to client's challenge
	challengeResponse := sr.computeChallengeResponse(
		req.ResumeChallenge, state.SharedSecret,
	)

	// Send accept response
	resp := &pb.ReconnectResponse{
		Accepted:           true,
		ResumeFromPhase:    state.Phase.ToProto(),
		ChallengeResponse:  challengeResponse,
		ServerChallenge:    serverChallenge,
		ServerSendSequence: state.SendSequence,
		ServerRecvSequence: state.RecvSequence,
	}
	if err := sr.sendSignedMessage(conn, resp, RouteReconnect); err != nil {
		return nil, fmt.Errorf("sending accept response: %w", err)
	}

	// Receive client verification
	var verify pb.ReconnectVerify
	route, err := sr.receiveSignedMessage(conn, &verify, req.RemotePublicKey)
	if err != nil {
		return nil, fmt.Errorf("receiving verification: %w", err)
	}
	if route != RouteReconnect {
		return nil, fmt.Errorf(
			"%w: expected %s, got %s", ErrUnexpectedRoute, RouteReconnect, route,
		)
	}

	// Verify client's response to our challenge
	expectedClientResponse := sr.computeChallengeResponse(
		serverChallenge, state.SharedSecret,
	)
	if subtle.ConstantTimeCompare(verify.ChallengeResponse, expectedClientResponse) != 1 {
		complete := &pb.ReconnectComplete{
			Success:      false,
			ErrorMessage: "challenge verification failed",
		}
		_ = sr.sendSignedMessage(conn, complete, RouteReconnect)
		return nil, ErrChallengeVerifyFailed
	}

	// Determine sequence numbers
	resumeSendSeq, resumeRecvSeq := sr.reconcileSequences(
		state.SendSequence, state.RecvSequence,
		req.LastRecvSequence, req.LastSendSequence,
	)

	// Send completion
	complete := &pb.ReconnectComplete{
		Success:            true,
		ResumeSendSequence: resumeSendSeq,
		ResumeRecvSequence: resumeRecvSeq,
	}
	if err := sr.sendSignedMessage(conn, complete, RouteReconnect); err != nil {
		return nil, fmt.Errorf("sending completion: %w", err)
	}

	// Create the transport with restored state
	transport, err := sr.restoreTransport(conn, state, resumeSendSeq, resumeRecvSeq)
	if err != nil {
		return nil, fmt.Errorf("restoring transport: %w", err)
	}

	return transport, nil
}

// computeChallengeResponse computes an HMAC-based response to a challenge.
func (sr *SessionResumer) computeChallengeResponse(challenge, sharedSecret []byte) []byte {
	h := hmac.New(sha3.New256, sharedSecret)
	h.Write(challenge)
	h.Write([]byte("kamune-resume"))
	return h.Sum(nil)
}

// reconcileSequences determines the correct sequence numbers to resume from.
// It takes both sides' send and receive counts and returns the agreed values.
func (sr *SessionResumer) reconcileSequences(
	localSend, localRecv, remoteSend, remoteRecv uint64,
) (sendSeq, recvSeq uint64) {
	// For send sequence: use the max of our send and their recv
	// (they may have received messages we think we sent)
	sendSeq = localSend
	if remoteRecv > sendSeq {
		sendSeq = remoteRecv
	}

	// For recv sequence: use the max of our recv and their send
	// (they may have sent messages we haven't received)
	recvSeq = localRecv
	if remoteSend > recvSeq {
		recvSeq = remoteSend
	}

	return sendSeq, recvSeq
}

// restoreTransport creates a Transport from persisted session state.
func (sr *SessionResumer) restoreTransport(
	conn Conn,
	state *SessionState,
	sendSeq, recvSeq uint64,
) (*Transport, error) {
	// Parse remote public key
	remoteKey, err := sr.storage.algorithm.Identitfier().ParsePublicKey(state.RemotePublicKey)
	if err != nil {
		return nil, fmt.Errorf("parsing remote public key: %w", err)
	}

	// Create plain transport
	pt := newPlainTransport(
		&connWrapper{Conn: conn},
		remoteKey,
		sr.attester,
		sr.storage,
	)

	// Recreate enigma encoders/decoders
	var encoderInfo, decoderInfo string
	if state.IsInitiator {
		encoderInfo = state.SessionID + c2s
		decoderInfo = state.SessionID + s2c
	} else {
		encoderInfo = state.SessionID + s2c
		decoderInfo = state.SessionID + c2s
	}

	encoder, err := enigma.NewEnigma(state.SharedSecret, state.LocalSalt, []byte(encoderInfo))
	if err != nil {
		return nil, fmt.Errorf("creating encoder: %w", err)
	}

	decoder, err := enigma.NewEnigma(state.SharedSecret, state.RemoteSalt, []byte(decoderInfo))
	if err != nil {
		return nil, fmt.Errorf("creating decoder: %w", err)
	}

	// Create transport
	t := newTransport(pt, state.SessionID, encoder, decoder, defaultRatchetThreshold)
	t.SetInitiator(state.IsInitiator)
	t.SetSecrets(state.SharedSecret, state.LocalSalt, state.RemoteSalt)
	t.SetRemotePublicKey(state.RemotePublicKey)
	t.SetPhase(PhaseEstablished)

	// Restore sequence numbers
	t.mu.Lock()
	t.sendSequence = sendSeq
	t.recvSequence = recvSeq
	t.mu.Unlock()

	// Ratchet restoration:
	//
	// We now support serialization/deserialization for the ratchet package.
	// An established session may only be resumed if the persisted ratchet state
	// is present and can be restored successfully.
	if len(state.RatchetState) == 0 {
		return nil, fmt.Errorf("%w: missing ratchet state", ErrResumptionFailed)
	}

	st, err := ratchet.Deserialize(state.RatchetState)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid ratchet state: %v", ErrResumptionFailed, err)
	}

	dr, err := ratchet.Restore(st)
	if err != nil {
		return nil, fmt.Errorf("%w: restore ratchet failed: %v", ErrResumptionFailed, err)
	}

	// Install ratchet into transport (thread-safe)
	t.mu.Lock()
	t.ratchet = dr
	t.mu.Unlock()

	return t, nil
}

// sendSignedMessage sends a signed but unencrypted message.
func (sr *SessionResumer) sendSignedMessage(conn Conn, msg Transferable, route Route) error {
	data, err := marshalMessage(msg)
	if err != nil {
		return fmt.Errorf("marshaling message: %w", err)
	}

	sig, err := sr.attester.Sign(data)
	if err != nil {
		return fmt.Errorf("signing message: %w", err)
	}

	st := &pb.SignedTransport{
		Data:      data,
		Signature: sig,
		Padding:   padding(maxPadding),
		Route:     route.ToProto(),
	}

	payload, err := marshalMessage(st)
	if err != nil {
		return fmt.Errorf("marshaling transport: %w", err)
	}

	if err := conn.WriteBytes(payload); err != nil {
		return fmt.Errorf("writing: %w", err)
	}

	return nil
}

// receiveSignedMessage receives and verifies a signed message.
func (sr *SessionResumer) receiveSignedMessage(
	conn Conn,
	dst Transferable,
	remotePublicKey []byte,
) (Route, error) {
	payload, err := conn.ReadBytes()
	if err != nil {
		return RouteInvalid, fmt.Errorf("reading: %w", err)
	}

	var st pb.SignedTransport
	if err := unmarshalMessage(payload, &st); err != nil {
		return RouteInvalid, fmt.Errorf("unmarshaling transport: %w", err)
	}

	// Verify signature
	remoteKey, err := sr.storage.algorithm.Identitfier().ParsePublicKey(remotePublicKey)
	if err != nil {
		return RouteInvalid, fmt.Errorf("parsing remote key: %w", err)
	}

	if !sr.storage.algorithm.Identitfier().Verify(remoteKey, st.Data, st.Signature) {
		return RouteInvalid, ErrInvalidSignature
	}

	if err := unmarshalMessage(st.Data, dst); err != nil {
		return RouteInvalid, fmt.Errorf("unmarshaling message: %w", err)
	}

	return RouteFromProto(st.Route), nil
}

// sendRejectResponse sends a rejection response.
func (sr *SessionResumer) sendRejectResponse(conn Conn, reason string) error {
	resp := &pb.ReconnectResponse{
		Accepted:     false,
		ErrorMessage: reason,
	}
	return sr.sendSignedMessage(conn, resp, RouteReconnect)
}

// connWrapper wraps a Conn to satisfy the Conn interface for plain transport.
type connWrapper struct {
	Conn
}

// SaveSessionForResumption saves a transport's state for future resumption.
func SaveSessionForResumption(t *Transport, sm *SessionManager) error {
	state := t.State()
	if state.Phase != PhaseEstablished {
		return ErrSessionNotResumable
	}

	// Register session by public key for quick lookup
	if len(state.RemotePublicKey) > 0 {
		sm.RegisterSession(state.SessionID, state.RemotePublicKey)
	}

	return sm.SaveSession(state)
}

// ResumeOrDial attempts to resume an existing session, falling back to fresh dial.
func ResumeOrDial(
	dialer *Dialer,
	remotePublicKey []byte,
	sm *SessionManager,
) (*Transport, bool, error) {
	// Check if we can resume
	canResume, state, err := checkResumability(remotePublicKey, sm)
	if err != nil {
		return nil, false, fmt.Errorf("checking resumability: %w", err)
	}

	if !canResume || state == nil {
		// Fall back to fresh dial
		t, err := dialer.Dial()
		if err != nil {
			return nil, false, err
		}
		return t, false, nil
	}

	// Try to resume
	resumer := NewSessionResumer(
		dialer.storage,
		sm,
		dialer.attester,
		24*time.Hour,
	)

	// Create connection
	conn, err := dialer.dial(dialer.address)
	if err != nil {
		// Fall back to fresh dial
		t, err := dialer.Dial()
		if err != nil {
			return nil, false, err
		}
		return t, false, nil
	}

	t, err := resumer.InitiateResumption(conn, state)
	if err != nil {
		// Close failed connection and fall back
		_ = conn.Close()
		t, err := dialer.Dial()
		if err != nil {
			return nil, false, err
		}
		return t, false, nil
	}

	return t, true, nil
}

// checkResumability checks if we can resume a session with the peer.
func checkResumability(remotePublicKey []byte, sm *SessionManager) (bool, *SessionState, error) {
	state, err := sm.LoadSessionByPublicKey(remotePublicKey)
	if err != nil {
		if errors.Is(err, ErrSessionNotFound) {
			return false, nil, nil
		}
		return false, nil, err
	}

	if state.Phase != PhaseEstablished {
		return false, nil, nil
	}

	if len(state.SharedSecret) == 0 {
		return false, nil, nil
	}

	return true, state, nil
}

// marshalMessage is a helper to marshal protobuf messages.
func marshalMessage(msg Transferable) ([]byte, error) {
	return protoMarshal(msg)
}

// unmarshalMessage is a helper to unmarshal protobuf messages.
func unmarshalMessage(data []byte, msg Transferable) error {
	return protoUnmarshal(data, msg)
}
