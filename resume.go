package kamune

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"time"

	"github.com/kamune-org/kamune/internal/box/pb"
	"github.com/kamune-org/kamune/internal/enigma"
	"github.com/kamune-org/kamune/pkg/attest"
	"google.golang.org/protobuf/proto"
)

const (
	resumeChallengeSize = 32
	resumeTimeout       = 30 * time.Second
)

const (
	// Domain separation labels for reconnect message encryption.
	//
	// We intentionally use distinct labels for each direction to reduce the risk
	// of key/nonce reuse in case of implementation errors and to provide clearer
	// protocol separation.
	reconnectC2SEncryptInfo = "kamune/reconnect/c2s/encrypt/v1"
	reconnectC2SDecryptInfo = "kamune/reconnect/c2s/decrypt/v1"
	reconnectS2CEncryptInfo = "kamune/reconnect/s2c/encrypt/v1"
	reconnectS2CDecryptInfo = "kamune/reconnect/s2c/decrypt/v1"
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
	UpdatedAt       time.Time
	CreatedAt       time.Time
	SessionID       string
	RemotePublicKey []byte
	LocalPublicKey  []byte
	SharedSecret    []byte
	LocalSalt       []byte
	RemoteSalt      []byte
	SendSequence    uint64
	Phase           SessionPhase
	RecvSequence    uint64
	IsInitiator     bool
}

// SessionResumer handles session resumption for both client and server.
type SessionResumer struct {
	storage        *Storage
	sessionManager *SessionManager
	attester       attest.Attester
	maxSessionAge  time.Duration
}

// sessionAgeOK enforces the configured max session age for resumption.
// We accept UpdatedAt as the primary freshness signal (because it moves forward
// across resumption and normal session updates). If UpdatedAt is missing, we
// fall back to CreatedAt. If both are missing, we fail closed.
func (sr *SessionResumer) sessionAgeOK(state *SessionState) error {
	if sr.maxSessionAge <= 0 {
		return nil
	}
	if state == nil {
		return ErrSessionTooOld
	}

	// Prefer UpdatedAt if available; otherwise fall back to CreatedAt.
	t := state.UpdatedAt
	if t.IsZero() {
		t = state.CreatedAt
	}

	// Fail closed if we cannot establish the session's age.
	if t.IsZero() {
		return ErrSessionTooOld
	}

	if time.Since(t) > sr.maxSessionAge {
		return ErrSessionTooOld
	}

	return nil
}

// encryptSignedTransport encrypts a SignedTransport payload (protobuf bytes)
// using a key derived from the session shared secret.
//
// The ciphertext is stored in SignedTransport.Data, and the signature covers
// the encrypted Data bytes.
func (sr *SessionResumer) encryptSignedTransport(sharedSecret []byte, info string, st *pb.SignedTransport) error {
	if st == nil {
		return errors.New("nil signed transport")
	}
	// Nothing to do if there's no data.
	if len(st.Data) == 0 {
		return nil
	}

	e, err := enigma.NewEnigma(sharedSecret, nil, []byte(info))
	if err != nil {
		return fmt.Errorf("creating reconnect encryptor: %w", err)
	}
	st.Data = e.Encrypt(st.Data)
	return nil
}

// decryptSignedTransport decrypts SignedTransport.Data using a key derived from
// the session shared secret.
func (sr *SessionResumer) decryptSignedTransport(sharedSecret []byte, info string, st *pb.SignedTransport) error {
	if st == nil {
		return errors.New("nil signed transport")
	}
	if len(st.Data) == 0 {
		return nil
	}

	e, err := enigma.NewEnigma(sharedSecret, nil, []byte(info))
	if err != nil {
		return fmt.Errorf("creating reconnect decryptor: %w", err)
	}
	plain, err := e.Decrypt(st.Data)
	if err != nil {
		return fmt.Errorf("decrypting reconnect payload: %w", err)
	}
	st.Data = plain
	return nil
}

// sendSignedMessageWithSecret sends a signed reconnect message.
//
// If sharedSecret is non-empty, it encrypts the message payload first (with the
// provided info label) and then signs the encrypted bytes. This reduces metadata
// leakage during resumption while still authenticating the ciphertext.
func (sr *SessionResumer) sendSignedMessageWithSecret(
	conn Conn,
	sharedSecret []byte,
	encryptInfo string,
	msg Transferable,
	route Route,
) error {
	data, err := marshalMessage(msg)
	if err != nil {
		return fmt.Errorf("marshaling message: %w", err)
	}

	st := &pb.SignedTransport{
		Data:    data,
		Padding: padding(maxPadding),
		Route:   route.ToProto(),
	}

	if len(sharedSecret) > 0 && encryptInfo != "" {
		if err := sr.encryptSignedTransport(sharedSecret, encryptInfo, st); err != nil {
			return err
		}
	}

	sig, err := sr.attester.Sign(st.Data)
	if err != nil {
		return fmt.Errorf("signing message: %w", err)
	}
	st.Signature = sig

	payload, err := proto.Marshal(st)
	if err != nil {
		return fmt.Errorf("marshaling transport: %w", err)
	}

	if err := conn.WriteBytes(payload); err != nil {
		return fmt.Errorf("writing: %w", err)
	}

	return nil
}

// receiveSignedMessageWithSecret receives, verifies, and decrypts (when possible)
// a signed reconnect message.
func (sr *SessionResumer) receiveSignedMessageWithSecret(
	conn Conn,
	sharedSecret []byte,
	decryptInfo string,
	dst Transferable,
	remotePublicKey []byte,
) (Route, error) {
	payload, err := conn.ReadBytes()
	if err != nil {
		return RouteInvalid, fmt.Errorf("reading: %w", err)
	}

	var st pb.SignedTransport
	if err := proto.Unmarshal(payload, &st); err != nil {
		return RouteInvalid, fmt.Errorf("unmarshaling transport: %w", err)
	}

	// Verify signature over the current Data bytes (encrypted or plaintext).
	remoteKey, err := sr.storage.algorithm.Identitfier().ParsePublicKey(remotePublicKey)
	if err != nil {
		return RouteInvalid, fmt.Errorf("parsing remote key: %w", err)
	}

	if !sr.storage.algorithm.Identitfier().Verify(remoteKey, st.Data, st.Signature) {
		return RouteInvalid, ErrInvalidSignature
	}

	route := RouteFromProto(st.Route)

	// Decrypt if a shared secret is available.
	if len(sharedSecret) > 0 && decryptInfo != "" {
		if err := sr.decryptSignedTransport(sharedSecret, decryptInfo, &st); err != nil {
			return RouteInvalid, err
		}
	}

	if err := unmarshalMessage(st.Data, dst); err != nil {
		return RouteInvalid, fmt.Errorf("unmarshaling message: %w", err)
	}

	return route, nil
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

	// Must be fully established.
	if state.Phase != PhaseEstablished {
		return false, nil, nil
	}

	// Must have shared secret for resumption.
	if len(state.SharedSecret) == 0 {
		return false, nil, nil
	}

	// Enforce session age if possible.
	if err := sr.sessionAgeOK(state); err != nil {
		return false, nil, err
	}

	return true, state, nil
}

// InitiateResumption starts the resumption process as a client.
func (sr *SessionResumer) InitiateResumption(
	conn Conn, state *SessionState,
) (*Transport, error) {
	if err := sr.sessionAgeOK(state); err != nil {
		return nil, err
	}

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

	// Send the reconnect request (encrypted + signed)
	if err := sr.sendSignedMessageWithSecret(
		conn,
		state.SharedSecret,
		reconnectC2SEncryptInfo,
		req,
		RouteReconnect,
	); err != nil {
		return nil, fmt.Errorf("sending reconnect request: %w", err)
	}

	// Receive response (encrypted + signed)
	var resp pb.ReconnectResponse
	route, err := sr.receiveSignedMessageWithSecret(
		conn,
		state.SharedSecret,
		reconnectS2CDecryptInfo,
		&resp,
		state.RemotePublicKey,
	)
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

	expectedResponse, err := sr.computeChallengeResponse(
		challenge, state.SharedSecret,
	)
	if err != nil {
		return nil, fmt.Errorf("compute expected challenge response: %w", err)
	}
	if subtle.ConstantTimeCompare(resp.ChallengeResponse, expectedResponse) != 1 {
		return nil, ErrChallengeVerifyFailed
	}

	clientChallengeResponse, err := sr.computeChallengeResponse(
		resp.ServerChallenge, state.SharedSecret,
	)
	if err != nil {
		return nil, fmt.Errorf("compute client challenge response: %w", err)
	}

	// Determine the sequence numbers to use
	resumeSendSeq, resumeRecvSeq := sr.reconcileSequences(
		state.SendSequence,
		state.RecvSequence,
		resp.ServerRecvSequence,
		resp.ServerSendSequence,
	)

	// Send verification (encrypted + signed)
	verify := &pb.ReconnectVerify{
		ChallengeResponse: clientChallengeResponse,
		Verified:          true,
	}
	if err := sr.sendSignedMessageWithSecret(
		conn,
		state.SharedSecret,
		reconnectC2SEncryptInfo,
		verify,
		RouteReconnect,
	); err != nil {
		return nil, fmt.Errorf("sending verification: %w", err)
	}

	// Receive completion (encrypted + signed)
	var complete pb.ReconnectComplete
	route, err = sr.receiveSignedMessageWithSecret(
		conn,
		state.SharedSecret,
		reconnectS2CDecryptInfo,
		&complete,
		state.RemotePublicKey,
	)
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
	// Look up the session by the client's public key.
	state, err := sr.sessionManager.LoadSessionByPublicKey(req.RemotePublicKey)
	if err != nil {
		// Generic rejection to reduce session enumeration.
		if err := sr.sendRejectResponse(conn, "resumption failed"); err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("loading session: %w", err)
	}

	// Enforce session age if possible.
	if err := sr.sessionAgeOK(state); err != nil {
		// Generic rejection to reduce session enumeration.
		if err2 := sr.sendRejectResponse(conn, "resumption failed"); err2 != nil {
			return nil, err2
		}
		return nil, ErrSessionTooOld
	}

	// Verify session ID matches.
	if state.SessionID != req.SessionId {
		// Generic rejection to reduce session enumeration.
		if err := sr.sendRejectResponse(conn, "resumption failed"); err != nil {
			return nil, err
		}
		return nil, ErrSessionMismatch
	}

	// Verify the session is in a resumable state.
	if state.Phase != PhaseEstablished {
		// Generic rejection to reduce session enumeration.
		if err := sr.sendRejectResponse(conn, "resumption failed"); err != nil {
			return nil, err
		}
		return nil, ErrResumptionNotSupported
	}

	// Generate server challenge.
	serverChallenge := make([]byte, resumeChallengeSize)
	if _, err := rand.Read(serverChallenge); err != nil {
		return nil, fmt.Errorf("generating server challenge: %w", err)
	}

	// Compute response to client's challenge.
	challengeResponse, err := sr.computeChallengeResponse(
		req.ResumeChallenge, state.SharedSecret,
	)
	if err != nil {
		return nil, fmt.Errorf("compute challenge response: %w", err)
	}

	// Send accept response (encrypted + signed).
	resp := &pb.ReconnectResponse{
		Accepted:           true,
		ResumeFromPhase:    state.Phase.ToProto(),
		ChallengeResponse:  challengeResponse,
		ServerChallenge:    serverChallenge,
		ServerSendSequence: state.SendSequence,
		ServerRecvSequence: state.RecvSequence,
	}
	if err := sr.sendSignedMessageWithSecret(
		conn,
		state.SharedSecret,
		reconnectS2CEncryptInfo,
		resp,
		RouteReconnect,
	); err != nil {
		return nil, fmt.Errorf("sending accept response: %w", err)
	}

	// Receive client verification (encrypted + signed).
	var verify pb.ReconnectVerify
	route, err := sr.receiveSignedMessageWithSecret(
		conn,
		state.SharedSecret,
		reconnectC2SDecryptInfo,
		&verify,
		req.RemotePublicKey,
	)
	if err != nil {
		return nil, fmt.Errorf("receiving verification: %w", err)
	}
	if route != RouteReconnect {
		return nil, fmt.Errorf(
			"%w: expected %s, got %s", ErrUnexpectedRoute, RouteReconnect, route,
		)
	}

	// Verify client's response to our challenge.
	expectedClientResponse, err := sr.computeChallengeResponse(
		serverChallenge, state.SharedSecret,
	)
	if err != nil {
		return nil, fmt.Errorf("compute expected client response: %w", err)
	}
	if subtle.ConstantTimeCompare(verify.ChallengeResponse, expectedClientResponse) != 1 {
		complete := &pb.ReconnectComplete{
			Success:      false,
			ErrorMessage: "resumption failed",
		}
		_ = sr.sendSignedMessageWithSecret(
			conn,
			state.SharedSecret,
			reconnectS2CEncryptInfo,
			complete,
			RouteReconnect,
		)
		return nil, ErrChallengeVerifyFailed
	}

	// Determine sequence numbers.
	resumeSendSeq, resumeRecvSeq := sr.reconcileSequences(
		state.SendSequence, state.RecvSequence,
		req.LastRecvSequence, req.LastSendSequence,
	)

	// Send completion (encrypted + signed).
	complete := &pb.ReconnectComplete{
		Success:            true,
		ResumeSendSequence: resumeSendSeq,
		ResumeRecvSequence: resumeRecvSeq,
	}
	if err := sr.sendSignedMessageWithSecret(
		conn,
		state.SharedSecret,
		reconnectS2CEncryptInfo,
		complete,
		RouteReconnect,
	); err != nil {
		return nil, fmt.Errorf("sending completion: %w", err)
	}

	// Create the transport with restored state.
	transport, err := sr.restoreTransport(conn, state, resumeSendSeq, resumeRecvSeq)
	if err != nil {
		return nil, fmt.Errorf("restoring transport: %w", err)
	}

	return transport, nil
}

// computeChallengeResponse computes an HMAC-based response to a challenge.
func (sr *SessionResumer) computeChallengeResponse(
	challenge, sharedSecret []byte,
) ([]byte, error) {
	return enigma.Derive(
		sharedSecret, nil, []byte(challenge), resumeChallengeSize,
	)
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
	t := newTransport(pt, state.SessionID, encoder, decoder)
	t.SetInitiator(state.IsInitiator)
	t.SetSecrets(state.SharedSecret, state.LocalSalt, state.RemoteSalt)
	t.SetRemotePublicKey(state.RemotePublicKey)
	t.SetPhase(PhaseEstablished)

	// Restore sequence numbers
	t.mu.Lock()
	t.sendSequence = sendSeq
	t.recvSequence = recvSeq
	t.mu.Unlock()

	return t, nil
}

// sendSignedMessage sends a signed (but not encrypted) message.
//
// This is used for non-resumption traffic and for resumption rejection paths
// where no sharedSecret is available.
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

// receiveSignedMessage receives and verifies a signed (but not encrypted) message.
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

	// Verify signature.
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
