package kamune

import (
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	mathrand "math/rand/v2"

	"github.com/kamune-org/kamune/internal/box/pb"
	"github.com/kamune-org/kamune/internal/enigma"
	"github.com/kamune-org/kamune/pkg/exchange"
	"github.com/kamune-org/kamune/pkg/ratchet"
)

type handshakeOpts struct {
	remoteVerifier   RemoteVerifier
	ratchetThreshold uint64
}

// handshakeState tracks the state of an ongoing handshake for potential
// resumption after connection reset.
type handshakeState struct {
	mlkemPrivateKey *exchange.MLKEM
	sessionID       string
	sessionPrefix   string
	sessionSuffix   string
	localSalt       []byte
	remoteSalt      []byte
	sharedSecret    []byte
	phase           SessionPhase
	isInitiator     bool
}

// requestHandshake initiates a handshake as the client/initiator.
func requestHandshake(
	pt *plainTransport, opts handshakeOpts,
) (*Transport, error) {
	state := &handshakeState{
		isInitiator: true,
		phase:       PhaseIntroduction,
	}

	// Step 1: Generate MLKEM keys and send handshake request
	ml, err := exchange.NewMLKEM()
	if err != nil {
		return nil, fmt.Errorf("creating MLKEM keys: %w", err)
	}
	state.mlkemPrivateKey = ml

	state.localSalt = randomBytes(saltSize)
	state.sessionPrefix = enigma.Text(sessionIDLength / 2)

	req := &pb.Handshake{
		Key:        ml.PublicKey.Bytes(),
		Salt:       state.localSalt,
		SessionKey: state.sessionPrefix,
	}

	reqBytes, _, err := pt.serialize(req, RouteRequestHandshake)
	if err != nil {
		return nil, fmt.Errorf("serializing handshake request: %w", err)
	}
	if err = pt.conn.WriteBytes(reqBytes); err != nil {
		return nil, fmt.Errorf("writing handshake request: %w", err)
	}
	state.phase = PhaseHandshakeRequested

	// Step 2: Receive handshake response
	respBytes, err := pt.conn.ReadBytes()
	if err != nil {
		return nil, fmt.Errorf("reading handshake response: %w", err)
	}

	var resp pb.Handshake
	_, route, err := pt.deserialize(respBytes, &resp)
	if err != nil {
		return nil, fmt.Errorf("deserializing handshake response: %w", err)
	}
	if route != RouteAcceptHandshake {
		return nil, fmt.Errorf(
			"%w: expected %s, got %s",
			ErrUnexpectedRoute, RouteAcceptHandshake, route,
		)
	}

	// Step 3: Decapsulate shared secret
	secret, err := ml.Decapsulate(resp.GetKey())
	if err != nil {
		return nil, fmt.Errorf("decapsulating secret: %w", err)
	}
	state.sharedSecret = secret
	state.remoteSalt = resp.GetSalt()
	state.sessionSuffix = resp.GetSessionKey()
	state.sessionID = state.sessionPrefix + state.sessionSuffix
	state.phase = PhaseHandshakeAccepted

	// Step 4: Create transport with encryption
	encoder, err := enigma.NewEnigma(
		secret, state.localSalt, []byte(state.sessionID+c2s),
	)
	if err != nil {
		return nil, fmt.Errorf("creating encrypter: %w", err)
	}
	decoder, err := enigma.NewEnigma(
		secret, state.remoteSalt, []byte(state.sessionID+s2c),
	)
	if err != nil {
		return nil, fmt.Errorf("creating decrypter: %w", err)
	}

	t := newTransport(pt, state.sessionID, encoder, decoder, opts.ratchetThreshold)
	t.SetInitiator(true)
	t.SetSecrets(secret, state.localSalt, state.remoteSalt)
	t.SetRemotePublicKey(pt.remote.Marshal())

	// Step 5: Challenge exchange
	if err := sendChallenge(t, secret, []byte(state.sessionID+c2s)); err != nil {
		return nil, fmt.Errorf("sending challenge: %w", err)
	}
	t.SetPhase(PhaseChallengeSent)

	if err := acceptChallenge(t, RouteSendChallenge); err != nil {
		return nil, fmt.Errorf("accepting challenge: %w", err)
	}
	t.SetPhase(PhaseChallengeVerified)

	// Step 6: Bootstrap double ratchet
	r, err := bootstrapDoubleRatchet(t, secret, t.sessionID, true)
	if err != nil {
		return nil, fmt.Errorf("bootstrap double ratchet: %w", err)
	}
	t.ratchet = r
	t.SetPhase(PhaseEstablished)

	return t, nil
}

// acceptHandshake accepts an incoming handshake as the server/responder.
func acceptHandshake(
	pt *plainTransport, opts handshakeOpts,
) (*Transport, error) {
	state := &handshakeState{
		isInitiator: false,
		phase:       PhaseIntroduction,
	}

	// Step 1: Receive handshake request
	reqBytes, err := pt.conn.ReadBytes()
	if err != nil {
		return nil, fmt.Errorf("reading handshake request: %w", err)
	}

	var req pb.Handshake
	_, route, err := pt.deserialize(reqBytes, &req)
	if err != nil {
		return nil, fmt.Errorf("deserializing handshake request: %w", err)
	}
	if route != RouteRequestHandshake {
		return nil, fmt.Errorf(
			"%w: expected %s, got %s",
			ErrUnexpectedRoute, RouteRequestHandshake, route,
		)
	}
	state.phase = PhaseHandshakeRequested

	// Step 2: Encapsulate secret and prepare response
	secret, ct, err := exchange.EncapsulateMLKEM(req.GetKey())
	if err != nil {
		return nil, fmt.Errorf("encapsulating key: %w", err)
	}
	state.sharedSecret = secret
	state.remoteSalt = req.GetSalt()

	state.sessionSuffix = enigma.Text(sessionIDLength / 2)
	state.sessionPrefix = req.GetSessionKey()
	state.sessionID = state.sessionPrefix + state.sessionSuffix
	state.localSalt = randomBytes(saltSize)

	resp := &pb.Handshake{
		Key:        ct,
		Salt:       state.localSalt,
		SessionKey: state.sessionSuffix,
	}

	respBytes, _, err := pt.serialize(resp, RouteAcceptHandshake)
	if err != nil {
		return nil, fmt.Errorf("serializing handshake response: %w", err)
	}
	if err = pt.conn.WriteBytes(respBytes); err != nil {
		return nil, fmt.Errorf("writing handshake response: %w", err)
	}
	state.phase = PhaseHandshakeAccepted

	// Step 3: Create transport with encryption
	encoder, err := enigma.NewEnigma(
		secret, state.localSalt, []byte(state.sessionID+s2c),
	)
	if err != nil {
		return nil, fmt.Errorf("creating encrypter: %w", err)
	}
	decoder, err := enigma.NewEnigma(
		secret, state.remoteSalt, []byte(state.sessionID+c2s),
	)
	if err != nil {
		return nil, fmt.Errorf("creating decrypter: %w", err)
	}

	t := newTransport(pt, state.sessionID, encoder, decoder, opts.ratchetThreshold)
	t.SetInitiator(false)
	t.SetSecrets(secret, state.localSalt, state.remoteSalt)
	t.SetRemotePublicKey(pt.remote.Marshal())

	// Step 4: Challenge exchange (order reversed from initiator)
	if err := acceptChallenge(t, RouteSendChallenge); err != nil {
		return nil, fmt.Errorf("accepting challenge: %w", err)
	}
	t.SetPhase(PhaseChallengeSent)

	if err := sendChallenge(t, secret, []byte(state.sessionID+s2c)); err != nil {
		return nil, fmt.Errorf("sending challenge: %w", err)
	}
	t.SetPhase(PhaseChallengeVerified)

	// Step 5: Bootstrap double ratchet
	r, err := bootstrapDoubleRatchet(t, secret, t.sessionID, false)
	if err != nil {
		return nil, fmt.Errorf("bootstrap double ratchet: %w", err)
	}
	t.ratchet = r
	t.SetPhase(PhaseEstablished)

	return t, nil
}

// sendChallenge sends a challenge derived from the shared secret and expects
// the peer to echo it back for verification.
func sendChallenge(t *Transport, secret, info []byte) error {
	challenge, err := enigma.Derive(secret, nil, info, challengeSize)
	if err != nil {
		return fmt.Errorf("deriving a challenge: %w", err)
	}

	if _, err := t.Send(Bytes(challenge), RouteSendChallenge); err != nil {
		return fmt.Errorf("sending: %w", err)
	}

	r := Bytes(nil)
	_, route, err := t.ReceiveWithRoute(r)
	if err != nil {
		return fmt.Errorf("receiving: %w", err)
	}
	if route != RouteVerifyChallenge {
		return fmt.Errorf(
			"%w: expected %s, got %s",
			ErrUnexpectedRoute, RouteVerifyChallenge, route,
		)
	}
	if subtle.ConstantTimeCompare(r.Value, challenge) != 1 {
		return ErrVerificationFailed
	}

	return nil
}

// acceptChallenge receives a challenge and echoes it back for verification.
func acceptChallenge(t *Transport, expectedRoute Route) error {
	r := Bytes(nil)
	_, route, err := t.ReceiveWithRoute(r)
	if err != nil {
		return fmt.Errorf("receiving: %w", err)
	}
	if route != expectedRoute {
		return fmt.Errorf(
			"%w: expected %s, got %s",
			ErrUnexpectedRoute, expectedRoute, route,
		)
	}

	if _, err := t.Send(Bytes(r.Value), RouteVerifyChallenge); err != nil {
		return fmt.Errorf("sending: %w", err)
	}

	return nil
}

// bootstrapDoubleRatchet exchanges X25519 public keys over the current
// enigma-authenticated channel and returns an initialized ratchet.
func bootstrapDoubleRatchet(
	t *Transport, secret []byte, sessionID string, initiator bool,
) (*ratchet.Ratchet, error) {
	r, err := ratchet.NewFromSecret(secret)
	if err != nil {
		return nil, fmt.Errorf("creating new ratchet: %w", err)
	}

	theirBlob := Bytes(nil)
	if initiator {
		if _, err := t.Send(
			Bytes(r.OurPublic()), RouteInitializeDoubleRatchet,
		); err != nil {
			return nil, fmt.Errorf("sending our public key: %w", err)
		}

		md, route, err := t.ReceiveWithRoute(theirBlob)
		if err != nil {
			return nil, fmt.Errorf("receiving their public key: %w", err)
		}
		if route != RouteConfirmDoubleRatchet {
			return nil, fmt.Errorf(
				"%w: expected %s, got %s",
				ErrUnexpectedRoute, RouteConfirmDoubleRatchet, route,
			)
		}
		_ = md
	} else {
		md, route, err := t.ReceiveWithRoute(theirBlob)
		if err != nil {
			return nil, fmt.Errorf("receiving their public key: %w", err)
		}
		if route != RouteInitializeDoubleRatchet {
			return nil, fmt.Errorf(
				"%w: expected %s, got %s",
				ErrUnexpectedRoute, RouteInitializeDoubleRatchet, route,
			)
		}
		_ = md

		if _, err := t.Send(
			Bytes(r.OurPublic()), RouteConfirmDoubleRatchet,
		); err != nil {
			return nil, fmt.Errorf("sending our public key: %w", err)
		}
	}

	if err := r.SetTheirPublic(theirBlob.GetValue(), sessionID); err != nil {
		return nil, fmt.Errorf("setting their public key: %w", err)
	}

	t.SetPhase(PhaseRatchetInitialized)
	return r, nil
}

// HandleReconnect processes a reconnection request and attempts to resume
// an existing session.
func HandleReconnect(
	t *Transport, req *pb.ReconnectRequest,
) (*pb.ReconnectResponse, error) {
	state := t.State()

	// Validate session ID
	if req.GetSessionId() != state.SessionID {
		return &pb.ReconnectResponse{
			Accepted:     false,
			ErrorMessage: "session ID mismatch",
		}, nil
	}

	// Check if we can resume from the requested phase
	lastPhase := PhaseFromProto(req.GetLastPhase())
	if lastPhase > state.Phase {
		return &pb.ReconnectResponse{
			Accepted:     false,
			ErrorMessage: "cannot resume from future phase",
		}, nil
	}

	// Determine the phase to resume from
	resumePhase := lastPhase
	if state.Phase > lastPhase {
		resumePhase = lastPhase
	}

	return &pb.ReconnectResponse{
		Accepted:        true,
		ResumeFromPhase: resumePhase.ToProto(),
	}, nil
}

// RequestReconnect sends a reconnection request to resume an existing session.
func RequestReconnect(t *Transport) (*pb.ReconnectResponse, error) {
	state := t.State()

	req := &pb.ReconnectRequest{
		SessionId:        state.SessionID,
		LastPhase:        state.Phase.ToProto(),
		LastSendSequence: state.SendSequence,
		LastRecvSequence: state.RecvSequence,
	}

	if _, err := t.Send(req, RouteReconnect); err != nil {
		return nil, fmt.Errorf("sending reconnect request: %w", err)
	}

	var resp pb.ReconnectResponse
	_, route, err := t.ReceiveWithRoute(&resp)
	if err != nil {
		return nil, fmt.Errorf("receiving reconnect response: %w", err)
	}
	if route != RouteReconnect {
		return nil, fmt.Errorf(
			"%w: expected %s, got %s",
			ErrUnexpectedRoute, RouteReconnect, route,
		)
	}

	return &resp, nil
}

func randomBytes(l int) []byte {
	buf := make([]byte, l)
	_, _ = rand.Read(buf)
	return buf
}

func padding(maxSize int) []byte {
	return randomBytes(mathrand.IntN(maxSize))
}
