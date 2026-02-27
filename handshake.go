package kamune

import (
	"crypto/hpke"
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	mathrand "math/rand/v2"

	"github.com/kamune-org/kamune/internal/box/pb"
	"github.com/kamune-org/kamune/internal/enigma"
)

// HPKE ciphersuite components used for key establishment.
// MLKEM768-X25519 provides hybrid post-quantum + classical security.
// HKDF-SHA256 is the KDF and ChaCha20Poly1305 is the AEAD (used only
// within the HPKE key schedule; actual transport encryption uses the
// exported keys with XChaCha20-Poly1305 via enigma).
var (
	hpkeKEM  = hpke.MLKEM768X25519
	hpkeKDF  = hpke.HKDFSHA256
	hpkeAEAD = hpke.ChaCha20Poly1305
)

const (
	// exportKeySize is the size of symmetric keys exported from the HPKE
	// context for bidirectional transport encryption.
	exportKeySize = 32
)

type handshakeOpts struct {
	remoteVerifier RemoteVerifier
}

// handshakeState tracks the state of an ongoing handshake for potential
// resumption after connection reset.
type handshakeState struct {
	sessionID     string
	sessionPrefix string
	sessionSuffix string
	localSalt     []byte
	remoteSalt    []byte
	sharedSecret  []byte
	phase         SessionPhase
	isInitiator   bool
}

// requestHandshake initiates a handshake as the client/initiator.
//
// Protocol flow (initiator perspective):
//  1. Generate an HPKE keypair and send the public key to the responder.
//  2. Receive the responder's encapsulated key (enc) and session info.
//  3. Create an HPKE Recipient context using the enc value, which
//     performs KEM decapsulation and derives the shared key schedule.
//  4. Export two symmetric keys from the HPKE context — one for each
//     direction (client-to-server and server-to-client).
//  5. Create the encrypted transport using those keys.
//  6. Perform a challenge-response to verify the shared secret.
func requestHandshake(
	pt *plainTransport, opts handshakeOpts,
) (*Transport, error) {
	state := &handshakeState{
		isInitiator: true,
		phase:       PhaseIntroduction,
	}

	kem := hpkeKEM()

	// Step 1: Generate HPKE keypair and send handshake request
	privKey, err := kem.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("generating HPKE key: %w", err)
	}

	state.localSalt = randomBytes(saltSize)
	state.sessionPrefix = enigma.Text(sessionIDLength / 2)

	req := &pb.Handshake{
		Key:        privKey.PublicKey().Bytes(),
		Salt:       state.localSalt,
		SessionKey: state.sessionPrefix,
	}

	reqBytes, _, err := pt.serialize(req, RouteRequestHandshake, 0)
	if err != nil {
		return nil, fmt.Errorf("serializing handshake request: %w", err)
	}
	if err = pt.conn.WriteBytes(reqBytes); err != nil {
		return nil, fmt.Errorf("writing handshake request: %w", err)
	}
	state.phase = PhaseHandshakeRequested

	// Step 2: Receive handshake response containing the encapsulated key
	respBytes, err := pt.conn.ReadBytes()
	if err != nil {
		return nil, fmt.Errorf("reading handshake response: %w", err)
	}

	var resp pb.Handshake
	_, route, _, err := pt.deserialize(respBytes, &resp)
	if err != nil {
		return nil, fmt.Errorf("deserializing handshake response: %w", err)
	}
	if route != RouteAcceptHandshake {
		return nil, fmt.Errorf(
			"%w: expected %s, got %s",
			ErrUnexpectedRoute, RouteAcceptHandshake, route,
		)
	}

	state.remoteSalt = resp.GetSalt()
	state.sessionSuffix = resp.GetSessionKey()
	state.sessionID = state.sessionPrefix + state.sessionSuffix
	state.phase = PhaseHandshakeAccepted

	// Step 3: Create HPKE Recipient context — this performs KEM
	// decapsulation and derives the shared key schedule in one step,
	// replacing the previous manual Decapsulate + HKDF + NewEnigma chain.
	kdf := hpkeKDF()
	aead := hpkeAEAD()
	recipient, err := hpke.NewRecipient(
		resp.GetKey(), privKey, kdf, aead, []byte(state.sessionID),
	)
	if err != nil {
		return nil, fmt.Errorf("creating HPKE recipient context: %w", err)
	}

	// Step 4: Export bidirectional symmetric keys from the HPKE context.
	// The HPKE Export function derives independent keys using distinct
	// exporter contexts, ensuring each direction has its own key material.
	c2sKey, err := recipient.Export(state.sessionID+c2s, exportKeySize)
	if err != nil {
		return nil, fmt.Errorf("exporting c2s key: %w", err)
	}
	s2cKey, err := recipient.Export(state.sessionID+s2c, exportKeySize)
	if err != nil {
		return nil, fmt.Errorf("exporting s2c key: %w", err)
	}

	// Derive a shared secret for challenge verification and session
	// resumption. This is a separate export with its own context.
	sharedSecret, err := recipient.Export(state.sessionID+"-shared", exportKeySize)
	if err != nil {
		return nil, fmt.Errorf("exporting shared secret: %w", err)
	}
	state.sharedSecret = sharedSecret

	// Step 5: Create transport with encryption using exported keys.
	// The initiator encrypts with c2s and decrypts with s2c.
	encoder, err := enigma.NewEnigma(
		c2sKey, state.localSalt, []byte(state.sessionID+c2s),
	)
	if err != nil {
		return nil, fmt.Errorf("creating encrypter: %w", err)
	}
	decoder, err := enigma.NewEnigma(
		s2cKey, state.remoteSalt, []byte(state.sessionID+s2c),
	)
	if err != nil {
		return nil, fmt.Errorf("creating decrypter: %w", err)
	}

	t := newTransport(pt, state.sessionID, encoder, decoder)
	t.SetInitiator(true)
	t.SetSecrets(sharedSecret, state.localSalt, state.remoteSalt)
	t.SetRemotePublicKey(pt.remote.Marshal())

	// Step 6: Challenge exchange
	err = sendChallenge(t, sharedSecret, []byte(state.sessionID+c2s))
	if err != nil {
		return nil, fmt.Errorf("sending challenge: %w", err)
	}
	t.SetPhase(PhaseChallengeSent)

	if err := acceptChallenge(t, RouteSendChallenge); err != nil {
		return nil, fmt.Errorf("accepting challenge: %w", err)
	}
	t.SetPhase(PhaseChallengeVerified)

	// Step 7: Session established
	t.SetPhase(PhaseEstablished)

	return t, nil
}

// acceptHandshake accepts an incoming handshake as the server/responder.
//
// Protocol flow (responder perspective):
//  1. Receive the initiator's HPKE public key.
//  2. Create an HPKE Sender context, which performs KEM encapsulation and
//     derives the shared key schedule. The enc value is sent back.
//  3. Export bidirectional symmetric keys from the HPKE context.
//  4. Create the encrypted transport and perform challenge-response.
func acceptHandshake(
	pt *plainTransport, opts handshakeOpts,
) (*Transport, error) {
	state := &handshakeState{
		isInitiator: false,
		phase:       PhaseIntroduction,
	}

	kem := hpkeKEM()

	// Step 1: Receive handshake request with the initiator's public key
	reqBytes, err := pt.conn.ReadBytes()
	if err != nil {
		return nil, fmt.Errorf("reading handshake request: %w", err)
	}

	var req pb.Handshake
	_, route, _, err := pt.deserialize(reqBytes, &req)
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

	// Step 2: Parse the initiator's public key and create an HPKE Sender
	// context. This performs KEM encapsulation and derives the shared key
	// schedule, replacing the previous EncapsulateMLKEM call.
	remotePubKey, err := kem.NewPublicKey(req.GetKey())
	if err != nil {
		return nil, fmt.Errorf("parsing remote HPKE public key: %w", err)
	}

	kdf := hpkeKDF()
	aead := hpkeAEAD()

	state.remoteSalt = req.GetSalt()
	state.sessionSuffix = enigma.Text(sessionIDLength / 2)
	state.sessionPrefix = req.GetSessionKey()
	state.sessionID = state.sessionPrefix + state.sessionSuffix
	state.localSalt = randomBytes(saltSize)

	enc, sender, err := hpke.NewSender(
		remotePubKey, kdf, aead, []byte(state.sessionID),
	)
	if err != nil {
		return nil, fmt.Errorf("creating HPKE sender context: %w", err)
	}

	// Send the encapsulated key (enc) and session info back to the initiator
	resp := &pb.Handshake{
		Key:        enc,
		Salt:       state.localSalt,
		SessionKey: state.sessionSuffix,
	}

	respBytes, _, err := pt.serialize(resp, RouteAcceptHandshake, 0)
	if err != nil {
		return nil, fmt.Errorf("serializing handshake response: %w", err)
	}
	if err = pt.conn.WriteBytes(respBytes); err != nil {
		return nil, fmt.Errorf("writing handshake response: %w", err)
	}
	state.phase = PhaseHandshakeAccepted

	// Step 3: Export bidirectional symmetric keys from the HPKE context.
	// Both sides derive the same keys because the HPKE key schedule is
	// deterministic given the same shared secret and info.
	c2sKey, err := sender.Export(state.sessionID+c2s, exportKeySize)
	if err != nil {
		return nil, fmt.Errorf("exporting c2s key: %w", err)
	}
	s2cKey, err := sender.Export(state.sessionID+s2c, exportKeySize)
	if err != nil {
		return nil, fmt.Errorf("exporting s2c key: %w", err)
	}

	// Derive a shared secret for challenge verification and resumption.
	sharedSecret, err := sender.Export(state.sessionID+"-shared", exportKeySize)
	if err != nil {
		return nil, fmt.Errorf("exporting shared secret: %w", err)
	}
	state.sharedSecret = sharedSecret

	// Step 4: Create transport with encryption using exported keys.
	// The responder encrypts with s2c and decrypts with c2s.
	encoder, err := enigma.NewEnigma(
		s2cKey, state.localSalt, []byte(state.sessionID+s2c),
	)
	if err != nil {
		return nil, fmt.Errorf("creating encrypter: %w", err)
	}
	decoder, err := enigma.NewEnigma(
		c2sKey, state.remoteSalt, []byte(state.sessionID+c2s),
	)
	if err != nil {
		return nil, fmt.Errorf("creating decrypter: %w", err)
	}

	t := newTransport(pt, state.sessionID, encoder, decoder)
	t.SetInitiator(false)
	t.SetSecrets(sharedSecret, state.localSalt, state.remoteSalt)
	t.SetRemotePublicKey(pt.remote.Marshal())

	// Step 5: Challenge exchange (responder must first accept initiator's
	// challenge, then send its own and verify the echo).
	if err := acceptChallenge(t, RouteSendChallenge); err != nil {
		return nil, fmt.Errorf("accepting challenge: %w", err)
	}
	t.SetPhase(PhaseChallengeVerified)

	if err := sendChallenge(t, sharedSecret, []byte(state.sessionID+s2c)); err != nil {
		return nil, fmt.Errorf("sending challenge: %w", err)
	}
	t.SetPhase(PhaseChallengeSent)

	// Step 6: Session established
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
