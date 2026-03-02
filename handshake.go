package kamune

import (
	"crypto/hpke"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	mathrand "math/rand/v2"
	"time"

	"github.com/kamune-org/kamune/internal/box/pb"
	"github.com/kamune-org/kamune/internal/enigma"
)

// HPKE ciphersuite components used for key establishment.
// MLKEM768-X25519 provides hybrid post-quantum + classical security.
// HKDF-SHA512 is the KDF and ChaCha20Poly1305 is the AEAD (used only
// within the HPKE key schedule; actual transport encryption uses the
// exported keys with XChaCha20-Poly1305 via enigma).
var (
	hpkeKEM  = hpke.MLKEM768X25519
	hpkeKDF  = hpke.HKDFSHA512
	hpkeAEAD = hpke.ChaCha20Poly1305
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
	// Bound the handshake to avoid indefinite blocking.
	// SetDeadline is part of net.Conn, embedded in Conn.
	_ = pt.conn.SetDeadline(time.Now().Add(handshakeTimeout))
	defer func() { _ = pt.conn.SetDeadline(time.Time{}) }()

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

	// Validate our own outbound fields (defense-in-depth; keeps invariants).
	if err := validateHandshakeFields(req.GetSalt(), req.GetSessionKey()); err != nil {
		return nil, fmt.Errorf("invalid local handshake fields: %w", err)
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

	// Validate untrusted responder-provided fields.
	if err := validateHandshakeFields(resp.GetSalt(), resp.GetSessionKey()); err != nil {
		return nil, fmt.Errorf("invalid remote handshake fields: %w", err)
	}

	state.remoteSalt = resp.GetSalt()
	state.sessionSuffix = resp.GetSessionKey()
	state.sessionID = state.sessionPrefix + state.sessionSuffix
	state.phase = PhaseHandshakeAccepted

	// Bind later challenge material to the semantic handshake transcript
	// (inner pb.Handshake fields only).
	transcriptHash := handshakeTranscriptHash(req, &resp)

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

	// Step 6: Challenge exchange (bound to handshake transcript)
	err = sendChallenge(
		t,
		sharedSecret,
		deriveChallengeInfo(state.sessionID, c2s, transcriptHash),
	)
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
	// Bound the handshake to avoid indefinite blocking.
	_ = pt.conn.SetDeadline(time.Now().Add(handshakeTimeout))
	defer func() { _ = pt.conn.SetDeadline(time.Time{}) }()

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

	// Validate untrusted initiator-provided fields early.
	if err := validateHandshakeFields(req.GetSalt(), req.GetSessionKey()); err != nil {
		return nil, fmt.Errorf("invalid remote handshake fields: %w", err)
	}

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

	// Validate our outbound fields (defense-in-depth; keeps invariants).
	if err := validateHandshakeFields(resp.GetSalt(), resp.GetSessionKey()); err != nil {
		return nil, fmt.Errorf("invalid local handshake fields: %w", err)
	}

	respBytes, _, err := pt.serialize(resp, RouteAcceptHandshake, 0)
	if err != nil {
		return nil, fmt.Errorf("serializing handshake response: %w", err)
	}
	if err = pt.conn.WriteBytes(respBytes); err != nil {
		return nil, fmt.Errorf("writing handshake response: %w", err)
	}
	state.phase = PhaseHandshakeAccepted

	// Bind later challenge material to the semantic handshake transcript
	// (inner pb.Handshake fields only).
	transcriptHash := handshakeTranscriptHash(&req, resp)

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

	// Step 5: Challenge exchange (bound to handshake transcript).
	// Responder accepts initiator's challenge, then sends its own and verifies echo.
	if err := acceptChallenge(t, RouteSendChallenge); err != nil {
		return nil, fmt.Errorf("accepting challenge: %w", err)
	}
	t.SetPhase(PhaseChallengeVerified)

	if err := sendChallenge(
		t,
		sharedSecret,
		deriveChallengeInfo(state.sessionID, s2c, transcriptHash),
	); err != nil {
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

// validateHandshakeFields enforces strict size checks for untrusted handshake
// inputs to prevent malformed session IDs, message bloat, and weird HPKE inputs.
func validateHandshakeFields(salt []byte, sessionKey string) error {
	if len(salt) != saltSize {
		return fmt.Errorf("invalid salt length: got %d, want %d", len(salt), saltSize)
	}
	if len(sessionKey) != sessionIDLength/2 {
		return fmt.Errorf(
			"invalid session key length: got %d, want %d",
			len(sessionKey), sessionIDLength/2,
		)
	}
	return nil
}

// handshakeTranscriptHash binds later challenge material to the semantic
// handshake inputs that matter for key agreement.
//
// We intentionally avoid hashing the full signed envelope bytes (which include
// padding/metadata) and instead bind to the inner pb.Handshake fields that
// influence session establishment:
//
//   - initiator: HPKE public key, salt, session prefix
//   - responder: HPKE enc, salt, session suffix
//
// It returns a fixed-size array to avoid returning a heap slice.
func handshakeTranscriptHash(req *pb.Handshake, resp *pb.Handshake) [32]byte {
	h := sha256.New()
	var b [4]byte

	// Domain separation label to avoid cross-protocol collisions.
	_, _ = h.Write([]byte("kamune/handshake/v1"))

	// Initiator fields
	binary.BigEndian.PutUint32(b[:], uint32(len(req.GetKey())))
	_, _ = h.Write(b[:])
	_, _ = h.Write(req.GetKey())

	binary.BigEndian.PutUint32(b[:], uint32(len(req.GetSalt())))
	_, _ = h.Write(b[:])
	_, _ = h.Write(req.GetSalt())

	// Session prefix (string)
	binary.BigEndian.PutUint32(b[:], uint32(len(req.GetSessionKey())))
	_, _ = h.Write(b[:])
	_, _ = h.Write([]byte(req.GetSessionKey()))

	// Responder fields
	binary.BigEndian.PutUint32(b[:], uint32(len(resp.GetKey())))
	_, _ = h.Write(b[:])
	_, _ = h.Write(resp.GetKey())

	binary.BigEndian.PutUint32(b[:], uint32(len(resp.GetSalt())))
	_, _ = h.Write(b[:])
	_, _ = h.Write(resp.GetSalt())

	// Session suffix (string)
	binary.BigEndian.PutUint32(b[:], uint32(len(resp.GetSessionKey())))
	_, _ = h.Write(b[:])
	_, _ = h.Write([]byte(resp.GetSessionKey()))

	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// deriveChallengeInfo returns challenge "info" bound to session, direction, and
// the handshake transcript hash (prevents replay across different handshakes
// even if a shared secret were ever reused).
func deriveChallengeInfo(sessionID, direction string, transcriptHash [32]byte) []byte {
	// Keep it simple and deterministic.
	// The transcript hash ensures the challenge is bound to the negotiated
	// handshake bytes, not just the exported secret.
	buf := make([]byte, 0, len(sessionID)+1+len(direction)+1+len(transcriptHash[:]))
	buf = append(buf, sessionID...)
	buf = append(buf, '|')
	buf = append(buf, direction...)
	buf = append(buf, '|')
	buf = append(buf, transcriptHash[:]...)
	return buf
}

func randomBytes(l int) []byte {
	buf := make([]byte, l)
	_, _ = rand.Read(buf)
	return buf
}

func padding(maxSize int) []byte {
	return randomBytes(mathrand.IntN(maxSize))
}
