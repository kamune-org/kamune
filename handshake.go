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
	"github.com/kamune-org/kamune/pkg/exchange"
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
	timeout        time.Duration
}

// requestHandshake initiates a handshake as the client/initiator.
//
// Protocol flow (initiator perspective):
//  1. Generate an MLKEM keypair and send the public key to the responder.
//  2. Receive the responder's encapsulated key (enc) and session info.
//  3. Perform KEM decapsulation and derive the shared key (secret).
//  4. Create two bidirectional symmetric encrypted transports - one for each
//     direction (client-to-server and server-to-client)
//  5. Perform a challenge-response to verify the shared secret.
func requestHandshake(
	pt *underlyingTransport, opts handshakeOpts,
) (*Transport, error) {
	// Step 1: Generate MLKEM keys and send handshake request
	ml, err := exchange.NewMLKEM()
	if err != nil {
		return nil, fmt.Errorf("creating MLKEM keys: %w", err)
	}
	localSalt := randomBytes(saltSize)
	sessionPrefix := enigma.Text(sessionIDLength / 2)

	req := &pb.Handshake{
		Key:        ml.PublicKey.Bytes(),
		Salt:       localSalt,
		SessionKey: sessionPrefix,
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

	remoteSalt := resp.GetSalt()
	sessionSuffix := resp.GetSessionKey()
	sessionID := sessionPrefix + sessionSuffix

	// Bind later challenge material to the semantic handshake transcript
	// (inner pb.Handshake fields only).
	transcriptHash := handshakeTranscriptHash(req, &resp)

	// Step 3: Decapsulate shared secret
	secret, err := ml.Decapsulate(resp.GetKey())
	if err != nil {
		return nil, fmt.Errorf("decapsulating secret: %w", err)
	}
	// Step 4: Create transport with encryption
	encoder, err := enigma.NewEnigma(
		secret, localSalt, []byte(sessionID+handshakeC2SInfo),
	)
	if err != nil {
		return nil, fmt.Errorf("creating encrypter: %w", err)
	}
	decoder, err := enigma.NewEnigma(
		secret, remoteSalt, []byte(sessionID+handshakeS2CInfo),
	)
	if err != nil {
		return nil, fmt.Errorf("creating decrypter: %w", err)
	}

	t := newTransport(pt, sessionID, encoder, decoder)
	t.SetInitiator(true)
	t.SetSecrets(secret, localSalt, remoteSalt)
	t.SetRemotePublicKey(pt.remote.Marshal())

	// Step 5: Challenge exchange (bound to handshake transcript)
	err = sendChallenge(
		t,
		secret,
		deriveChallengeInfo(sessionID, handshakeC2SInfo, transcriptHash),
	)
	if err != nil {
		return nil, fmt.Errorf("sending challenge: %w", err)
	}

	if err := acceptChallenge(t, RouteSendChallenge); err != nil {
		return nil, fmt.Errorf("accepting challenge: %w", err)
	}

	return t, nil
}

// acceptHandshake accepts an incoming handshake as the server/responder.
//
// Protocol flow (responder perspective):
//  1. Receive the initiator's MLKEM public key.
//  2. Perform KEM encapsulation and derive the shared key (secret). The
//     ciphertext value is sent back.
//  3. Create two bidirectional symetric encrypted transports
//  4. Perform challenge-response.
func acceptHandshake(
	pt *underlyingTransport, opts handshakeOpts,
) (*Transport, error) {
	// Step 1: Receive handshake request
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

	// Validate untrusted initiator-provided fields early.
	if err := validateHandshakeFields(req.GetSalt(), req.GetSessionKey()); err != nil {
		return nil, fmt.Errorf("invalid remote handshake fields: %w", err)
	}

	// Step 2: Encapsulate secret and prepare response
	secret, ct, err := exchange.EncapsulateMLKEM(req.GetKey())
	if err != nil {
		return nil, fmt.Errorf("encapsulating key: %w", err)
	}

	remoteSalt := req.GetSalt()
	sessionSuffix := enigma.Text(sessionIDLength / 2)
	sessionPrefix := req.GetSessionKey()
	sessionID := sessionPrefix + sessionSuffix
	localSalt := randomBytes(saltSize)

	// Send the encapsulated key (ct) and session info back to the initiator
	resp := &pb.Handshake{
		Key:        ct,
		Salt:       localSalt,
		SessionKey: sessionSuffix,
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

	// Bind later challenge material to the semantic handshake transcript
	// (inner pb.Handshake fields only).
	transcriptHash := handshakeTranscriptHash(&req, resp)

	// Step 3: Create transport with encryption
	encoder, err := enigma.NewEnigma(
		secret, localSalt, []byte(sessionID+handshakeS2CInfo),
	)
	if err != nil {
		return nil, fmt.Errorf("creating encrypter: %w", err)
	}
	decoder, err := enigma.NewEnigma(
		secret, remoteSalt, []byte(sessionID+handshakeC2SInfo),
	)
	if err != nil {
		return nil, fmt.Errorf("creating decrypter: %w", err)
	}

	t := newTransport(pt, sessionID, encoder, decoder)
	t.SetInitiator(false)
	t.SetSecrets(secret, localSalt, remoteSalt)
	t.SetRemotePublicKey(pt.remote.Marshal())

	// Step 4: Challenge exchange (bound to handshake transcript). Responder
	// accepts initiator's challenge, then sends its own and verifies echo.
	if err := acceptChallenge(t, RouteSendChallenge); err != nil {
		return nil, fmt.Errorf("accepting challenge: %w", err)
	}

	if err := sendChallenge(
		t,
		secret,
		deriveChallengeInfo(sessionID, handshakeS2CInfo, transcriptHash),
	); err != nil {
		return nil, fmt.Errorf("sending challenge: %w", err)
	}

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
//   - initiator: MLKEM public key, salt, session prefix
//   - responder: KEM enc, salt, session suffix
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
