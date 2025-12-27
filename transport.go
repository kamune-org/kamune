package kamune

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"sync"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/kamune-org/kamune/internal/box/pb"
	"github.com/kamune-org/kamune/internal/enigma"
	"github.com/kamune-org/kamune/pkg/attest"
	"github.com/kamune-org/kamune/pkg/ratchet"
)

var (
	ErrConnClosed         = errors.New("connection has been closed")
	ErrInvalidSignature   = errors.New("invalid signature")
	ErrVerificationFailed = errors.New("verification failed")
	ErrMessageTooLarge    = errors.New("message is too large")
	ErrOutOfSync          = errors.New("peers are out of sync")
	ErrUnexpectedRoute    = errors.New("unexpected route received")
	ErrInvalidRoute       = errors.New("invalid route")
	ErrSessionNotFound    = errors.New("session not found")
	ErrSessionExpired     = errors.New("session has expired")
)

// SessionPhase represents the current phase of a session.
type SessionPhase int

const (
	PhaseInvalid SessionPhase = iota
	PhaseIntroduction
	PhaseHandshakeRequested
	PhaseHandshakeAccepted
	PhaseChallengeSent
	PhaseChallengeVerified
	PhaseRatchetInitialized
	PhaseEstablished
	PhaseClosed
)

// String returns the string representation of the session phase.
func (p SessionPhase) String() string {
	switch p {
	case PhaseIntroduction:
		return "Introduction"
	case PhaseHandshakeRequested:
		return "HandshakeRequested"
	case PhaseHandshakeAccepted:
		return "HandshakeAccepted"
	case PhaseChallengeSent:
		return "ChallengeSent"
	case PhaseChallengeVerified:
		return "ChallengeVerified"
	case PhaseRatchetInitialized:
		return "RatchetInitialized"
	case PhaseEstablished:
		return "Established"
	case PhaseClosed:
		return "Closed"
	default:
		return "Invalid"
	}
}

// ToProto converts the SessionPhase to its protobuf enum representation.
func (p SessionPhase) ToProto() pb.SessionPhase {
	switch p {
	case PhaseIntroduction:
		return pb.SessionPhase_PHASE_INTRODUCTION
	case PhaseHandshakeRequested:
		return pb.SessionPhase_PHASE_HANDSHAKE_REQUESTED
	case PhaseHandshakeAccepted:
		return pb.SessionPhase_PHASE_HANDSHAKE_ACCEPTED
	case PhaseChallengeSent:
		return pb.SessionPhase_PHASE_CHALLENGE_SENT
	case PhaseChallengeVerified:
		return pb.SessionPhase_PHASE_CHALLENGE_VERIFIED
	case PhaseRatchetInitialized:
		return pb.SessionPhase_PHASE_RATCHET_INITIALIZED
	case PhaseEstablished:
		return pb.SessionPhase_PHASE_ESTABLISHED
	case PhaseClosed:
		return pb.SessionPhase_PHASE_CLOSED
	default:
		return pb.SessionPhase_PHASE_INVALID
	}
}

// PhaseFromProto converts a protobuf SessionPhase enum to the local type.
func PhaseFromProto(p pb.SessionPhase) SessionPhase {
	switch p {
	case pb.SessionPhase_PHASE_INTRODUCTION:
		return PhaseIntroduction
	case pb.SessionPhase_PHASE_HANDSHAKE_REQUESTED:
		return PhaseHandshakeRequested
	case pb.SessionPhase_PHASE_HANDSHAKE_ACCEPTED:
		return PhaseHandshakeAccepted
	case pb.SessionPhase_PHASE_CHALLENGE_SENT:
		return PhaseChallengeSent
	case pb.SessionPhase_PHASE_CHALLENGE_VERIFIED:
		return PhaseChallengeVerified
	case pb.SessionPhase_PHASE_RATCHET_INITIALIZED:
		return PhaseRatchetInitialized
	case pb.SessionPhase_PHASE_ESTABLISHED:
		return PhaseEstablished
	case pb.SessionPhase_PHASE_CLOSED:
		return PhaseClosed
	default:
		return PhaseInvalid
	}
}

// plainTransport handles unencrypted message serialization and deserialization.
type plainTransport struct {
	conn    Conn
	attest  attest.Attester
	remote  attest.PublicKey
	id      attest.Identifier
	storage *Storage
}

func newPlainTransport(
	conn Conn,
	remote attest.PublicKey,
	attest attest.Attester,
	storage *Storage,
) *plainTransport {
	return &plainTransport{
		conn:    conn,
		remote:  remote,
		attest:  attest,
		storage: storage,
		id:      storage.algorithm.Identitfier(),
	}
}

func (pt *plainTransport) serialize(
	msg Transferable, route Route,
) ([]byte, *Metadata, error) {
	message, err := proto.Marshal(msg)
	if err != nil {
		return nil, nil, fmt.Errorf("marshalling message: %w", err)
	}
	sig, err := pt.attest.Sign(message)
	if err != nil {
		return nil, nil, fmt.Errorf("signing: %w", err)
	}

	md := &pb.Metadata{
		ID:        rand.Text(),
		Timestamp: timestamppb.Now(),
		Sequence:  uint64(route),
	}
	st := &pb.SignedTransport{
		Data:      message,
		Signature: sig,
		Metadata:  md,
		Padding:   padding(maxPadding),
		Route:     route.ToProto(),
	}
	payload, err := proto.Marshal(st)
	if err != nil {
		return nil, nil, fmt.Errorf("marshalling transport: %w", err)
	}

	return payload, &Metadata{md}, nil
}

func (pt *plainTransport) deserialize(
	payload []byte, dst Transferable,
) (*Metadata, Route, error) {
	var st pb.SignedTransport
	if err := proto.Unmarshal(payload, &st); err != nil {
		return nil, RouteInvalid, fmt.Errorf("unmarshalling transport: %w", err)
	}

	msg := st.GetData()
	if ok := pt.id.Verify(pt.remote, msg, st.Signature); !ok {
		return nil, RouteInvalid, ErrInvalidSignature
	}
	if err := proto.Unmarshal(msg, dst); err != nil {
		return nil, RouteInvalid, fmt.Errorf("unmarshalling message: %w", err)
	}

	route := RouteFromProto(st.GetRoute())
	return &Metadata{st.GetMetadata()}, route, nil
}

// SessionState holds the current state of a session for potential resumption.
type SessionState struct {
	SessionID       string
	SharedSecret    []byte
	LocalSalt       []byte
	RemoteSalt      []byte
	RatchetState    []byte
	RemotePublicKey []byte
	Phase           SessionPhase
	SendSequence    uint64
	RecvSequence    uint64
	IsInitiator     bool
}

// Transport handles encrypted message exchange with route-based dispatch.
type Transport struct {
	encoder *enigma.Enigma
	decoder *enigma.Enigma
	ratchet *ratchet.Ratchet
	mu      *sync.Mutex
	*plainTransport
	sessionID        string
	sharedSecret     []byte
	remotePublicKey  []byte
	remoteSalt       []byte
	localSalt        []byte
	phase            SessionPhase
	recvSequence     uint64
	sendSequence     uint64
	ratchetThreshold uint64
	isInitiator      bool
}

func newTransport(
	pt *plainTransport,
	sessionID string,
	encoder, decoder *enigma.Enigma,
	ratchetThreshold uint64,
) *Transport {
	return &Transport{
		plainTransport:   pt,
		sessionID:        sessionID,
		encoder:          encoder,
		decoder:          decoder,
		mu:               &sync.Mutex{},
		ratchetThreshold: ratchetThreshold,
		phase:            PhaseHandshakeAccepted,
	}
}

// Receive reads and decrypts the next message from the connection.
// It returns the metadata, the route of the received message, and any error.
func (t *Transport) Receive(dst Transferable) (*Metadata, error) {
	md, _, err := t.ReceiveWithRoute(dst)
	return md, err
}

// ReceiveWithRoute reads and decrypts the next message, returning both
// the metadata and the route of the received message.
func (t *Transport) ReceiveWithRoute(dst Transferable) (*Metadata, Route, error) {
	payload, err := t.conn.ReadBytes()
	switch {
	case err == nil: // continue
	case errors.Is(err, io.EOF):
		return nil, RouteInvalid, ErrConnClosed
	default:
		return nil, RouteInvalid, fmt.Errorf("reading payload: %w", err)
	}

	decrypted, err := t.decryptPayload(payload)
	if err != nil {
		return nil, RouteInvalid, fmt.Errorf("decrypting payload: %w", err)
	}

	metadata, route, err := t.deserialize(decrypted, dst)
	if err != nil {
		return nil, RouteInvalid, fmt.Errorf("deserializing: %w", err)
	}

	// Validate that metadata and transport route agree (defense-in-depth).
	// We use Metadata.Sequence to carry the Route for logging/debugging.
	if metadata != nil && metadata.pb != nil {
		if mdRoute := Route(metadata.pb.Sequence); mdRoute != RouteInvalid && mdRoute != route {
			return nil, RouteInvalid, fmt.Errorf("%w: metadata route %s does not match transport route %s", ErrUnexpectedRoute, mdRoute, route)
		}
	}

	t.mu.Lock()
	t.recvSequence++
	t.mu.Unlock()

	return metadata, route, nil
}

// ReceiveExpecting reads a message and validates that it matches the expected route.
func (t *Transport) ReceiveExpecting(
	dst Transferable, expected Route,
) (*Metadata, error) {
	md, route, err := t.ReceiveWithRoute(dst)
	if err != nil {
		return nil, err
	}
	if route != expected {
		return nil, fmt.Errorf(
			"%w: expected %s, got %s",
			ErrUnexpectedRoute, expected, route,
		)
	}
	return md, nil
}

// Send encrypts and sends a message with the specified route.
func (t *Transport) Send(message Transferable, route Route) (*Metadata, error) {
	if !route.IsValid() {
		return nil, fmt.Errorf("%w: %s", ErrInvalidRoute, route)
	}

	payload, metadata, err := t.serialize(message, route)
	if err != nil {
		return nil, fmt.Errorf("serializing: %w", err)
	}
	encrypted, err := t.encryptPayload(payload)
	if err != nil {
		return nil, fmt.Errorf("encrypting payload: %w", err)
	}

	if err := t.conn.WriteBytes(encrypted); err != nil {
		return nil, fmt.Errorf("writing: %w", err)
	}

	t.mu.Lock()
	t.sendSequence++
	t.mu.Unlock()

	return metadata, nil
}

// SessionID returns the unique identifier for this session.
func (t *Transport) SessionID() string { return t.sessionID }

// Phase returns the current session phase.
func (t *Transport) Phase() SessionPhase {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.phase
}

// SetPhase updates the session phase.
func (t *Transport) SetPhase(phase SessionPhase) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.phase = phase
}

// IsEstablished returns true if the session is fully established.
func (t *Transport) IsEstablished() bool {
	return t.Phase() == PhaseEstablished
}

// Close closes the transport connection.
func (t *Transport) Close() error {
	t.SetPhase(PhaseClosed)
	return t.conn.Close()
}

// Store returns the storage associated with this transport.
func (t *Transport) Store() *Storage { return t.storage }

// State returns the current session state for potential resumption.
//
// It includes the serialized Double Ratchet state when available so that an
// established session can be resumed without re-handshaking.
func (t *Transport) State() *SessionState {
	t.mu.Lock()
	defer t.mu.Unlock()

	var ratchetState []byte
	if t.ratchet != nil {
		st, err := t.ratchet.Save()
		if err == nil && st != nil {
			// Store JSON encoded ratchet state (ratchet.State uses JSON encoding).
			// If serialization fails, we fall back to empty, which will prevent
			// ratchet-based resumption (better to fail closed).
			if b, err := st.Serialize(); err == nil {
				ratchetState = b
			}
		}
	}

	return &SessionState{
		SessionID:       t.sessionID,
		Phase:           t.phase,
		IsInitiator:     t.isInitiator,
		SendSequence:    t.sendSequence,
		RecvSequence:    t.recvSequence,
		SharedSecret:    t.sharedSecret,
		LocalSalt:       t.localSalt,
		RemoteSalt:      t.remoteSalt,
		RatchetState:    ratchetState,
		RemotePublicKey: t.remotePublicKey,
	}
}

// RemotePublicKey returns the remote peer's public key.
func (t *Transport) RemotePublicKey() []byte {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.remotePublicKey
}

// SetRemotePublicKey sets the remote peer's public key for session tracking.
func (t *Transport) SetRemotePublicKey(key []byte) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.remotePublicKey = key
}

// SetInitiator marks whether this transport is the initiator.
func (t *Transport) SetInitiator(isInitiator bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.isInitiator = isInitiator
}

// SetSecrets stores the cryptographic secrets for potential session resumption.
func (t *Transport) SetSecrets(sharedSecret, localSalt, remoteSalt []byte) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.sharedSecret = sharedSecret
	t.localSalt = localSalt
	t.remoteSalt = remoteSalt
}

func readSignedTransport(c Conn) (*pb.SignedTransport, Route, error) {
	payload, err := c.ReadBytes()
	if err != nil {
		return nil, RouteInvalid, fmt.Errorf("reading payload: %w", err)
	}
	var st pb.SignedTransport
	if err := proto.Unmarshal(payload, &st); err != nil {
		return nil, RouteInvalid, fmt.Errorf("unmarshalling transport: %w", err)
	}
	return &st, RouteFromProto(st.GetRoute()), nil
}

func (t *Transport) decryptPayload(payload []byte) ([]byte, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.ratchet == nil {
		decrypted, err := t.decoder.Decrypt(payload)
		if err != nil {
			return nil, fmt.Errorf("decrypting: %w", err)
		}
		return decrypted, nil
	}

	var ratchet pb.Ratchet
	if err := proto.Unmarshal(payload, &ratchet); err != nil {
		return nil, fmt.Errorf("unmarshalling ratchet: %w", err)
	}

	if dh := ratchet.GetDh(); dh != nil {
		if err := t.ratchet.SetTheirPublic(dh, t.sessionID); err != nil {
			return nil, fmt.Errorf("setting their public key: %w", err)
		}
	}

	decrypted, err := t.ratchet.Decrypt(ratchet.GetCiphertext())
	if err != nil {
		return nil, fmt.Errorf("ratchet decrypt: %w", err)
	}
	return decrypted, nil
}

func (t *Transport) encryptPayload(payload []byte) ([]byte, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.ratchet == nil {
		return t.encoder.Encrypt(payload), nil
	}

	// Snapshot send counter before possible ratchet step
	pn := t.ratchet.Sent()

	// If threshold reached, initiate a new DH ratchet
	var pub []byte
	var err error
	if pn >= t.ratchetThreshold {
		pub, err = t.ratchet.InitiateRatchet(t.sessionID)
		if err != nil {
			return nil, fmt.Errorf("initiating ratchet: %w", err)
		}
	}

	// Encrypt with the (possibly updated) send chain
	ct, err := t.ratchet.Encrypt(payload)
	if err != nil {
		return nil, fmt.Errorf("ratchet encrypt: %w", err)
	}
	ns := t.ratchet.Sent()

	ratchet := &pb.Ratchet{Dh: pub, Pn: pn, Ns: ns, Ciphertext: ct}
	data, err := proto.Marshal(ratchet)
	if err != nil {
		return nil, fmt.Errorf("marshalling ratchet: %w", err)
	}

	return data, nil
}
