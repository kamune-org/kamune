package kamune

import (
	"crypto/sha3"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/kamune-org/kamune/internal/box/pb"
	"github.com/kamune-org/kamune/pkg/store"
)

var (
	ErrSessionNotResumable = errors.New("session cannot be resumed")
	ErrSessionMismatch     = errors.New("session state mismatch")
	ErrHandshakeInProgress = errors.New("handshake already in progress")
	ErrHandshakeNotFound   = errors.New("handshake state not found")

	sessionsBucket  = []byte(store.DefaultBucket + "_sessions")
	handshakeBucket = []byte(store.DefaultBucket + "_handshakes")
)

// HandshakeState tracks an in-progress handshake identified by the remote
// peer's public key.
type HandshakeState struct {
	CreatedAt       time.Time
	UpdatedAt       time.Time
	SessionID       string
	RemotePublicKey []byte
	LocalPublicKey  []byte
	SharedSecret    []byte
	LocalSalt       []byte
	RemoteSalt      []byte
	Phase           SessionPhase
	IsInitiator     bool
}

// HandshakeTracker manages in-progress handshakes using public keys as
// identifiers. This allows handshakes to be resumed after connection resets.
type HandshakeTracker struct {
	handshakes map[string]*HandshakeState
	storage    *Storage
	timeout    time.Duration
	mu         sync.RWMutex
}

// NewHandshakeTracker creates a new handshake tracker.
func NewHandshakeTracker(storage *Storage, timeout time.Duration) *HandshakeTracker {
	if timeout <= 0 {
		timeout = 5 * time.Minute // Default handshake timeout
	}
	return &HandshakeTracker{
		handshakes: make(map[string]*HandshakeState),
		storage:    storage,
		timeout:    timeout,
	}
}

// publicKeyHash generates a unique key from a public key for map lookups.
func publicKeyHash(publicKey []byte) string {
	hash := sha3.Sum256(publicKey)
	return string(hash[:])
}

// StartHandshake begins tracking a new handshake with the given remote public key.
func (ht *HandshakeTracker) StartHandshake(
	remotePublicKey, localPublicKey []byte,
	isInitiator bool,
) (*HandshakeState, error) {
	ht.mu.Lock()
	defer ht.mu.Unlock()

	key := publicKeyHash(remotePublicKey)

	// Check if there's an existing handshake
	if existing, ok := ht.handshakes[key]; ok {
		// Check if it's expired
		if time.Since(existing.UpdatedAt) < ht.timeout {
			return existing, ErrHandshakeInProgress
		}
		// Expired, remove it
		delete(ht.handshakes, key)
	}

	now := time.Now()
	state := &HandshakeState{
		RemotePublicKey: remotePublicKey,
		LocalPublicKey:  localPublicKey,
		Phase:           PhaseIntroduction,
		IsInitiator:     isInitiator,
		CreatedAt:       now,
		UpdatedAt:       now,
	}

	ht.handshakes[key] = state
	return state, nil
}

// GetHandshake retrieves an in-progress handshake by remote public key.
func (ht *HandshakeTracker) GetHandshake(
	remotePublicKey []byte,
) (*HandshakeState, error) {
	ht.mu.RLock()
	defer ht.mu.RUnlock()

	key := publicKeyHash(remotePublicKey)
	state, ok := ht.handshakes[key]
	if !ok {
		return nil, ErrHandshakeNotFound
	}

	// Check expiration
	if time.Since(state.UpdatedAt) > ht.timeout {
		return nil, ErrSessionExpired
	}

	return state, nil
}

// UpdateHandshake updates the state of an in-progress handshake.
func (ht *HandshakeTracker) UpdateHandshake(
	remotePublicKey []byte,
	phase SessionPhase,
	sessionID string,
	sharedSecret, localSalt, remoteSalt []byte,
) error {
	ht.mu.Lock()
	defer ht.mu.Unlock()

	key := publicKeyHash(remotePublicKey)
	state, ok := ht.handshakes[key]
	if !ok {
		return ErrHandshakeNotFound
	}

	state.Phase = phase
	state.UpdatedAt = time.Now()

	if sessionID != "" {
		state.SessionID = sessionID
	}
	if sharedSecret != nil {
		state.SharedSecret = sharedSecret
	}
	if localSalt != nil {
		state.LocalSalt = localSalt
	}
	if remoteSalt != nil {
		state.RemoteSalt = remoteSalt
	}

	return nil
}

// CompleteHandshake marks a handshake as complete and removes it from tracking.
// Returns the final state for session creation.
func (ht *HandshakeTracker) CompleteHandshake(
	remotePublicKey []byte,
) (*HandshakeState, error) {
	ht.mu.Lock()
	defer ht.mu.Unlock()

	key := publicKeyHash(remotePublicKey)
	state, ok := ht.handshakes[key]
	if !ok {
		return nil, ErrHandshakeNotFound
	}

	delete(ht.handshakes, key)
	return state, nil
}

// CancelHandshake removes a handshake from tracking.
func (ht *HandshakeTracker) CancelHandshake(remotePublicKey []byte) {
	ht.mu.Lock()
	defer ht.mu.Unlock()

	key := publicKeyHash(remotePublicKey)
	delete(ht.handshakes, key)
}

// CleanupExpired removes all expired handshakes.
func (ht *HandshakeTracker) CleanupExpired() int {
	ht.mu.Lock()
	defer ht.mu.Unlock()

	count := 0
	for key, state := range ht.handshakes {
		if time.Since(state.UpdatedAt) > ht.timeout {
			delete(ht.handshakes, key)
			count++
		}
	}
	return count
}

// PersistHandshake saves the handshake state to storage for resumption
// after process restart.
func (ht *HandshakeTracker) PersistHandshake(remotePublicKey []byte) error {
	ht.mu.RLock()
	state, ok := ht.handshakes[publicKeyHash(remotePublicKey)]
	ht.mu.RUnlock()

	if !ok {
		return ErrHandshakeNotFound
	}

	pbState := &pb.SessionState{
		SessionId:       state.SessionID,
		Phase:           state.Phase.ToProto(),
		IsInitiator:     state.IsInitiator,
		SharedSecret:    state.SharedSecret,
		LocalSalt:       state.LocalSalt,
		RemoteSalt:      state.RemoteSalt,
		RemotePublicKey: state.RemotePublicKey,
		CreatedAt:       timestamppb.New(state.CreatedAt),
		UpdatedAt:       timestamppb.New(state.UpdatedAt),
	}

	data, err := proto.Marshal(pbState)
	if err != nil {
		return fmt.Errorf("marshaling handshake state: %w", err)
	}

	key := sha3.Sum256(remotePublicKey)
	err = ht.storage.store.Command(func(c store.Command) error {
		return c.AddEncrypted(handshakeBucket, key[:], data)
	})
	if err != nil {
		return fmt.Errorf("storing handshake state: %w", err)
	}

	return nil
}

// LoadHandshake loads a persisted handshake state from storage.
func (ht *HandshakeTracker) LoadHandshake(
	remotePublicKey []byte,
) (*HandshakeState, error) {
	key := sha3.Sum256(remotePublicKey)

	var data []byte
	err := ht.storage.store.Query(func(q store.Query) error {
		var err error
		data, err = q.GetEncrypted(handshakeBucket, key[:])
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("loading handshake state: %w", err)
	}

	var pbState pb.SessionState
	if err := proto.Unmarshal(data, &pbState); err != nil {
		return nil, fmt.Errorf("unmarshaling handshake state: %w", err)
	}

	// Check expiration
	if pbState.UpdatedAt != nil {
		if time.Since(pbState.UpdatedAt.AsTime()) > ht.timeout {
			// Clean up expired
			_ = ht.storage.store.Command(func(c store.Command) error {
				return c.Delete(handshakeBucket, key[:])
			})
			return nil, ErrSessionExpired
		}
	}

	var createdAt, updatedAt time.Time
	if pbState.CreatedAt != nil {
		createdAt = pbState.CreatedAt.AsTime()
	}
	if pbState.UpdatedAt != nil {
		updatedAt = pbState.UpdatedAt.AsTime()
	}

	state := &HandshakeState{
		RemotePublicKey: pbState.RemotePublicKey,
		SessionID:       pbState.SessionId,
		Phase:           PhaseFromProto(pbState.Phase),
		IsInitiator:     pbState.IsInitiator,
		SharedSecret:    pbState.SharedSecret,
		LocalSalt:       pbState.LocalSalt,
		RemoteSalt:      pbState.RemoteSalt,
		CreatedAt:       createdAt,
		UpdatedAt:       updatedAt,
	}

	// Also add to in-memory cache
	ht.mu.Lock()
	ht.handshakes[publicKeyHash(remotePublicKey)] = state
	ht.mu.Unlock()

	return state, nil
}

// DeletePersistedHandshake removes a persisted handshake from storage.
func (ht *HandshakeTracker) DeletePersistedHandshake(remotePublicKey []byte) error {
	key := sha3.Sum256(remotePublicKey)
	return ht.storage.store.Command(func(c store.Command) error {
		return c.Delete(handshakeBucket, key[:])
	})
}

// CanResumeHandshake checks if there's a resumable handshake with the peer.
func (ht *HandshakeTracker) CanResumeHandshake(
	remotePublicKey []byte,
) (bool, SessionPhase, error) {
	// First check in-memory
	state, err := ht.GetHandshake(remotePublicKey)
	if err == nil {
		return true, state.Phase, nil
	}

	// Try loading from storage
	state, err = ht.LoadHandshake(remotePublicKey)
	if err != nil {
		if errors.Is(err, store.ErrMissingItem) || errors.Is(err, ErrSessionExpired) {
			return false, PhaseInvalid, nil
		}
		return false, PhaseInvalid, err
	}

	return true, state.Phase, nil
}

// ActiveHandshakes returns the number of in-progress handshakes.
func (ht *HandshakeTracker) ActiveHandshakes() int {
	ht.mu.RLock()
	defer ht.mu.RUnlock()
	return len(ht.handshakes)
}

// SessionManager handles persistence and resumption of session states.
// Sessions are identified by both session ID and the remote peer's public key.
type SessionManager struct {
	storage          *Storage
	handshakeTracker *HandshakeTracker
	sessionsByPubKey map[string]string
	sessionTimeout   time.Duration
	mu               sync.RWMutex
}

// NewSessionManager creates a new session manager.
func NewSessionManager(storage *Storage, timeout time.Duration) *SessionManager {
	if timeout <= 0 {
		timeout = 24 * time.Hour // Default session timeout
	}
	return &SessionManager{
		storage:          storage,
		sessionTimeout:   timeout,
		handshakeTracker: NewHandshakeTracker(storage, 5*time.Minute),
		sessionsByPubKey: make(map[string]string),
	}
}

// HandshakeTracker returns the handshake tracker for managing in-progress handshakes.
func (sm *SessionManager) HandshakeTracker() *HandshakeTracker {
	return sm.handshakeTracker
}

// RegisterSession associates a session ID with a remote public key.
func (sm *SessionManager) RegisterSession(sessionID string, remotePublicKey []byte) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.sessionsByPubKey[publicKeyHash(remotePublicKey)] = sessionID
}

// GetSessionByPublicKey retrieves a session ID by the remote peer's public key.
func (sm *SessionManager) GetSessionByPublicKey(remotePublicKey []byte) (string, bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	sessionID, ok := sm.sessionsByPubKey[publicKeyHash(remotePublicKey)]
	return sessionID, ok
}

// UnregisterSession removes the association between a session ID and public key.
func (sm *SessionManager) UnregisterSession(remotePublicKey []byte) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	delete(sm.sessionsByPubKey, publicKeyHash(remotePublicKey))
}

// SaveSession persists the session state for potential resumption.
//
// NOTE: CreatedAt must be stable across updates. We preserve any existing
// CreatedAt value in storage and only set it on first save.
func (sm *SessionManager) SaveSession(state *SessionState) error {
	if state == nil || state.SessionID == "" {
		return errors.New("invalid session state")
	}

	createdAt := timestamppb.Now()

	// Preserve CreatedAt if this session already exists.
	key := sessionKey(state.SessionID)
	_ = sm.storage.store.Query(func(q store.Query) error {
		data, err := q.GetEncrypted(sessionsBucket, key)
		if err != nil {
			return err
		}

		var existing pb.SessionState
		if err := proto.Unmarshal(data, &existing); err != nil {
			return err
		}

		if existing.CreatedAt != nil {
			createdAt = existing.CreatedAt
		}
		return nil
	})

	pbState := &pb.SessionState{
		SessionId:       state.SessionID,
		Phase:           state.Phase.ToProto(),
		IsInitiator:     state.IsInitiator,
		SendSequence:    state.SendSequence,
		RecvSequence:    state.RecvSequence,
		SharedSecret:    state.SharedSecret,
		LocalSalt:       state.LocalSalt,
		RemoteSalt:      state.RemoteSalt,
		RatchetState:    state.RatchetState,
		CreatedAt:       createdAt,
		UpdatedAt:       timestamppb.Now(),
		RemotePublicKey: state.RemotePublicKey,
	}

	data, err := proto.Marshal(pbState)
	if err != nil {
		return fmt.Errorf("marshaling session state: %w", err)
	}

	err = sm.storage.store.Command(func(c store.Command) error {
		return c.AddEncrypted(sessionsBucket, key, data)
	})
	if err != nil {
		return fmt.Errorf("storing session state: %w", err)
	}

	// Also register by public key if available
	if len(state.RemotePublicKey) > 0 {
		sm.RegisterSession(state.SessionID, state.RemotePublicKey)
	}

	return nil
}

// LoadSession retrieves a persisted session state.
func (sm *SessionManager) LoadSession(sessionID string) (*SessionState, error) {
	key := sessionKey(sessionID)

	var data []byte
	err := sm.storage.store.Query(func(q store.Query) error {
		var err error
		data, err = q.GetEncrypted(sessionsBucket, key)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("loading session state: %w", err)
	}

	var pbState pb.SessionState
	if err := proto.Unmarshal(data, &pbState); err != nil {
		return nil, fmt.Errorf("unmarshaling session state: %w", err)
	}

	// Check if session has expired
	if pbState.UpdatedAt != nil {
		lastUpdate := pbState.UpdatedAt.AsTime()
		if time.Since(lastUpdate) > sm.sessionTimeout {
			// Clean up expired session
			_ = sm.DeleteSession(sessionID)
			return nil, ErrSessionExpired
		}
	}

	return &SessionState{
		SessionID:       pbState.SessionId,
		Phase:           PhaseFromProto(pbState.Phase),
		IsInitiator:     pbState.IsInitiator,
		SendSequence:    pbState.SendSequence,
		RecvSequence:    pbState.RecvSequence,
		SharedSecret:    pbState.SharedSecret,
		LocalSalt:       pbState.LocalSalt,
		RemoteSalt:      pbState.RemoteSalt,
		RatchetState:    pbState.RatchetState,
		RemotePublicKey: pbState.RemotePublicKey,
	}, nil
}

// LoadSessionByPublicKey retrieves a session state by the remote peer's public key.
func (sm *SessionManager) LoadSessionByPublicKey(
	remotePublicKey []byte,
) (*SessionState, error) {
	sessionID, ok := sm.GetSessionByPublicKey(remotePublicKey)
	if !ok {
		return nil, ErrSessionNotFound
	}
	return sm.LoadSession(sessionID)
}

// DeleteSession removes a persisted session state.
func (sm *SessionManager) DeleteSession(sessionID string) error {
	key := sessionKey(sessionID)
	return sm.storage.store.Command(func(c store.Command) error {
		return c.Delete(sessionsBucket, key)
	})
}

// UpdateSessionPhase updates the phase of a persisted session.
func (sm *SessionManager) UpdateSessionPhase(sessionID string, phase SessionPhase) error {
	state, err := sm.LoadSession(sessionID)
	if err != nil {
		return err
	}
	state.Phase = phase
	return sm.SaveSession(state)
}

// UpdateSessionPhaseByPublicKey updates the phase of a session by public key.
func (sm *SessionManager) UpdateSessionPhaseByPublicKey(
	remotePublicKey []byte, phase SessionPhase,
) error {
	state, err := sm.LoadSessionByPublicKey(remotePublicKey)
	if err != nil {
		return err
	}
	state.Phase = phase
	return sm.SaveSession(state)
}

// UpdateSessionSequences updates the sequence numbers of a persisted session.
func (sm *SessionManager) UpdateSessionSequences(
	sessionID string, sendSeq, recvSeq uint64,
) error {
	state, err := sm.LoadSession(sessionID)
	if err != nil {
		return err
	}
	state.SendSequence = sendSeq
	state.RecvSequence = recvSeq
	return sm.SaveSession(state)
}

// CanResume checks if a session can be resumed based on its state.
func (sm *SessionManager) CanResume(sessionID string) (bool, SessionPhase, error) {
	state, err := sm.LoadSession(sessionID)
	if err != nil {
		if errors.Is(err, ErrSessionExpired) || errors.Is(err, store.ErrMissingItem) {
			return false, PhaseInvalid, nil
		}
		return false, PhaseInvalid, err
	}

	// Only established sessions can be resumed
	if state.Phase < PhaseEstablished {
		return false, state.Phase, nil
	}

	// Must have the shared secret to resume
	if len(state.SharedSecret) == 0 {
		return false, state.Phase, nil
	}

	return true, state.Phase, nil
}

// ListActiveSessions returns all non-expired session IDs.
func (sm *SessionManager) ListActiveSessions() ([]string, error) {
	var sessions []string

	err := sm.storage.store.Query(func(q store.Query) error {
		for _, value := range q.IterateEncrypted(sessionsBucket) {
			var pbState pb.SessionState
			if err := proto.Unmarshal(value, &pbState); err != nil {
				continue
			}

			// Check expiration
			if pbState.UpdatedAt != nil {
				if time.Since(pbState.UpdatedAt.AsTime()) > sm.sessionTimeout {
					continue
				}
			}

			sessions = append(sessions, pbState.SessionId)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("listing sessions: %w", err)
	}

	return sessions, nil
}

// CleanupExpiredSessions removes all expired sessions from storage.
func (sm *SessionManager) CleanupExpiredSessions() (int, error) {
	var expiredKeys [][]byte

	err := sm.storage.store.Query(func(q store.Query) error {
		for key, value := range q.IterateEncrypted(sessionsBucket) {
			var pbState pb.SessionState
			if err := proto.Unmarshal(value, &pbState); err != nil {
				continue
			}

			if pbState.UpdatedAt != nil {
				if time.Since(pbState.UpdatedAt.AsTime()) > sm.sessionTimeout {
					keyCopy := make([]byte, len(key))
					copy(keyCopy, key)
					expiredKeys = append(expiredKeys, keyCopy)
				}
			}
		}
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("scanning sessions: %w", err)
	}

	deleted := 0
	for _, key := range expiredKeys {
		err := sm.storage.store.Command(func(c store.Command) error {
			return c.Delete(sessionsBucket, key)
		})
		if err == nil {
			deleted++
		}
	}

	return deleted, nil
}

// SessionStats returns statistics about stored sessions.
type SessionStats struct {
	ByPhase         map[SessionPhase]int
	TotalSessions   int
	ActiveSessions  int
	ExpiredSessions int
}

// Stats returns statistics about the stored sessions.
func (sm *SessionManager) Stats() (*SessionStats, error) {
	stats := &SessionStats{
		ByPhase: make(map[SessionPhase]int),
	}

	err := sm.storage.store.Query(func(q store.Query) error {
		for _, value := range q.IterateEncrypted(sessionsBucket) {
			var pbState pb.SessionState
			if err := proto.Unmarshal(value, &pbState); err != nil {
				continue
			}

			stats.TotalSessions++
			phase := PhaseFromProto(pbState.Phase)
			stats.ByPhase[phase]++

			if pbState.UpdatedAt != nil {
				if time.Since(pbState.UpdatedAt.AsTime()) > sm.sessionTimeout {
					stats.ExpiredSessions++
				} else {
					stats.ActiveSessions++
				}
			}
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("computing stats: %w", err)
	}

	return stats, nil
}

// sessionKey generates a storage key from a session ID.
func sessionKey(sessionID string) []byte {
	hash := sha3.Sum256([]byte(sessionID))
	return hash[:]
}

// SaveTransportState extracts and saves the current state from a transport.
func (sm *SessionManager) SaveTransportState(t *Transport) error {
	state := t.State()
	return sm.SaveSession(state)
}

// SessionInfo contains summary information about a session.
type SessionInfo struct {
	CreatedAt    time.Time
	UpdatedAt    time.Time
	SessionID    string
	Phase        SessionPhase
	SendSequence uint64
	RecvSequence uint64
	IsInitiator  bool
	IsExpired    bool
}

// GetSessionInfo returns summary information about a session.
func (sm *SessionManager) GetSessionInfo(sessionID string) (*SessionInfo, error) {
	key := sessionKey(sessionID)

	var data []byte
	err := sm.storage.store.Query(func(q store.Query) error {
		var err error
		data, err = q.GetEncrypted(sessionsBucket, key)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("loading session info: %w", err)
	}

	var pbState pb.SessionState
	if err := proto.Unmarshal(data, &pbState); err != nil {
		return nil, fmt.Errorf("unmarshaling session info: %w", err)
	}

	var createdAt, updatedAt time.Time
	var isExpired bool

	if pbState.CreatedAt != nil {
		createdAt = pbState.CreatedAt.AsTime()
	}
	if pbState.UpdatedAt != nil {
		updatedAt = pbState.UpdatedAt.AsTime()
		isExpired = time.Since(updatedAt) > sm.sessionTimeout
	}

	return &SessionInfo{
		SessionID:    pbState.SessionId,
		Phase:        PhaseFromProto(pbState.Phase),
		IsInitiator:  pbState.IsInitiator,
		SendSequence: pbState.SendSequence,
		RecvSequence: pbState.RecvSequence,
		CreatedAt:    createdAt,
		UpdatedAt:    updatedAt,
		IsExpired:    isExpired,
	}, nil
}

// SequenceTracker helps maintain message ordering across reconnections.
type SequenceTracker struct {
	sendSeq uint64
	recvSeq uint64
}

// NewSequenceTracker creates a new sequence tracker from a session state.
func NewSequenceTracker(state *SessionState) *SequenceTracker {
	if state == nil {
		return &SequenceTracker{}
	}
	return &SequenceTracker{
		sendSeq: state.SendSequence,
		recvSeq: state.RecvSequence,
	}
}

// NextSend returns the next send sequence number.
func (st *SequenceTracker) NextSend() uint64 {
	st.sendSeq++
	return st.sendSeq
}

// NextRecv returns the next expected receive sequence number.
func (st *SequenceTracker) NextRecv() uint64 {
	st.recvSeq++
	return st.recvSeq
}

// ValidateRecv checks if a received sequence number is valid.
func (st *SequenceTracker) ValidateRecv(seq uint64) error {
	expected := st.recvSeq + 1
	if seq < expected {
		return fmt.Errorf("duplicate message: got %d, expected >= %d", seq, expected)
	}
	if seq > expected {
		return fmt.Errorf("missing messages: got %d, expected %d", seq, expected)
	}
	st.recvSeq = seq
	return nil
}

// Sequences returns the current send and receive sequence numbers.
func (st *SequenceTracker) Sequences() (send, recv uint64) {
	return st.sendSeq, st.recvSeq
}

// EncodeSequences encodes the sequence numbers for transmission.
func (st *SequenceTracker) EncodeSequences() []byte {
	buf := make([]byte, 16)
	binary.BigEndian.PutUint64(buf[:8], st.sendSeq)
	binary.BigEndian.PutUint64(buf[8:], st.recvSeq)
	return buf
}

// DecodeSequences decodes sequence numbers from received data.
func DecodeSequences(data []byte) (send, recv uint64, err error) {
	if len(data) < 16 {
		return 0, 0, errors.New("sequence data too short")
	}
	send = binary.BigEndian.Uint64(data[:8])
	recv = binary.BigEndian.Uint64(data[8:])
	return send, recv, nil
}
