package kamune

import (
	"net"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/kamune-org/kamune/pkg/attest"
)

func TestResumableSession(t *testing.T) {
	a := assert.New(t)
	session := &ResumableSession{
		SessionID:       "test-session-123",
		RemotePublicKey: []byte("remote-key"),
		LocalPublicKey:  []byte("local-key"),
		SharedSecret:    []byte("shared-secret"),
		LocalSalt:       []byte("local-salt"),
		RemoteSalt:      []byte("remote-salt"),
		SendSequence:    100,
		RecvSequence:    50,
		Phase:           PhaseEstablished,
		IsInitiator:     true,
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
	}

	a.Equal("test-session-123", session.SessionID)
	a.Equal([]byte("remote-key"), session.RemotePublicKey)
	a.Equal(PhaseEstablished, session.Phase)
	a.True(session.IsInitiator)
	a.Equal(uint64(100), session.SendSequence)
	a.Equal(uint64(50), session.RecvSequence)
}

func TestSessionResumerCanResume(t *testing.T) {
	a := assert.New(t)
	// Create temp storage
	f, err := os.CreateTemp("", "kamune-resume-test")
	a.NoError(err)
	a.NoError(f.Close())
	defer func() { a.NoError(os.Remove(f.Name())) }()

	storage, err := OpenStorage(
		StorageWithDBPath(f.Name()),
		StorageWithAlgorithm(attest.Ed25519Algorithm),
		StorageWithNoPassphrase(),
	)
	a.NoError(err)
	defer func() { a.NoError(storage.Close()) }()

	sm := NewSessionManager(storage, 24*time.Hour)
	attester, err := attest.NewAttester(attest.Ed25519Algorithm)
	a.NoError(err)

	resumer := NewSessionResumer(storage, sm, attester, 24*time.Hour)

	// With no existing session, CanResume should return false
	canResume, state, err := resumer.CanResume([]byte("unknown-key"))
	a.NoError(err)
	a.False(canResume)
	a.Nil(state)
}

func TestSessionResumerChallengeResponse(t *testing.T) {
	a := assert.New(t)
	// Create temp storage
	f, err := os.CreateTemp("", "kamune-challenge-test")
	a.NoError(err)
	a.NoError(f.Close())
	defer func() { a.NoError(os.Remove(f.Name())) }()

	storage, err := OpenStorage(
		StorageWithDBPath(f.Name()),
		StorageWithAlgorithm(attest.Ed25519Algorithm),
		StorageWithNoPassphrase(),
	)
	a.NoError(err)
	defer func() { a.NoError(storage.Close()) }()

	sm := NewSessionManager(storage, 24*time.Hour)
	attester, err := attest.NewAttester(attest.Ed25519Algorithm)
	a.NoError(err)

	resumer := NewSessionResumer(storage, sm, attester, 24*time.Hour)

	challenge := []byte("test-challenge-data")
	sharedSecret := []byte("shared-secret-key")

	// Challenge response should be deterministic
	response1 := resumer.computeChallengeResponse(challenge, sharedSecret)
	response2 := resumer.computeChallengeResponse(challenge, sharedSecret)
	a.Equal(response1, response2)

	// Different challenge should produce different response
	differentChallenge := []byte("different-challenge")
	response3 := resumer.computeChallengeResponse(differentChallenge, sharedSecret)
	a.NotEqual(response1, response3)

	// Different secret should produce different response
	differentSecret := []byte("different-secret")
	response4 := resumer.computeChallengeResponse(challenge, differentSecret)
	a.NotEqual(response1, response4)
}

func TestSessionResumerReconcileSequences(t *testing.T) {
	a := assert.New(t)
	f, err := os.CreateTemp("", "kamune-seq-test")
	a.NoError(err)
	a.NoError(f.Close())
	defer func() { a.NoError(os.Remove(f.Name())) }()

	storage, err := OpenStorage(
		StorageWithDBPath(f.Name()),
		StorageWithAlgorithm(attest.Ed25519Algorithm),
		StorageWithNoPassphrase(),
	)
	a.NoError(err)
	defer func() { a.NoError(storage.Close()) }()

	sm := NewSessionManager(storage, 24*time.Hour)
	attester, err := attest.NewAttester(attest.Ed25519Algorithm)
	a.NoError(err)

	resumer := NewSessionResumer(storage, sm, attester, 24*time.Hour)

	tests := []struct {
		name                       string
		localSend, localRecv       uint64
		remoteSend, remoteRecv     uint64
		expectedSend, expectedRecv uint64
	}{
		{
			name:         "both in sync",
			localSend:    10,
			localRecv:    10,
			remoteSend:   10,
			remoteRecv:   10,
			expectedSend: 10,
			expectedRecv: 10,
		},
		{
			name:         "local ahead on send",
			localSend:    15,
			localRecv:    10,
			remoteSend:   10,
			remoteRecv:   10,
			expectedSend: 15,
			expectedRecv: 10,
		},
		{
			name:         "remote ahead on recv",
			localSend:    10,
			localRecv:    10,
			remoteSend:   15,
			remoteRecv:   10,
			expectedSend: 10,
			expectedRecv: 15,
		},
		{
			name:         "remote received more than we sent",
			localSend:    10,
			localRecv:    10,
			remoteSend:   10,
			remoteRecv:   15,
			expectedSend: 15,
			expectedRecv: 10,
		},
		{
			name:         "complex scenario",
			localSend:    100,
			localRecv:    80,
			remoteSend:   90,
			remoteRecv:   95,
			expectedSend: 100,
			expectedRecv: 90,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			send, recv := resumer.reconcileSequences(
				tt.localSend, tt.localRecv,
				tt.remoteSend, tt.remoteRecv,
			)
			a.Equal(tt.expectedSend, send)
			a.Equal(tt.expectedRecv, recv)
		})
	}
}

func TestResumeOrDialFallback(t *testing.T) {
	a := assert.New(t)
	// This test verifies that ResumeOrDial falls back to fresh dial
	// when no session exists

	// Create temp storage for client
	f, err := os.CreateTemp("", "kamune-dial-test")
	a.NoError(err)
	a.NoError(f.Close())
	defer func() { a.NoError(os.Remove(f.Name())) }()

	sm := NewSessionManager(nil, 24*time.Hour)

	// With no existing session for this key, checkResumability should return false
	canResume, state, err := checkResumability([]byte("nonexistent-key"), sm)
	a.NoError(err)
	a.False(canResume)
	a.Nil(state)
}

func TestSaveSessionForResumption(t *testing.T) {
	a := assert.New(t)
	// Create temp storage
	f, err := os.CreateTemp("", "kamune-save-test")
	a.NoError(err)
	a.NoError(f.Close())
	defer func() { a.NoError(os.Remove(f.Name())) }()

	storage, err := OpenStorage(
		StorageWithDBPath(f.Name()),
		StorageWithAlgorithm(attest.Ed25519Algorithm),
		StorageWithNoPassphrase(),
	)
	a.NoError(err)
	defer func() { a.NoError(storage.Close()) }()

	sm := NewSessionManager(storage, 24*time.Hour)

	// Create mock attesters
	attester1, err := attest.NewAttester(attest.Ed25519Algorithm)
	a.NoError(err)
	attester2, err := attest.NewAttester(attest.Ed25519Algorithm)
	a.NoError(err)

	// Create a pipe for testing
	c1, c2 := net.Pipe()
	conn1, err := newConn(c1)
	a.NoError(err)
	conn2, err := newConn(c2)
	a.NoError(err)
	defer func() { a.NoError(conn1.Close()) }()
	defer func() { a.NoError(conn2.Close()) }()

	// Create plain transports
	pt1 := newPlainTransport(conn1, attester2.PublicKey(), attester1, storage)
	pt2 := newPlainTransport(conn2, attester1.PublicKey(), attester2, storage)

	handshakeOpts := handshakeOpts{
		ratchetThreshold: defaultRatchetThreshold,
		remoteVerifier:   func(store *Storage, peer *Peer) error { return nil },
	}

	// Perform handshake
	var t1 *Transport
	done := make(chan struct{})
	go func() {
		var err error
		t1, err = requestHandshake(pt1, handshakeOpts)
		a.NoError(err)
		close(done)
	}()

	t2, err := acceptHandshake(pt2, handshakeOpts)
	a.NoError(err)
	<-done

	a.NotNil(t1)
	a.NotNil(t2)

	// Save session for resumption
	err = SaveSessionForResumption(t1, sm)
	a.NoError(err)

	// Verify session was saved and can be found by public key
	state, err := sm.LoadSession(t1.SessionID())
	a.NoError(err)
	a.Equal(t1.SessionID(), state.SessionID)
	a.Equal(PhaseEstablished, state.Phase)
}

func TestHmacEqual(t *testing.T) {
	a := assert.New(t)
	tests := []struct {
		name     string
		a, b     []byte
		expected bool
	}{
		{
			name:     "equal slices",
			a:        []byte("hello"),
			b:        []byte("hello"),
			expected: true,
		},
		{
			name:     "different slices same length",
			a:        []byte("hello"),
			b:        []byte("world"),
			expected: false,
		},
		{
			name:     "different lengths",
			a:        []byte("hello"),
			b:        []byte("hi"),
			expected: false,
		},
		{
			name:     "empty slices",
			a:        []byte{},
			b:        []byte{},
			expected: true,
		},
		{
			name:     "one empty",
			a:        []byte("hello"),
			b:        []byte{},
			expected: false,
		},
		{
			name:     "nil slices",
			a:        nil,
			b:        nil,
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := hmacEqual(tt.a, tt.b)
			a.Equal(tt.expected, result)
		})
	}
}

func TestResumptionConfig(t *testing.T) {
	a := assert.New(t)
	// Test default config
	defaultConfig := DefaultResumptionConfig()
	a.True(defaultConfig.Enabled)
	a.Equal(24*time.Hour, defaultConfig.MaxSessionAge)
	a.True(defaultConfig.PersistSessions)

	// Test custom config
	customConfig := ResumptionConfig{
		Enabled:         false,
		MaxSessionAge:   1 * time.Hour,
		PersistSessions: false,
	}
	a.False(customConfig.Enabled)
	a.Equal(1*time.Hour, customConfig.MaxSessionAge)
	a.False(customConfig.PersistSessions)
}

func TestSessionResumerNew(t *testing.T) {
	a := assert.New(t)
	f, err := os.CreateTemp("", "kamune-resumer-new-test")
	a.NoError(err)
	a.NoError(f.Close())
	defer func() { a.NoError(os.Remove(f.Name())) }()

	storage, err := OpenStorage(
		StorageWithDBPath(f.Name()),
		StorageWithAlgorithm(attest.Ed25519Algorithm),
		StorageWithNoPassphrase(),
	)
	a.NoError(err)
	defer func() { a.NoError(storage.Close()) }()

	sm := NewSessionManager(storage, 24*time.Hour)
	attester, err := attest.NewAttester(attest.Ed25519Algorithm)
	a.NoError(err)

	// Test with zero max age (should default to 24h)
	resumer := NewSessionResumer(storage, sm, attester, 0)
	a.NotNil(resumer)
	a.Equal(24*time.Hour, resumer.maxSessionAge)

	// Test with custom max age
	resumer2 := NewSessionResumer(storage, sm, attester, 1*time.Hour)
	a.NotNil(resumer2)
	a.Equal(1*time.Hour, resumer2.maxSessionAge)
}

func TestCheckResumability(t *testing.T) {
	a := assert.New(t)
	f, err := os.CreateTemp("", "kamune-check-resume-test")
	a.NoError(err)
	a.NoError(f.Close())
	defer func() { a.NoError(os.Remove(f.Name())) }()

	storage, err := OpenStorage(
		StorageWithDBPath(f.Name()),
		StorageWithAlgorithm(attest.Ed25519Algorithm),
		StorageWithNoPassphrase(),
	)
	a.NoError(err)
	defer func() { a.NoError(storage.Close()) }()

	sm := NewSessionManager(storage, 24*time.Hour)

	remotePubKey := []byte("test-remote-public-key")
	sessionID := "test-session-for-check"

	// Initially should not be resumable
	canResume, state, err := checkResumability(remotePubKey, sm)
	a.NoError(err)
	a.False(canResume)
	a.Nil(state)

	// Save a session state
	testState := &SessionState{
		SessionID:       sessionID,
		Phase:           PhaseEstablished,
		IsInitiator:     true,
		SharedSecret:    []byte("test-secret"),
		RemotePublicKey: remotePubKey,
		LocalSalt:       []byte("local-salt"),
		RemoteSalt:      []byte("remote-salt"),
	}

	err = sm.SaveSession(testState)
	a.NoError(err)

	// Register the session by public key
	sm.RegisterSession(sessionID, remotePubKey)

	// Now should be resumable
	canResume, state, err = checkResumability(remotePubKey, sm)
	a.NoError(err)
	a.True(canResume)
	a.NotNil(state)
	a.Equal(sessionID, state.SessionID)
}

func TestCheckResumabilityNotEstablished(t *testing.T) {
	a := assert.New(t)
	f, err := os.CreateTemp("", "kamune-check-not-established-test")
	a.NoError(err)
	a.NoError(f.Close())
	defer func() { a.NoError(os.Remove(f.Name())) }()

	storage, err := OpenStorage(
		StorageWithDBPath(f.Name()),
		StorageWithAlgorithm(attest.Ed25519Algorithm),
		StorageWithNoPassphrase(),
	)
	a.NoError(err)
	defer func() { a.NoError(storage.Close()) }()

	sm := NewSessionManager(storage, 24*time.Hour)

	remotePubKey := []byte("test-remote-key-not-established")
	sessionID := "test-session-not-established"

	// Save a session that's not established
	testState := &SessionState{
		SessionID:       sessionID,
		Phase:           PhaseHandshakeRequested, // Not established
		IsInitiator:     true,
		SharedSecret:    []byte("test-secret"),
		RemotePublicKey: remotePubKey,
	}

	err = sm.SaveSession(testState)
	a.NoError(err)
	sm.RegisterSession(sessionID, remotePubKey)

	// Should not be resumable because phase is not established
	canResume, _, err := checkResumability(remotePubKey, sm)
	a.NoError(err)
	a.False(canResume)
}

func TestCheckResumabilityNoSecret(t *testing.T) {
	a := assert.New(t)
	f, err := os.CreateTemp("", "kamune-check-no-secret-test")
	a.NoError(err)
	a.NoError(f.Close())
	defer func() { a.NoError(os.Remove(f.Name())) }()

	storage, err := OpenStorage(
		StorageWithDBPath(f.Name()),
		StorageWithAlgorithm(attest.Ed25519Algorithm),
		StorageWithNoPassphrase(),
	)
	a.NoError(err)
	defer func() { a.NoError(storage.Close()) }()

	sm := NewSessionManager(storage, 24*time.Hour)

	remotePubKey := []byte("test-remote-key-no-secret")
	sessionID := "test-session-no-secret"

	// Save a session without shared secret
	testState := &SessionState{
		SessionID:       sessionID,
		Phase:           PhaseEstablished,
		IsInitiator:     true,
		SharedSecret:    nil, // No secret
		RemotePublicKey: remotePubKey,
	}

	err = sm.SaveSession(testState)
	a.NoError(err)
	sm.RegisterSession(sessionID, remotePubKey)

	// Should not be resumable because no shared secret
	canResume, _, err := checkResumability(remotePubKey, sm)
	a.NoError(err)
	a.False(canResume)
}
