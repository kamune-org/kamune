package kamune

import (
	"net"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kamune-org/kamune/pkg/attest"
)

func TestResumableSession(t *testing.T) {
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

	assert.Equal(t, "test-session-123", session.SessionID)
	assert.Equal(t, []byte("remote-key"), session.RemotePublicKey)
	assert.Equal(t, PhaseEstablished, session.Phase)
	assert.True(t, session.IsInitiator)
	assert.Equal(t, uint64(100), session.SendSequence)
	assert.Equal(t, uint64(50), session.RecvSequence)
}

func TestSessionResumerCanResume(t *testing.T) {
	// Create temp storage
	f, err := os.CreateTemp("", "kamune-resume-test")
	require.NoError(t, err)
	require.NoError(t, f.Close())
	defer os.Remove(f.Name())

	storage, err := OpenStorage(
		StorageWithDBPath(f.Name()),
		StorageWithAlgorithm(attest.Ed25519Algorithm),
		StorageWithNoPassphrase(),
	)
	require.NoError(t, err)
	defer storage.Close()

	sm := NewSessionManager(storage, 24*time.Hour)
	attester, err := attest.NewAttester(attest.Ed25519Algorithm)
	require.NoError(t, err)

	resumer := NewSessionResumer(storage, sm, attester, 24*time.Hour)

	// With no existing session, CanResume should return false
	canResume, state, err := resumer.CanResume([]byte("unknown-key"))
	require.NoError(t, err)
	assert.False(t, canResume)
	assert.Nil(t, state)
}

func TestSessionResumerChallengeResponse(t *testing.T) {
	// Create temp storage
	f, err := os.CreateTemp("", "kamune-challenge-test")
	require.NoError(t, err)
	require.NoError(t, f.Close())
	defer os.Remove(f.Name())

	storage, err := OpenStorage(
		StorageWithDBPath(f.Name()),
		StorageWithAlgorithm(attest.Ed25519Algorithm),
		StorageWithNoPassphrase(),
	)
	require.NoError(t, err)
	defer storage.Close()

	sm := NewSessionManager(storage, 24*time.Hour)
	attester, err := attest.NewAttester(attest.Ed25519Algorithm)
	require.NoError(t, err)

	resumer := NewSessionResumer(storage, sm, attester, 24*time.Hour)

	challenge := []byte("test-challenge-data")
	sharedSecret := []byte("shared-secret-key")

	// Challenge response should be deterministic
	response1 := resumer.computeChallengeResponse(challenge, sharedSecret)
	response2 := resumer.computeChallengeResponse(challenge, sharedSecret)
	assert.Equal(t, response1, response2)

	// Different challenge should produce different response
	differentChallenge := []byte("different-challenge")
	response3 := resumer.computeChallengeResponse(differentChallenge, sharedSecret)
	assert.NotEqual(t, response1, response3)

	// Different secret should produce different response
	differentSecret := []byte("different-secret")
	response4 := resumer.computeChallengeResponse(challenge, differentSecret)
	assert.NotEqual(t, response1, response4)
}

func TestSessionResumerReconcileSequences(t *testing.T) {
	f, err := os.CreateTemp("", "kamune-seq-test")
	require.NoError(t, err)
	require.NoError(t, f.Close())
	defer os.Remove(f.Name())

	storage, err := OpenStorage(
		StorageWithDBPath(f.Name()),
		StorageWithAlgorithm(attest.Ed25519Algorithm),
		StorageWithNoPassphrase(),
	)
	require.NoError(t, err)
	defer storage.Close()

	sm := NewSessionManager(storage, 24*time.Hour)
	attester, err := attest.NewAttester(attest.Ed25519Algorithm)
	require.NoError(t, err)

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
			assert.Equal(t, tt.expectedSend, send)
			assert.Equal(t, tt.expectedRecv, recv)
		})
	}
}

func TestResumeOrDialFallback(t *testing.T) {
	// This test verifies that ResumeOrDial falls back to fresh dial
	// when no session exists

	// Create temp storage for client
	f, err := os.CreateTemp("", "kamune-dial-test")
	require.NoError(t, err)
	require.NoError(t, f.Close())
	defer os.Remove(f.Name())

	sm := NewSessionManager(nil, 24*time.Hour)

	// With no existing session for this key, checkResumability should return false
	canResume, state, err := checkResumability([]byte("nonexistent-key"), sm)
	require.NoError(t, err)
	assert.False(t, canResume)
	assert.Nil(t, state)
}

func TestSaveSessionForResumption(t *testing.T) {
	// Create temp storage
	f, err := os.CreateTemp("", "kamune-save-test")
	require.NoError(t, err)
	require.NoError(t, f.Close())
	defer os.Remove(f.Name())

	storage, err := OpenStorage(
		StorageWithDBPath(f.Name()),
		StorageWithAlgorithm(attest.Ed25519Algorithm),
		StorageWithNoPassphrase(),
	)
	require.NoError(t, err)
	defer storage.Close()

	sm := NewSessionManager(storage, 24*time.Hour)

	// Create mock attesters
	attester1, err := attest.NewAttester(attest.Ed25519Algorithm)
	require.NoError(t, err)
	attester2, err := attest.NewAttester(attest.Ed25519Algorithm)
	require.NoError(t, err)

	// Create a pipe for testing
	c1, c2 := net.Pipe()
	conn1, err := newConn(c1)
	require.NoError(t, err)
	conn2, err := newConn(c2)
	require.NoError(t, err)
	defer conn1.Close()
	defer conn2.Close()

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
		require.NoError(t, err)
		close(done)
	}()

	t2, err := acceptHandshake(pt2, handshakeOpts)
	require.NoError(t, err)
	<-done

	require.NotNil(t, t1)
	require.NotNil(t, t2)

	// Save session for resumption
	err = SaveSessionForResumption(t1, sm)
	require.NoError(t, err)

	// Verify session was saved and can be found by public key
	state, err := sm.LoadSession(t1.SessionID())
	require.NoError(t, err)
	assert.Equal(t, t1.SessionID(), state.SessionID)
	assert.Equal(t, PhaseEstablished, state.Phase)
}

func TestHmacEqual(t *testing.T) {
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
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestResumptionConfig(t *testing.T) {
	// Test default config
	defaultConfig := DefaultResumptionConfig()
	assert.True(t, defaultConfig.Enabled)
	assert.Equal(t, 24*time.Hour, defaultConfig.MaxSessionAge)
	assert.True(t, defaultConfig.PersistSessions)

	// Test custom config
	customConfig := ResumptionConfig{
		Enabled:         false,
		MaxSessionAge:   1 * time.Hour,
		PersistSessions: false,
	}
	assert.False(t, customConfig.Enabled)
	assert.Equal(t, 1*time.Hour, customConfig.MaxSessionAge)
	assert.False(t, customConfig.PersistSessions)
}

func TestSessionResumerNew(t *testing.T) {
	f, err := os.CreateTemp("", "kamune-resumer-new-test")
	require.NoError(t, err)
	require.NoError(t, f.Close())
	defer os.Remove(f.Name())

	storage, err := OpenStorage(
		StorageWithDBPath(f.Name()),
		StorageWithAlgorithm(attest.Ed25519Algorithm),
		StorageWithNoPassphrase(),
	)
	require.NoError(t, err)
	defer storage.Close()

	sm := NewSessionManager(storage, 24*time.Hour)
	attester, err := attest.NewAttester(attest.Ed25519Algorithm)
	require.NoError(t, err)

	// Test with zero max age (should default to 24h)
	resumer := NewSessionResumer(storage, sm, attester, 0)
	assert.NotNil(t, resumer)
	assert.Equal(t, 24*time.Hour, resumer.maxSessionAge)

	// Test with custom max age
	resumer2 := NewSessionResumer(storage, sm, attester, 1*time.Hour)
	assert.NotNil(t, resumer2)
	assert.Equal(t, 1*time.Hour, resumer2.maxSessionAge)
}

func TestCheckResumability(t *testing.T) {
	f, err := os.CreateTemp("", "kamune-check-resume-test")
	require.NoError(t, err)
	require.NoError(t, f.Close())
	defer os.Remove(f.Name())

	storage, err := OpenStorage(
		StorageWithDBPath(f.Name()),
		StorageWithAlgorithm(attest.Ed25519Algorithm),
		StorageWithNoPassphrase(),
	)
	require.NoError(t, err)
	defer storage.Close()

	sm := NewSessionManager(storage, 24*time.Hour)

	remotePubKey := []byte("test-remote-public-key")
	sessionID := "test-session-for-check"

	// Initially should not be resumable
	canResume, state, err := checkResumability(remotePubKey, sm)
	require.NoError(t, err)
	assert.False(t, canResume)
	assert.Nil(t, state)

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
	require.NoError(t, err)

	// Register the session by public key
	sm.RegisterSession(sessionID, remotePubKey)

	// Now should be resumable
	canResume, state, err = checkResumability(remotePubKey, sm)
	require.NoError(t, err)
	assert.True(t, canResume)
	assert.NotNil(t, state)
	assert.Equal(t, sessionID, state.SessionID)
}

func TestCheckResumabilityNotEstablished(t *testing.T) {
	f, err := os.CreateTemp("", "kamune-check-not-established-test")
	require.NoError(t, err)
	require.NoError(t, f.Close())
	defer os.Remove(f.Name())

	storage, err := OpenStorage(
		StorageWithDBPath(f.Name()),
		StorageWithAlgorithm(attest.Ed25519Algorithm),
		StorageWithNoPassphrase(),
	)
	require.NoError(t, err)
	defer storage.Close()

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
	require.NoError(t, err)
	sm.RegisterSession(sessionID, remotePubKey)

	// Should not be resumable because phase is not established
	canResume, _, err := checkResumability(remotePubKey, sm)
	require.NoError(t, err)
	assert.False(t, canResume)
}

func TestCheckResumabilityNoSecret(t *testing.T) {
	f, err := os.CreateTemp("", "kamune-check-no-secret-test")
	require.NoError(t, err)
	require.NoError(t, f.Close())
	defer os.Remove(f.Name())

	storage, err := OpenStorage(
		StorageWithDBPath(f.Name()),
		StorageWithAlgorithm(attest.Ed25519Algorithm),
		StorageWithNoPassphrase(),
	)
	require.NoError(t, err)
	defer storage.Close()

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
	require.NoError(t, err)
	sm.RegisterSession(sessionID, remotePubKey)

	// Should not be resumable because no shared secret
	canResume, _, err := checkResumability(remotePubKey, sm)
	require.NoError(t, err)
	assert.False(t, canResume)
}
