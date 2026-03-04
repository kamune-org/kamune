package kamune

import (
	"crypto/rand"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kamune-org/kamune/internal/box/pb"
	"github.com/kamune-org/kamune/pkg/attest"
)

// ---------------------------------------------------------------------------
// Test infrastructure
// ---------------------------------------------------------------------------

// testEnv bundles the shared infrastructure needed by resume integration tests.
type testEnv struct {
	storageA *Storage
	storageB *Storage
	smA      *SessionManager
	smB      *SessionManager
	attA     attest.Attester
	attB     attest.Attester
	cleanups []func()
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	e := &testEnv{}

	mkStorage := func(label string) *Storage {
		f, err := os.CreateTemp("", "kamune-resume-"+label+"-*.db")
		require.NoError(t, err)
		require.NoError(t, f.Close())
		e.cleanups = append(e.cleanups, func() { _ = os.Remove(f.Name()) })

		s, err := OpenStorage(
			StorageWithDBPath(f.Name()),
			StorageWithAlgorithm(attest.Ed25519Algorithm),
			StorageWithNoPassphrase(),
		)
		require.NoError(t, err)
		e.cleanups = append(e.cleanups, func() { _ = s.Close() })
		return s
	}

	e.storageA = mkStorage("a")
	e.storageB = mkStorage("b")

	var err error
	e.attA, err = attest.NewAttester(attest.Ed25519Algorithm)
	require.NoError(t, err)
	e.attB, err = attest.NewAttester(attest.Ed25519Algorithm)
	require.NoError(t, err)

	e.smA = NewSessionManager(e.storageA, 24*time.Hour)
	e.smB = NewSessionManager(e.storageB, 24*time.Hour)

	return e
}

func (e *testEnv) close() {
	for i := len(e.cleanups) - 1; i >= 0; i-- {
		e.cleanups[i]()
	}
}

// handshakePair performs a fresh handshake over a net.Pipe and returns both
// transports. tA is the initiator (client); tB is the responder (server).
func handshakePair(t *testing.T, e *testEnv) (*Transport, *Transport) {
	t.Helper()
	c1, c2 := net.Pipe()
	conn1, err := newConn(c1)
	require.NoError(t, err)
	conn2, err := newConn(c2)
	require.NoError(t, err)

	ut1 := newUnderlyingTransport(
		conn1, conn1, e.attB.PublicKey(), e.attA, e.storageA,
	)
	ut2 := newUnderlyingTransport(
		conn2, conn2, e.attA.PublicKey(), e.attB, e.storageB,
	)

	opts := handshakeOpts{
		remoteVerifier: func(_ *Storage, _ *Peer) error { return nil },
		timeout:        30 * time.Second,
	}

	var tA *Transport
	var hsErr error
	done := make(chan struct{})
	go func() {
		defer close(done)
		tA, hsErr = requestHandshake(ut1, opts)
	}()

	tB, err := acceptHandshake(ut2, opts)
	require.NoError(t, err)
	<-done
	require.NoError(t, hsErr)
	require.NotNil(t, tA)
	require.NotNil(t, tB)
	return tA, tB
}

// saveForResumption saves both sides of a session for future resumption.
func saveForResumption(t *testing.T, tA, tB *Transport, smA, smB *SessionManager) {
	t.Helper()
	require.NoError(t, SaveSessionForResumption(tA, smA))
	require.NoError(t, SaveSessionForResumption(tB, smB))
}

// loadClientState loads the persisted session state for the client side.
// Unlike Transport.State(), the loaded state includes CreatedAt/UpdatedAt
// timestamps that sessionAgeOK requires.
func loadClientState(t *testing.T, tA *Transport, smA *SessionManager) *SessionState {
	t.Helper()
	state, err := smA.LoadSession(tA.SessionID())
	require.NoError(t, err)
	return state
}

// doResumptionE2E performs client↔server resumption over a fresh net.Pipe,
// mirroring the real Server.serve → handleReconnection flow on the server side
// and Dialer.attemptResumption → InitiateResumption on the client side.
func doResumptionE2E(
	t *testing.T,
	e *testEnv,
	stateA *SessionState,
	maxAge time.Duration,
) (*Transport, *Transport) {
	t.Helper()

	if maxAge <= 0 {
		maxAge = 24 * time.Hour
	}

	c1, c2 := net.Pipe()
	connA, err := newConn(c1)
	require.NoError(t, err)
	connB, err := newConn(c2)
	require.NoError(t, err)

	resumerA := NewSessionResumer(e.storageA, e.smA, e.attA, maxAge)
	resumerB := NewSessionResumer(e.storageB, e.smB, e.attB, maxAge)

	type result struct {
		t   *Transport
		err error
	}

	clientCh := make(chan result, 1)
	serverCh := make(chan result, 1)

	// Client: InitiateResumption sends the reconnect request, then drives the
	// rest of the 4-message protocol.
	go func() {
		tr, err := resumerA.InitiateResumption(connA, stateA)
		if err != nil {
			// Close our end so the server goroutine unblocks from any
			// pending read on the other side of the pipe.
			_ = connA.Close()
		}
		clientCh <- result{tr, err}
	}()

	// Server: mirrors Server.serve → handleReconnection.
	//
	// The first wire message is a SignedTransport wrapping the (encrypted +
	// signed) ReconnectRequest. The server must:
	//   1. Read the outer SignedTransport.
	//   2. Look up the session using the client's public key to obtain the
	//      shared secret.
	//   3. Decrypt st.Data.
	//   4. Unmarshal the ReconnectRequest.
	//   5. Pass the request to HandleResumption which drives the rest of the
	//      protocol (response, verify, complete).
	go func() {
		st, route, err := readSignedTransport(connB)
		if err != nil {
			serverCh <- result{nil, err}
			return
		}
		if route != RouteReconnect {
			serverCh <- result{nil, ErrUnexpectedRoute}
			return
		}

		// Look up the session by the client's public key so we can decrypt.
		stateB, err := e.smB.LoadSessionByPublicKey(e.attA.PublicKey().Marshal())
		if err != nil {
			serverCh <- result{nil, err}
			return
		}

		// Decrypt st.Data in-place. We use the same per-direction label
		// (reconnectC2SInfo) that the client used to encrypt so that HKDF
		// derives the same symmetric key. The signature was computed over
		// the encrypted bytes; we skip re-verification here since the test
		// trusts the setup – production code verifies before calling
		// HandleResumption.
		if err := resumerB.decryptSignedTransport(
			stateB.SharedSecret, reconnectC2SInfo, st,
		); err != nil {
			serverCh <- result{nil, err}
			return
		}

		var req pb.ReconnectRequest
		if err := unmarshalMessage(st.Data, &req); err != nil {
			serverCh <- result{nil, err}
			return
		}

		tr, err := resumerB.HandleResumption(connB, &req)
		if err != nil {
			_ = connB.Close()
		}
		serverCh <- result{tr, err}
	}()

	clientRes := <-clientCh
	serverRes := <-serverCh

	if clientRes.err != nil || serverRes.err != nil {
		if clientRes.t != nil {
			_ = clientRes.t.Close()
		}
		if serverRes.t != nil {
			_ = serverRes.t.Close()
		}
		t.Fatalf("resumption failed: client=%v, server=%v",
			clientRes.err, serverRes.err)
	}

	return clientRes.t, serverRes.t
}

// exchangeMessages sends a message from sender to receiver and verifies it.
func exchangeMessages(
	t *testing.T,
	sender, receiver *Transport,
	payload []byte,
) {
	t.Helper()

	msg := Bytes(payload)
	var sendErr error
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, sendErr = sender.Send(msg, RouteExchangeMessages)
	}()

	recv := Bytes(nil)
	_, err := receiver.Receive(recv)
	require.NoError(t, err)
	<-done
	require.NoError(t, sendErr)
	require.Equal(t, payload, recv.Value)
}

// exchangeNMessages sends n messages alternating directions and verifies each.
func exchangeNMessages(t *testing.T, tA, tB *Transport, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		payload := make([]byte, 64)
		_, _ = rand.Read(payload)
		if i%2 == 0 {
			exchangeMessages(t, tA, tB, payload)
		} else {
			exchangeMessages(t, tB, tA, payload)
		}
	}
}

// ---------------------------------------------------------------------------
// End-to-end resumption tests
// ---------------------------------------------------------------------------

// TestResumeE2E_HandshakeThenResume performs a full handshake, saves state,
// disconnects, resumes, and verifies bidirectional messaging works.
func TestResumeE2E_HandshakeThenResume(t *testing.T) {
	e := newTestEnv(t)
	defer e.close()

	// Phase 1: fresh handshake.
	tA, tB := handshakePair(t, e)
	require.True(t, tA.IsEstablished())
	require.True(t, tB.IsEstablished())

	exchangeMessages(t, tA, tB, []byte("hello before save"))
	exchangeMessages(t, tB, tA, []byte("reply before save"))

	saveForResumption(t, tA, tB, e.smA, e.smB)
	stateA := loadClientState(t, tA, e.smA)
	require.Equal(t, PhaseEstablished, stateA.Phase)
	require.NotEmpty(t, stateA.SharedSecret)

	require.NoError(t, tA.Close())
	require.NoError(t, tB.Close())

	// Phase 2: resume.
	rA, rB := doResumptionE2E(t, e, stateA, 0)
	defer func() {
		_ = rA.Close()
		_ = rB.Close()
	}()

	require.True(t, rA.IsEstablished())
	require.True(t, rB.IsEstablished())
	require.Equal(t, stateA.SessionID, rA.SessionID())
	require.Equal(t, stateA.SessionID, rB.SessionID())

	exchangeMessages(t, rA, rB, []byte("hello after resume"))
	exchangeMessages(t, rB, rA, []byte("reply after resume"))
}

// TestResumeE2E_WithMessages exchanges messages before disconnect and verifies
// that sequence numbers are properly reconciled after resumption.
func TestResumeE2E_WithMessages(t *testing.T) {
	e := newTestEnv(t)
	defer e.close()

	tA, tB := handshakePair(t, e)

	exchangeNMessages(t, tA, tB, 10)

	saveForResumption(t, tA, tB, e.smA, e.smB)
	stateA := loadClientState(t, tA, e.smA)
	require.Greater(t, stateA.SendSequence, uint64(0))
	require.Greater(t, stateA.RecvSequence, uint64(0))

	require.NoError(t, tA.Close())
	require.NoError(t, tB.Close())

	rA, rB := doResumptionE2E(t, e, stateA, 0)
	defer func() {
		_ = rA.Close()
		_ = rB.Close()
	}()

	require.True(t, rA.IsEstablished())
	require.True(t, rB.IsEstablished())
	exchangeNMessages(t, rA, rB, 5)
}

// TestResumeE2E_MultipleResumptions verifies that a session can be resumed
// multiple times in succession.
func TestResumeE2E_MultipleResumptions(t *testing.T) {
	e := newTestEnv(t)
	defer e.close()

	tA, tB := handshakePair(t, e)
	exchangeMessages(t, tA, tB, []byte("round 0"))
	saveForResumption(t, tA, tB, e.smA, e.smB)
	stateA := loadClientState(t, tA, e.smA)
	_ = tA.Close()
	_ = tB.Close()

	for round := 1; round <= 3; round++ {
		rA, rB := doResumptionE2E(t, e, stateA, 0)
		require.True(t, rA.IsEstablished())

		payload := make([]byte, 32)
		_, _ = rand.Read(payload)
		exchangeMessages(t, rA, rB, payload)
		exchangeMessages(t, rB, rA, payload)

		saveForResumption(t, rA, rB, e.smA, e.smB)
		stateA = loadClientState(t, rA, e.smA)

		_ = rA.Close()
		_ = rB.Close()
	}
}

// TestResumeE2E_PreservesSessionID verifies the session ID survives resumption.
func TestResumeE2E_PreservesSessionID(t *testing.T) {
	e := newTestEnv(t)
	defer e.close()

	tA, tB := handshakePair(t, e)
	originalID := tA.SessionID()
	require.Equal(t, originalID, tB.SessionID())

	saveForResumption(t, tA, tB, e.smA, e.smB)
	stateA := loadClientState(t, tA, e.smA)
	_ = tA.Close()
	_ = tB.Close()

	rA, rB := doResumptionE2E(t, e, stateA, 0)
	defer func() {
		_ = rA.Close()
		_ = rB.Close()
	}()

	assert.Equal(t, originalID, rA.SessionID())
	assert.Equal(t, originalID, rB.SessionID())
}

// TestResumeE2E_InitiatorFlag verifies IsInitiator is preserved after resume.
func TestResumeE2E_InitiatorFlag(t *testing.T) {
	e := newTestEnv(t)
	defer e.close()

	tA, tB := handshakePair(t, e)
	saveForResumption(t, tA, tB, e.smA, e.smB)
	stateA := loadClientState(t, tA, e.smA)

	require.True(t, stateA.IsInitiator)
	require.False(t, tB.State().IsInitiator)

	_ = tA.Close()
	_ = tB.Close()

	rA, rB := doResumptionE2E(t, e, stateA, 0)
	defer func() {
		_ = rA.Close()
		_ = rB.Close()
	}()

	assert.True(t, rA.State().IsInitiator)
	assert.False(t, rB.State().IsInitiator)
}

// TestResumeE2E_LargePayloadAfterResume verifies large messages work after
// resumption.
func TestResumeE2E_LargePayloadAfterResume(t *testing.T) {
	e := newTestEnv(t)
	defer e.close()

	tA, tB := handshakePair(t, e)
	saveForResumption(t, tA, tB, e.smA, e.smB)
	stateA := loadClientState(t, tA, e.smA)
	_ = tA.Close()
	_ = tB.Close()

	rA, rB := doResumptionE2E(t, e, stateA, 0)
	defer func() {
		_ = rA.Close()
		_ = rB.Close()
	}()

	payload := make([]byte, 4096)
	_, _ = rand.Read(payload)
	exchangeMessages(t, rA, rB, payload)
	exchangeMessages(t, rB, rA, payload)
}

// TestResumeE2E_MessageIntegrity sends multiple distinct messages after
// resumption and checks for content corruption.
func TestResumeE2E_MessageIntegrity(t *testing.T) {
	e := newTestEnv(t)
	defer e.close()

	tA, tB := handshakePair(t, e)
	saveForResumption(t, tA, tB, e.smA, e.smB)
	stateA := loadClientState(t, tA, e.smA)
	_ = tA.Close()
	_ = tB.Close()

	rA, rB := doResumptionE2E(t, e, stateA, 0)
	defer func() {
		_ = rA.Close()
		_ = rB.Close()
	}()

	messages := []string{
		"The quick brown fox jumps over the lazy dog",
		"Hello, 世界! 🌍",
		string(make([]byte, 1)), // single null byte
	}
	for _, m := range messages {
		exchangeMessages(t, rA, rB, []byte(m))
	}
}

// ---------------------------------------------------------------------------
// Session age enforcement
// ---------------------------------------------------------------------------

// TestResume_SessionAgeEnforcement verifies old sessions are rejected.
func TestResume_SessionAgeEnforcement(t *testing.T) {
	e := newTestEnv(t)
	defer e.close()

	resumer := NewSessionResumer(e.storageA, e.smA, e.attA, 1*time.Millisecond)

	oldTime := time.Now().Add(-1 * time.Hour)
	state := &SessionState{
		SessionID:    "old-session",
		Phase:        PhaseEstablished,
		SharedSecret: []byte("secret"),
		CreatedAt:    oldTime,
		UpdatedAt:    oldTime,
	}

	assert.ErrorIs(t, resumer.sessionAgeOK(state), ErrSessionTooOld)
}

// TestResume_SessionAgeZeroTimestamps verifies zero timestamps fail closed.
func TestResume_SessionAgeZeroTimestamps(t *testing.T) {
	e := newTestEnv(t)
	defer e.close()

	resumer := NewSessionResumer(e.storageA, e.smA, e.attA, 1*time.Hour)

	state := &SessionState{
		SessionID:    "zero-ts-session",
		Phase:        PhaseEstablished,
		SharedSecret: []byte("secret"),
	}

	assert.ErrorIs(t, resumer.sessionAgeOK(state), ErrSessionTooOld)
}

// TestResume_SessionAgeFreshIsOK verifies fresh sessions pass.
func TestResume_SessionAgeFreshIsOK(t *testing.T) {
	e := newTestEnv(t)
	defer e.close()

	resumer := NewSessionResumer(e.storageA, e.smA, e.attA, 24*time.Hour)

	state := &SessionState{
		SessionID:    "fresh-session",
		Phase:        PhaseEstablished,
		SharedSecret: []byte("secret"),
		UpdatedAt:    time.Now(),
		CreatedAt:    time.Now().Add(-1 * time.Hour),
	}

	assert.NoError(t, resumer.sessionAgeOK(state))
}

// TestResume_SessionAgeDisabled verifies zero maxSessionAge disables the check.
func TestResume_SessionAgeDisabled(t *testing.T) {
	e := newTestEnv(t)
	defer e.close()

	// NewSessionResumer clamps <=0 to 24h, so build directly.
	resumer := &SessionResumer{
		storage:        e.storageA,
		sessionManager: e.smA,
		attester:       e.attA,
		maxSessionAge:  0,
	}

	state := &SessionState{
		SessionID:    "old-but-ok",
		Phase:        PhaseEstablished,
		SharedSecret: []byte("secret"),
	}

	assert.NoError(t, resumer.sessionAgeOK(state))
}

// TestResume_SessionAgeNilState verifies nil state is rejected.
func TestResume_SessionAgeNilState(t *testing.T) {
	e := newTestEnv(t)
	defer e.close()

	resumer := NewSessionResumer(e.storageA, e.smA, e.attA, 1*time.Hour)
	assert.ErrorIs(t, resumer.sessionAgeOK(nil), ErrSessionTooOld)
}

// TestResume_SessionAgePrefersUpdatedAt verifies UpdatedAt takes precedence.
func TestResume_SessionAgePrefersUpdatedAt(t *testing.T) {
	e := newTestEnv(t)
	defer e.close()

	resumer := NewSessionResumer(e.storageA, e.smA, e.attA, 1*time.Hour)

	// CreatedAt old, UpdatedAt fresh → pass.
	state := &SessionState{
		SessionID:    "t1",
		Phase:        PhaseEstablished,
		SharedSecret: []byte("s"),
		CreatedAt:    time.Now().Add(-2 * time.Hour),
		UpdatedAt:    time.Now(),
	}
	assert.NoError(t, resumer.sessionAgeOK(state))

	// UpdatedAt old → fail even with fresh CreatedAt.
	state2 := &SessionState{
		SessionID:    "t2",
		Phase:        PhaseEstablished,
		SharedSecret: []byte("s"),
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now().Add(-2 * time.Hour),
	}
	assert.ErrorIs(t, resumer.sessionAgeOK(state2), ErrSessionTooOld)
}

// TestResume_SessionAgeFallsBackToCreatedAt verifies that when UpdatedAt is
// zero, CreatedAt is used.
func TestResume_SessionAgeFallsBackToCreatedAt(t *testing.T) {
	e := newTestEnv(t)
	defer e.close()

	resumer := NewSessionResumer(e.storageA, e.smA, e.attA, 1*time.Hour)

	// Zero UpdatedAt, fresh CreatedAt → pass.
	state := &SessionState{
		SessionID:    "t1",
		Phase:        PhaseEstablished,
		SharedSecret: []byte("s"),
		CreatedAt:    time.Now(),
	}
	assert.NoError(t, resumer.sessionAgeOK(state))

	// Zero UpdatedAt, old CreatedAt → fail.
	state2 := &SessionState{
		SessionID:    "t2",
		Phase:        PhaseEstablished,
		SharedSecret: []byte("s"),
		CreatedAt:    time.Now().Add(-2 * time.Hour),
	}
	assert.ErrorIs(t, resumer.sessionAgeOK(state2), ErrSessionTooOld)
}

// ---------------------------------------------------------------------------
// CanResume
// ---------------------------------------------------------------------------

// TestResume_CanResumeAfterHandshake verifies CanResume returns true after a
// completed handshake and save.
func TestResume_CanResumeAfterHandshake(t *testing.T) {
	e := newTestEnv(t)
	defer e.close()

	tA, tB := handshakePair(t, e)
	saveForResumption(t, tA, tB, e.smA, e.smB)

	// Client side.
	resumerA := NewSessionResumer(e.storageA, e.smA, e.attA, 24*time.Hour)
	canResume, state, err := resumerA.CanResume(e.attB.PublicKey().Marshal())
	require.NoError(t, err)
	assert.True(t, canResume)
	assert.NotNil(t, state)
	assert.Equal(t, tA.SessionID(), state.SessionID)
	assert.Equal(t, PhaseEstablished, state.Phase)

	// Server side.
	resumerB := NewSessionResumer(e.storageB, e.smB, e.attB, 24*time.Hour)
	canResume, state, err = resumerB.CanResume(e.attA.PublicKey().Marshal())
	require.NoError(t, err)
	assert.True(t, canResume)
	assert.NotNil(t, state)
	assert.Equal(t, tB.SessionID(), state.SessionID)

	_ = tA.Close()
	_ = tB.Close()
}

// TestResume_CanResumeUnknownPeer verifies CanResume returns false for unknown
// peers.
func TestResume_CanResumeUnknownPeer(t *testing.T) {
	e := newTestEnv(t)
	defer e.close()

	resumer := NewSessionResumer(e.storageA, e.smA, e.attA, 24*time.Hour)
	canResume, state, err := resumer.CanResume([]byte("nonexistent"))
	require.NoError(t, err)
	assert.False(t, canResume)
	assert.Nil(t, state)
}

// TestResume_CanResumeAfterSequenceUpdate verifies that a session remains
// resumable after message exchanges.
func TestResume_CanResumeAfterSequenceUpdate(t *testing.T) {
	e := newTestEnv(t)
	defer e.close()

	tA, tB := handshakePair(t, e)
	exchangeNMessages(t, tA, tB, 20)
	saveForResumption(t, tA, tB, e.smA, e.smB)

	stateA := tA.State()
	assert.Greater(t, stateA.SendSequence, uint64(0))
	assert.Greater(t, stateA.RecvSequence, uint64(0))

	resumerA := NewSessionResumer(e.storageA, e.smA, e.attA, 24*time.Hour)
	canResume, state, err := resumerA.CanResume(e.attB.PublicKey().Marshal())
	require.NoError(t, err)
	assert.True(t, canResume)
	assert.Equal(t, stateA.SessionID, state.SessionID)

	_ = tA.Close()
	_ = tB.Close()
}

// ---------------------------------------------------------------------------
// Challenge response
// ---------------------------------------------------------------------------

// TestResume_ChallengeResponseDeterminism verifies determinism and domain
// separation of the challenge-response function.
func TestResume_ChallengeResponseDeterminism(t *testing.T) {
	e := newTestEnv(t)
	defer e.close()

	resumer := NewSessionResumer(e.storageA, e.smA, e.attA, 24*time.Hour)

	challenge := make([]byte, resumeChallengeSize)
	_, _ = rand.Read(challenge)
	secret := make([]byte, 32)
	_, _ = rand.Read(secret)

	r1, err := resumer.computeChallengeResponse(challenge, secret)
	require.NoError(t, err)
	r2, err := resumer.computeChallengeResponse(challenge, secret)
	require.NoError(t, err)
	assert.Equal(t, r1, r2, "same inputs → same output")

	// Different challenge.
	other := make([]byte, resumeChallengeSize)
	_, _ = rand.Read(other)
	r3, err := resumer.computeChallengeResponse(other, secret)
	require.NoError(t, err)
	assert.NotEqual(t, r1, r3)

	// Different secret.
	otherSecret := make([]byte, 32)
	_, _ = rand.Read(otherSecret)
	r4, err := resumer.computeChallengeResponse(challenge, otherSecret)
	require.NoError(t, err)
	assert.NotEqual(t, r1, r4)
}

// ---------------------------------------------------------------------------
// Sequence reconciliation
// ---------------------------------------------------------------------------

// TestResume_ReconcileSequences_TableDriven covers a comprehensive set of
// sequence drift scenarios.
func TestResume_ReconcileSequences_TableDriven(t *testing.T) {
	e := newTestEnv(t)
	defer e.close()

	resumer := NewSessionResumer(e.storageA, e.smA, e.attA, 24*time.Hour)

	tests := []struct {
		name                       string
		localSend, localRecv       uint64
		remoteSend, remoteRecv     uint64
		expectedSend, expectedRecv uint64
	}{
		{
			name:      "perfectly in sync",
			localSend: 42, localRecv: 42,
			remoteSend: 42, remoteRecv: 42,
			expectedSend: 42, expectedRecv: 42,
		},
		{
			name:      "zero sequences",
			localSend: 0, localRecv: 0,
			remoteSend: 0, remoteRecv: 0,
			expectedSend: 0, expectedRecv: 0,
		},
		{
			name:      "client sent more than server received",
			localSend: 50, localRecv: 30,
			remoteSend: 30, remoteRecv: 40,
			expectedSend: 50, expectedRecv: 30,
		},
		{
			name:      "server sent more than client received",
			localSend: 30, localRecv: 30,
			remoteSend: 50, remoteRecv: 30,
			expectedSend: 30, expectedRecv: 50,
		},
		{
			name:      "both drifted",
			localSend: 100, localRecv: 80,
			remoteSend: 90, remoteRecv: 95,
			expectedSend: 100, expectedRecv: 90,
		},
		{
			name:      "remote received everything we sent plus extra",
			localSend: 10, localRecv: 10,
			remoteSend: 10, remoteRecv: 20,
			expectedSend: 20, expectedRecv: 10,
		},
		{
			name:      "large sequence numbers",
			localSend: 1_000_000, localRecv: 999_999,
			remoteSend: 999_998, remoteRecv: 1_000_000,
			expectedSend: 1_000_000, expectedRecv: 999_999,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			send, recv := resumer.reconcileSequences(
				tt.localSend, tt.localRecv,
				tt.remoteSend, tt.remoteRecv,
			)
			assert.Equal(t, tt.expectedSend, send, "send sequence")
			assert.Equal(t, tt.expectedRecv, recv, "recv sequence")
		})
	}
}

// ---------------------------------------------------------------------------
// Encrypt / decrypt signed transport
// ---------------------------------------------------------------------------

// TestResume_EncryptDecryptSymmetry verifies round-trip encryption.
func TestResume_EncryptDecryptSymmetry(t *testing.T) {
	e := newTestEnv(t)
	defer e.close()

	resumer := NewSessionResumer(e.storageA, e.smA, e.attA, 24*time.Hour)
	secret := make([]byte, 32)
	_, _ = rand.Read(secret)

	original := []byte("sensitive reconnect payload data")
	st := &pb.SignedTransport{Data: make([]byte, len(original))}
	copy(st.Data, original)

	require.NoError(t, resumer.encryptSignedTransport(secret, reconnectC2SInfo, st))
	assert.NotEqual(t, original, st.Data)

	require.NoError(t, resumer.decryptSignedTransport(secret, reconnectC2SInfo, st))
	assert.Equal(t, original, st.Data)
}

// TestResume_EncryptDecryptWrongSecret verifies decryption with wrong key fails.
func TestResume_EncryptDecryptWrongSecret(t *testing.T) {
	e := newTestEnv(t)
	defer e.close()

	resumer := NewSessionResumer(e.storageA, e.smA, e.attA, 24*time.Hour)
	s1 := make([]byte, 32)
	s2 := make([]byte, 32)
	_, _ = rand.Read(s1)
	_, _ = rand.Read(s2)

	st := &pb.SignedTransport{Data: []byte("secret data")}
	require.NoError(t, resumer.encryptSignedTransport(s1, reconnectC2SInfo, st))
	assert.Error(t, resumer.decryptSignedTransport(s2, reconnectC2SInfo, st))
}

// TestResume_EncryptDecryptDirectionSeparation verifies direction labels are
// domain-separated.
func TestResume_EncryptDecryptDirectionSeparation(t *testing.T) {
	e := newTestEnv(t)
	defer e.close()

	resumer := NewSessionResumer(e.storageA, e.smA, e.attA, 24*time.Hour)
	secret := make([]byte, 32)
	_, _ = rand.Read(secret)

	st := &pb.SignedTransport{Data: []byte("directional data")}
	require.NoError(t, resumer.encryptSignedTransport(secret, reconnectC2SInfo, st))
	assert.Error(t, resumer.decryptSignedTransport(secret, reconnectS2CInfo, st))
}

// TestResume_EncryptNilTransport verifies nil transport returns error.
func TestResume_EncryptNilTransport(t *testing.T) {
	e := newTestEnv(t)
	defer e.close()

	resumer := NewSessionResumer(e.storageA, e.smA, e.attA, 24*time.Hour)
	secret := make([]byte, 32)

	assert.Error(t, resumer.encryptSignedTransport(secret, reconnectC2SInfo, nil))
	assert.Error(t, resumer.decryptSignedTransport(secret, reconnectC2SInfo, nil))
}

// TestResume_EncryptEmptyData verifies empty data is a no-op.
func TestResume_EncryptEmptyData(t *testing.T) {
	e := newTestEnv(t)
	defer e.close()

	resumer := NewSessionResumer(e.storageA, e.smA, e.attA, 24*time.Hour)
	secret := make([]byte, 32)

	st := &pb.SignedTransport{Data: nil}
	assert.NoError(t, resumer.encryptSignedTransport(secret, reconnectC2SInfo, st))
	assert.Nil(t, st.Data)

	st2 := &pb.SignedTransport{Data: []byte{}}
	assert.NoError(t, resumer.encryptSignedTransport(secret, reconnectC2SInfo, st2))
}

// ---------------------------------------------------------------------------
// Session save / load
// ---------------------------------------------------------------------------

// TestResume_SaveAndLoadRoundTrip verifies that save → load produces
// equivalent session state.
func TestResume_SaveAndLoadRoundTrip(t *testing.T) {
	e := newTestEnv(t)
	defer e.close()

	tA, tB := handshakePair(t, e)
	defer func() {
		_ = tA.Close()
		_ = tB.Close()
	}()

	exchangeNMessages(t, tA, tB, 5)
	require.NoError(t, SaveSessionForResumption(tA, e.smA))
	stateA := tA.State()

	loaded, err := e.smA.LoadSession(stateA.SessionID)
	require.NoError(t, err)

	assert.Equal(t, stateA.SessionID, loaded.SessionID)
	assert.Equal(t, stateA.Phase, loaded.Phase)
	assert.Equal(t, stateA.IsInitiator, loaded.IsInitiator)
	assert.Equal(t, stateA.SendSequence, loaded.SendSequence)
	assert.Equal(t, stateA.RecvSequence, loaded.RecvSequence)
	assert.Equal(t, stateA.SharedSecret, loaded.SharedSecret)
	assert.Equal(t, stateA.LocalSalt, loaded.LocalSalt)
	assert.Equal(t, stateA.RemoteSalt, loaded.RemoteSalt)
	assert.Equal(t, stateA.RemotePublicKey, loaded.RemotePublicKey)
}

// TestResume_SaveNotEstablished verifies saving a non-established session fails.
func TestResume_SaveNotEstablished(t *testing.T) {
	e := newTestEnv(t)
	defer e.close()

	tA, tB := handshakePair(t, e)
	defer func() {
		_ = tA.Close()
		_ = tB.Close()
	}()

	tA.SetPhase(PhaseHandshakeAccepted)
	assert.ErrorIs(t, SaveSessionForResumption(tA, e.smA), ErrSessionNotResumable)
}

// ---------------------------------------------------------------------------
// HandleResumption rejection cases
// ---------------------------------------------------------------------------

// TestResume_HandleResumption_SessionMismatch verifies rejection when the
// request carries the wrong session ID.
func TestResume_HandleResumption_SessionMismatch(t *testing.T) {
	e := newTestEnv(t)
	defer e.close()

	tA, tB := handshakePair(t, e)
	saveForResumption(t, tA, tB, e.smA, e.smB)
	_ = tA.Close()
	_ = tB.Close()

	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	connB, err := newConn(c2)
	require.NoError(t, err)

	resumerB := NewSessionResumer(e.storageB, e.smB, e.attB, 24*time.Hour)

	req := &pb.ReconnectRequest{
		SessionId:       "wrong-session-id",
		LastPhase:       PhaseEstablished.ToProto(),
		RemotePublicKey: e.attA.PublicKey().Marshal(),
		ResumeChallenge: make([]byte, resumeChallengeSize),
	}

	done := make(chan error, 1)
	go func() {
		_, err := resumerB.HandleResumption(connB, req)
		done <- err
	}()

	// Drain the reject response so the server goroutine doesn't block.
	connA, err := newConn(c1)
	require.NoError(t, err)
	_, _ = connA.ReadBytes()

	assert.Error(t, <-done)
}

// TestResume_HandleResumption_NotEstablished verifies rejection for a session
// in a non-established phase.
func TestResume_HandleResumption_NotEstablished(t *testing.T) {
	e := newTestEnv(t)
	defer e.close()

	tA, tB := handshakePair(t, e)
	saveForResumption(t, tA, tB, e.smA, e.smB)

	// Force server-side session to non-established phase.
	stateB := tB.State()
	stateB.Phase = PhaseHandshakeRequested
	require.NoError(t, e.smB.SaveSession(stateB))

	_ = tA.Close()
	_ = tB.Close()

	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	connB, err := newConn(c2)
	require.NoError(t, err)

	resumerB := NewSessionResumer(e.storageB, e.smB, e.attB, 24*time.Hour)

	req := &pb.ReconnectRequest{
		SessionId:       stateB.SessionID,
		LastPhase:       PhaseEstablished.ToProto(),
		RemotePublicKey: e.attA.PublicKey().Marshal(),
		ResumeChallenge: make([]byte, resumeChallengeSize),
	}

	done := make(chan error, 1)
	go func() {
		_, err := resumerB.HandleResumption(connB, req)
		done <- err
	}()

	connA, err := newConn(c1)
	require.NoError(t, err)
	_, _ = connA.ReadBytes()

	assert.ErrorIs(t, <-done, ErrResumptionNotSupported)
}

// TestResume_HandleResumption_UnknownPeer verifies rejection for unknown peers.
func TestResume_HandleResumption_UnknownPeer(t *testing.T) {
	e := newTestEnv(t)
	defer e.close()

	unknownAtt, err := attest.NewAttester(attest.Ed25519Algorithm)
	require.NoError(t, err)

	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	connB, err := newConn(c2)
	require.NoError(t, err)

	resumerB := NewSessionResumer(e.storageB, e.smB, e.attB, 24*time.Hour)

	req := &pb.ReconnectRequest{
		SessionId:       "nonexistent-session",
		LastPhase:       PhaseEstablished.ToProto(),
		RemotePublicKey: unknownAtt.PublicKey().Marshal(),
		ResumeChallenge: make([]byte, resumeChallengeSize),
	}

	done := make(chan error, 1)
	go func() {
		_, err := resumerB.HandleResumption(connB, req)
		done <- err
	}()

	connA, err := newConn(c1)
	require.NoError(t, err)
	_, _ = connA.ReadBytes()

	assert.Error(t, <-done)
}

// TestResume_HandleResumption_ExpiredSession verifies rejection of expired
// sessions.
func TestResume_HandleResumption_ExpiredSession(t *testing.T) {
	e := newTestEnv(t)
	defer e.close()

	tA, tB := handshakePair(t, e)
	saveForResumption(t, tA, tB, e.smA, e.smB)
	stateB := tB.State()
	_ = tA.Close()
	_ = tB.Close()

	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	connB, err := newConn(c2)
	require.NoError(t, err)

	// Very short max age so the session expires immediately.
	resumerB := NewSessionResumer(e.storageB, e.smB, e.attB, 1*time.Nanosecond)
	time.Sleep(10 * time.Millisecond)

	req := &pb.ReconnectRequest{
		SessionId:       stateB.SessionID,
		LastPhase:       PhaseEstablished.ToProto(),
		RemotePublicKey: e.attA.PublicKey().Marshal(),
		ResumeChallenge: make([]byte, resumeChallengeSize),
	}

	done := make(chan error, 1)
	go func() {
		_, err := resumerB.HandleResumption(connB, req)
		done <- err
	}()

	connA, err := newConn(c1)
	require.NoError(t, err)
	_, _ = connA.ReadBytes()

	assert.ErrorIs(t, <-done, ErrSessionTooOld)
}

// ---------------------------------------------------------------------------
// restoreTransport
// ---------------------------------------------------------------------------

// TestResume_RestoreTransportBidirectional verifies that restoreTransport
// creates transports that can exchange messages in both directions.
func TestResume_RestoreTransportBidirectional(t *testing.T) {
	e := newTestEnv(t)
	defer e.close()

	tA, tB := handshakePair(t, e)
	saveForResumption(t, tA, tB, e.smA, e.smB)
	stateA := tA.State()
	stateB := tB.State()
	_ = tA.Close()
	_ = tB.Close()

	c1, c2 := net.Pipe()
	connA, err := newConn(c1)
	require.NoError(t, err)
	connB, err := newConn(c2)
	require.NoError(t, err)

	resumerA := NewSessionResumer(e.storageA, e.smA, e.attA, 24*time.Hour)
	resumerB := NewSessionResumer(e.storageB, e.smB, e.attB, 24*time.Hour)

	rA, err := resumerA.restoreTransport(connA, stateA, 0, 0)
	require.NoError(t, err)
	rB, err := resumerB.restoreTransport(connB, stateB, 0, 0)
	require.NoError(t, err)
	defer func() {
		_ = rA.Close()
		_ = rB.Close()
	}()

	exchangeMessages(t, rA, rB, []byte("restored A→B"))
	exchangeMessages(t, rB, rA, []byte("restored B→A"))
}

// TestResume_RestoreTransportSequences verifies that restored transports use
// the specified sequence numbers.
func TestResume_RestoreTransportSequences(t *testing.T) {
	e := newTestEnv(t)
	defer e.close()

	tA, tB := handshakePair(t, e)
	exchangeNMessages(t, tA, tB, 10)
	saveForResumption(t, tA, tB, e.smA, e.smB)
	stateA := tA.State()
	stateB := tB.State()
	_ = tA.Close()
	_ = tB.Close()

	c1, c2 := net.Pipe()
	connA, err := newConn(c1)
	require.NoError(t, err)
	connB, err := newConn(c2)
	require.NoError(t, err)

	resumerA := NewSessionResumer(e.storageA, e.smA, e.attA, 24*time.Hour)
	resumerB := NewSessionResumer(e.storageB, e.smB, e.attB, 24*time.Hour)

	rA, err := resumerA.restoreTransport(connA, stateA, stateA.SendSequence, stateA.RecvSequence)
	require.NoError(t, err)
	rB, err := resumerB.restoreTransport(connB, stateB, stateB.SendSequence, stateB.RecvSequence)
	require.NoError(t, err)
	defer func() {
		_ = rA.Close()
		_ = rB.Close()
	}()

	restoredA := rA.State()
	assert.Equal(t, stateA.SendSequence, restoredA.SendSequence)
	assert.Equal(t, stateA.RecvSequence, restoredA.RecvSequence)

	exchangeMessages(t, rA, rB, []byte("post-restore"))
}

// ---------------------------------------------------------------------------
// Signed message round-trip
// ---------------------------------------------------------------------------

// TestResume_SendSignedMessageRoundTrip tests plain signed message exchange.
func TestResume_SendSignedMessageRoundTrip(t *testing.T) {
	e := newTestEnv(t)
	defer e.close()

	c1, c2 := net.Pipe()
	connA, err := newConn(c1)
	require.NoError(t, err)
	connB, err := newConn(c2)
	require.NoError(t, err)
	defer func() {
		_ = connA.Close()
		_ = connB.Close()
	}()

	resumerA := NewSessionResumer(e.storageA, e.smA, e.attA, 24*time.Hour)
	resumerB := NewSessionResumer(e.storageB, e.smB, e.attB, 24*time.Hour)

	resp := &pb.ReconnectResponse{Accepted: true}

	var wg sync.WaitGroup
	var sendErr, recvErr error

	wg.Add(1)
	go func() {
		defer wg.Done()
		sendErr = resumerA.sendSignedMessage(connA, resp, RouteReconnect)
	}()

	var received pb.ReconnectResponse
	var route Route
	wg.Add(1)
	go func() {
		defer wg.Done()
		route, recvErr = resumerB.receiveSignedMessage(
			connB, &received, e.attA.PublicKey().Marshal(),
		)
	}()

	wg.Wait()
	require.NoError(t, sendErr)
	require.NoError(t, recvErr)
	assert.Equal(t, RouteReconnect, route)
	assert.True(t, received.Accepted)
}

// TestResume_SendSignedMessageWrongKey verifies that signature verification
// with the wrong key fails.
func TestResume_SendSignedMessageWrongKey(t *testing.T) {
	e := newTestEnv(t)
	defer e.close()

	c1, c2 := net.Pipe()
	connA, err := newConn(c1)
	require.NoError(t, err)
	connB, err := newConn(c2)
	require.NoError(t, err)
	defer func() {
		_ = connA.Close()
		_ = connB.Close()
	}()

	resumerA := NewSessionResumer(e.storageA, e.smA, e.attA, 24*time.Hour)
	resumerB := NewSessionResumer(e.storageB, e.smB, e.attB, 24*time.Hour)

	attC, err := attest.NewAttester(attest.Ed25519Algorithm)
	require.NoError(t, err)

	resp := &pb.ReconnectResponse{Accepted: true}

	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = resumerA.sendSignedMessage(connA, resp, RouteReconnect)
	}()

	var received pb.ReconnectResponse
	_, err = resumerB.receiveSignedMessage(
		connB, &received, attC.PublicKey().Marshal(),
	)
	<-done
	assert.ErrorIs(t, err, ErrInvalidSignature)
}

// TestResume_SendReceiveSignedWithSecret tests the encrypted+signed round-trip
// used in the resumption protocol.
func TestResume_SendReceiveSignedWithSecret(t *testing.T) {
	e := newTestEnv(t)
	defer e.close()

	c1, c2 := net.Pipe()
	connA, err := newConn(c1)
	require.NoError(t, err)
	connB, err := newConn(c2)
	require.NoError(t, err)
	defer func() {
		_ = connA.Close()
		_ = connB.Close()
	}()

	secret := make([]byte, 32)
	_, _ = rand.Read(secret)

	resumerA := NewSessionResumer(e.storageA, e.smA, e.attA, 24*time.Hour)
	resumerB := NewSessionResumer(e.storageB, e.smB, e.attB, 24*time.Hour)

	resp := &pb.ReconnectResponse{
		Accepted:        true,
		ServerChallenge: []byte("test-challenge"),
	}

	var wg sync.WaitGroup
	var sendErr, recvErr error

	wg.Add(1)
	go func() {
		defer wg.Done()
		sendErr = resumerA.sendSignedMessageWithSecret(
			connA, secret, reconnectS2CInfo, resp, RouteReconnect,
		)
	}()

	var received pb.ReconnectResponse
	var route Route
	wg.Add(1)
	go func() {
		defer wg.Done()
		route, recvErr = resumerB.receiveSignedMessageWithSecret(
			connB, secret, reconnectS2CInfo, &received,
			e.attA.PublicKey().Marshal(),
		)
	}()

	wg.Wait()
	require.NoError(t, sendErr)
	require.NoError(t, recvErr)
	assert.Equal(t, RouteReconnect, route)
	assert.True(t, received.Accepted)
	assert.Equal(t, []byte("test-challenge"), received.ServerChallenge)
}

// ---------------------------------------------------------------------------
// Reject response
// ---------------------------------------------------------------------------

// TestResume_SendRejectResponse verifies that sendRejectResponse sends a
// properly-formed rejection.
func TestResume_SendRejectResponse(t *testing.T) {
	e := newTestEnv(t)
	defer e.close()

	c1, c2 := net.Pipe()
	connA, err := newConn(c1)
	require.NoError(t, err)
	connB, err := newConn(c2)
	require.NoError(t, err)
	defer func() {
		_ = connA.Close()
		_ = connB.Close()
	}()

	resumerB := NewSessionResumer(e.storageB, e.smB, e.attB, 24*time.Hour)
	resumerA := NewSessionResumer(e.storageA, e.smA, e.attA, 24*time.Hour)

	done := make(chan error, 1)
	go func() {
		done <- resumerB.sendRejectResponse(connB, "test rejection")
	}()

	var resp pb.ReconnectResponse
	route, err := resumerA.receiveSignedMessage(
		connA, &resp, e.attB.PublicKey().Marshal(),
	)
	require.NoError(t, err)
	assert.Equal(t, RouteReconnect, route)
	assert.False(t, resp.Accepted)
	assert.Equal(t, "test rejection", resp.ErrorMessage)

	require.NoError(t, <-done)
}

// ---------------------------------------------------------------------------
// checkResumability with various states
// ---------------------------------------------------------------------------

// TestResume_CheckResumabilityStates tests checkResumability with every
// relevant session phase.
func TestResume_CheckResumabilityStates(t *testing.T) {
	e := newTestEnv(t)
	defer e.close()

	tests := []struct {
		name      string
		phase     SessionPhase
		secret    []byte
		canResume bool
	}{
		{"established with secret", PhaseEstablished, []byte("secret"), true},
		{"established no secret", PhaseEstablished, nil, false},
		{"established empty secret", PhaseEstablished, []byte{}, false},
		{"handshake requested", PhaseHandshakeRequested, []byte("s"), false},
		{"handshake accepted", PhaseHandshakeAccepted, []byte("s"), false},
		{"challenge sent", PhaseChallengeSent, []byte("s"), false},
		{"challenge verified", PhaseChallengeVerified, []byte("s"), false},
		{"closed", PhaseClosed, []byte("s"), false},
	}

	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Use unique keys so tests don't collide.
			pubKey := make([]byte, 32)
			pubKey[0] = byte(i)
			_, _ = rand.Read(pubKey[1:])
			sessionID := rand.Text()

			state := &SessionState{
				SessionID:       sessionID,
				Phase:           tt.phase,
				SharedSecret:    tt.secret,
				RemotePublicKey: pubKey,
			}

			require.NoError(t, e.smA.SaveSession(state))
			e.smA.RegisterSession(sessionID, pubKey)

			canResume, _, err := checkResumability(pubKey, e.smA)
			require.NoError(t, err)
			assert.Equal(t, tt.canResume, canResume, "phase=%s", tt.phase)
		})
	}
}

// ---------------------------------------------------------------------------
// connWrapper
// ---------------------------------------------------------------------------

// TestResume_ConnWrapperSatisfiesInterface verifies compile-time interface
// conformance.
func TestResume_ConnWrapperSatisfiesInterface(t *testing.T) {
	c1, _ := net.Pipe()
	defer c1.Close()

	cn, err := newConn(c1)
	require.NoError(t, err)

	wrapper := &connWrapper{Conn: cn}
	var _ Conn = wrapper // compile-time check
	assert.NotNil(t, wrapper)
}

// ---------------------------------------------------------------------------
// Session manager registration
// ---------------------------------------------------------------------------

// TestResume_SessionManagerRegistration verifies register / unregister.
func TestResume_SessionManagerRegistration(t *testing.T) {
	e := newTestEnv(t)
	defer e.close()

	tA, tB := handshakePair(t, e)
	saveForResumption(t, tA, tB, e.smA, e.smB)

	pubKeyB := e.attB.PublicKey().Marshal()
	pubKeyA := e.attA.PublicKey().Marshal()

	sessionID, ok := e.smA.GetSessionByPublicKey(pubKeyB)
	assert.True(t, ok)
	assert.Equal(t, tA.SessionID(), sessionID)

	sessionID, ok = e.smB.GetSessionByPublicKey(pubKeyA)
	assert.True(t, ok)
	assert.Equal(t, tB.SessionID(), sessionID)

	e.smA.UnregisterSession(pubKeyB)
	_, ok = e.smA.GetSessionByPublicKey(pubKeyB)
	assert.False(t, ok)

	_ = tA.Close()
	_ = tB.Close()
}

// ---------------------------------------------------------------------------
// Concurrency safety
// ---------------------------------------------------------------------------

// TestResume_ConcurrentCanResume verifies CanResume is safe under concurrent
// access.
func TestResume_ConcurrentCanResume(t *testing.T) {
	e := newTestEnv(t)
	defer e.close()

	tA, tB := handshakePair(t, e)
	saveForResumption(t, tA, tB, e.smA, e.smB)
	defer func() {
		_ = tA.Close()
		_ = tB.Close()
	}()

	resumer := NewSessionResumer(e.storageA, e.smA, e.attA, 24*time.Hour)
	pubKeyB := e.attB.PublicKey().Marshal()

	const goroutines = 20
	var wg sync.WaitGroup
	errs := make(chan error, goroutines)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			canResume, state, err := resumer.CanResume(pubKeyB)
			if err != nil {
				errs <- err
				return
			}
			if !canResume || state == nil {
				errs <- assert.AnError
				return
			}
		}()
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Errorf("concurrent CanResume failed: %v", err)
	}
}

// ---------------------------------------------------------------------------
// NewSessionResumer defaults
// ---------------------------------------------------------------------------

// TestResume_NewSessionResumerDefaults verifies zero/negative max age clamping.
func TestResume_NewSessionResumerDefaults(t *testing.T) {
	e := newTestEnv(t)
	defer e.close()

	r := NewSessionResumer(e.storageA, e.smA, e.attA, 0)
	assert.Equal(t, 24*time.Hour, r.maxSessionAge)

	r2 := NewSessionResumer(e.storageA, e.smA, e.attA, -5*time.Minute)
	assert.Equal(t, 24*time.Hour, r2.maxSessionAge)

	r3 := NewSessionResumer(e.storageA, e.smA, e.attA, 1*time.Hour)
	assert.Equal(t, 1*time.Hour, r3.maxSessionAge)
}

// ---------------------------------------------------------------------------
// ResumptionConfig
// ---------------------------------------------------------------------------

// TestResume_ResumptionConfigDefaults verifies the default config values.
func TestResume_ResumptionConfigDefaults(t *testing.T) {
	cfg := DefaultResumptionConfig()
	assert.True(t, cfg.Enabled)
	assert.Equal(t, 24*time.Hour, cfg.MaxSessionAge)
	assert.True(t, cfg.PersistSessions)
}

// TestResume_ResumptionConfigCustom verifies custom config values.
func TestResume_ResumptionConfigCustom(t *testing.T) {
	cfg := ResumptionConfig{
		Enabled:         false,
		MaxSessionAge:   30 * time.Minute,
		PersistSessions: false,
	}
	assert.False(t, cfg.Enabled)
	assert.Equal(t, 30*time.Minute, cfg.MaxSessionAge)
	assert.False(t, cfg.PersistSessions)
}

// ---------------------------------------------------------------------------
// SequenceTracker
// ---------------------------------------------------------------------------

// TestResume_SequenceTrackerBasic tests basic SequenceTracker operations.
func TestResume_SequenceTrackerBasic(t *testing.T) {
	st := NewSequenceTracker(&SessionState{SendSequence: 10, RecvSequence: 20})
	send, recv := st.Sequences()
	assert.Equal(t, uint64(10), send)
	assert.Equal(t, uint64(20), recv)

	assert.Equal(t, uint64(11), st.NextSend())
	assert.Equal(t, uint64(21), st.NextRecv())

	send2, recv2 := st.Sequences()
	assert.Equal(t, uint64(11), send2)
	assert.Equal(t, uint64(21), recv2)
}

// TestResume_SequenceTrackerEncoding tests round-trip encoding of sequences.
func TestResume_SequenceTrackerEncoding(t *testing.T) {
	st := NewSequenceTracker(&SessionState{SendSequence: 42, RecvSequence: 99})
	encoded := st.EncodeSequences()

	send, recv, err := DecodeSequences(encoded)
	require.NoError(t, err)
	assert.Equal(t, uint64(42), send)
	assert.Equal(t, uint64(99), recv)
}
