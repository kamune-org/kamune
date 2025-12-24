package kamune

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/kamune-org/kamune/internal/box/pb"
)

func TestRouteString(t *testing.T) {
	tests := []struct {
		route    Route
		expected string
	}{
		{RouteInvalid, "Invalid"},
		{RouteIdentity, "Identity"},
		{RouteRequestHandshake, "RequestHandshake"},
		{RouteAcceptHandshake, "AcceptHandshake"},
		{RouteFinalizeHandshake, "FinalizeHandshake"},
		{RouteSendChallenge, "SendChallenge"},
		{RouteVerifyChallenge, "VerifyChallenge"},
		{RouteInitializeDoubleRatchet, "InitializeDoubleRatchet"},
		{RouteConfirmDoubleRatchet, "ConfirmDoubleRatchet"},
		{RouteExchangeMessages, "ExchangeMessages"},
		{RouteCloseTransport, "CloseTransport"},
		{RouteReconnect, "Reconnect"},
		{Route(999), "Invalid"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.route.String())
		})
	}
}

func TestRouteIsValid(t *testing.T) {
	validRoutes := []Route{
		RouteIdentity,
		RouteRequestHandshake,
		RouteAcceptHandshake,
		RouteFinalizeHandshake,
		RouteSendChallenge,
		RouteVerifyChallenge,
		RouteInitializeDoubleRatchet,
		RouteConfirmDoubleRatchet,
		RouteExchangeMessages,
		RouteCloseTransport,
		RouteReconnect,
	}

	for _, route := range validRoutes {
		t.Run(route.String(), func(t *testing.T) {
			assert.True(t, route.IsValid())
		})
	}

	invalidRoutes := []Route{
		RouteInvalid,
		Route(-1),
		Route(999),
	}

	for _, route := range invalidRoutes {
		t.Run("invalid", func(t *testing.T) {
			assert.False(t, route.IsValid())
		})
	}
}

func TestRouteIsHandshakeRoute(t *testing.T) {
	handshakeRoutes := []Route{
		RouteIdentity,
		RouteRequestHandshake,
		RouteAcceptHandshake,
		RouteFinalizeHandshake,
		RouteSendChallenge,
		RouteVerifyChallenge,
		RouteInitializeDoubleRatchet,
		RouteConfirmDoubleRatchet,
	}

	for _, route := range handshakeRoutes {
		t.Run(route.String(), func(t *testing.T) {
			assert.True(t, route.IsHandshakeRoute())
		})
	}

	nonHandshakeRoutes := []Route{
		RouteExchangeMessages,
		RouteCloseTransport,
		RouteReconnect,
	}

	for _, route := range nonHandshakeRoutes {
		t.Run(route.String(), func(t *testing.T) {
			assert.False(t, route.IsHandshakeRoute())
		})
	}
}

func TestRouteIsSessionRoute(t *testing.T) {
	sessionRoutes := []Route{
		RouteExchangeMessages,
		RouteCloseTransport,
		RouteReconnect,
	}

	for _, route := range sessionRoutes {
		t.Run(route.String(), func(t *testing.T) {
			assert.True(t, route.IsSessionRoute())
		})
	}

	nonSessionRoutes := []Route{
		RouteIdentity,
		RouteRequestHandshake,
		RouteAcceptHandshake,
	}

	for _, route := range nonSessionRoutes {
		t.Run(route.String(), func(t *testing.T) {
			assert.False(t, route.IsSessionRoute())
		})
	}
}

func TestRouteProtoConversion(t *testing.T) {
	tests := []struct {
		route   Route
		pbRoute pb.Route
	}{
		{RouteIdentity, pb.Route_ROUTE_IDENTITY},
		{RouteRequestHandshake, pb.Route_ROUTE_REQUEST_HANDSHAKE},
		{RouteAcceptHandshake, pb.Route_ROUTE_ACCEPT_HANDSHAKE},
		{RouteFinalizeHandshake, pb.Route_ROUTE_FINALIZE_HANDSHAKE},
		{RouteSendChallenge, pb.Route_ROUTE_SEND_CHALLENGE},
		{RouteVerifyChallenge, pb.Route_ROUTE_VERIFY_CHALLENGE},
		{RouteInitializeDoubleRatchet, pb.Route_ROUTE_INITIALIZE_DOUBLE_RATCHET},
		{RouteConfirmDoubleRatchet, pb.Route_ROUTE_CONFIRM_DOUBLE_RATCHET},
		{RouteExchangeMessages, pb.Route_ROUTE_EXCHANGE_MESSAGES},
		{RouteCloseTransport, pb.Route_ROUTE_CLOSE_TRANSPORT},
		{RouteReconnect, pb.Route_ROUTE_RECONNECT},
		{RouteInvalid, pb.Route_ROUTE_INVALID},
	}

	for _, tt := range tests {
		t.Run(tt.route.String(), func(t *testing.T) {
			// Test ToProto
			assert.Equal(t, tt.pbRoute, tt.route.ToProto())

			// Test FromProto
			assert.Equal(t, tt.route, RouteFromProto(tt.pbRoute))
		})
	}
}

func TestExpectedRoutes(t *testing.T) {
	initiatorRoutes := ExpectedRoutes(true)
	responderRoutes := ExpectedRoutes(false)

	assert.NotEmpty(t, initiatorRoutes)
	assert.NotEmpty(t, responderRoutes)
	assert.Equal(t, len(initiatorRoutes), len(responderRoutes))

	// First route should be identity
	assert.Equal(t, RouteIdentity, initiatorRoutes[0])
	assert.Equal(t, RouteIdentity, responderRoutes[0])
}

func TestSessionPhaseString(t *testing.T) {
	tests := []struct {
		phase    SessionPhase
		expected string
	}{
		{PhaseInvalid, "Invalid"},
		{PhaseIntroduction, "Introduction"},
		{PhaseHandshakeRequested, "HandshakeRequested"},
		{PhaseHandshakeAccepted, "HandshakeAccepted"},
		{PhaseChallengeSent, "ChallengeSent"},
		{PhaseChallengeVerified, "ChallengeVerified"},
		{PhaseRatchetInitialized, "RatchetInitialized"},
		{PhaseEstablished, "Established"},
		{PhaseClosed, "Closed"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.phase.String())
		})
	}
}

func TestSessionPhaseProtoConversion(t *testing.T) {
	tests := []struct {
		phase   SessionPhase
		pbPhase pb.SessionPhase
	}{
		{PhaseIntroduction, pb.SessionPhase_PHASE_INTRODUCTION},
		{PhaseHandshakeRequested, pb.SessionPhase_PHASE_HANDSHAKE_REQUESTED},
		{PhaseHandshakeAccepted, pb.SessionPhase_PHASE_HANDSHAKE_ACCEPTED},
		{PhaseChallengeSent, pb.SessionPhase_PHASE_CHALLENGE_SENT},
		{PhaseChallengeVerified, pb.SessionPhase_PHASE_CHALLENGE_VERIFIED},
		{PhaseRatchetInitialized, pb.SessionPhase_PHASE_RATCHET_INITIALIZED},
		{PhaseEstablished, pb.SessionPhase_PHASE_ESTABLISHED},
		{PhaseClosed, pb.SessionPhase_PHASE_CLOSED},
		{PhaseInvalid, pb.SessionPhase_PHASE_INVALID},
	}

	for _, tt := range tests {
		t.Run(tt.phase.String(), func(t *testing.T) {
			// Test ToProto
			assert.Equal(t, tt.pbPhase, tt.phase.ToProto())

			// Test FromProto
			assert.Equal(t, tt.phase, PhaseFromProto(tt.pbPhase))
		})
	}
}

func TestRouterBasic(t *testing.T) {
	r := NewRouter()
	defer r.Close()

	handler := func(t *Transport, msg Transferable, md *Metadata) error {
		return nil
	}

	// Register handler
	err := r.Handle(RouteExchangeMessages, handler)
	require.NoError(t, err)

	// Check handler exists
	assert.True(t, r.HasHandler(RouteExchangeMessages))
	assert.False(t, r.HasHandler(RouteCloseTransport))

	// Try to register duplicate
	err = r.Handle(RouteExchangeMessages, handler)
	assert.ErrorIs(t, err, ErrHandlerExists)

	// Remove handler
	removed := r.Remove(RouteExchangeMessages)
	assert.True(t, removed)
	assert.False(t, r.HasHandler(RouteExchangeMessages))

	// Remove non-existent handler
	removed = r.Remove(RouteExchangeMessages)
	assert.False(t, removed)
}

func TestRouterRoutes(t *testing.T) {
	r := NewRouter()
	defer r.Close()

	handler := func(t *Transport, msg Transferable, md *Metadata) error {
		return nil
	}

	routes := []Route{
		RouteExchangeMessages,
		RouteCloseTransport,
		RouteReconnect,
	}

	for _, route := range routes {
		err := r.Handle(route, handler)
		require.NoError(t, err)
	}

	registeredRoutes := r.Routes()
	assert.Len(t, registeredRoutes, len(routes))
}

func TestRouterValidation(t *testing.T) {
	r := NewRouter()
	defer r.Close()

	// Nil handler
	err := r.Handle(RouteExchangeMessages, nil)
	assert.ErrorIs(t, err, ErrInvalidHandler)

	// Invalid route
	err = r.Handle(RouteInvalid, func(t *Transport, msg Transferable, md *Metadata) error {
		return nil
	})
	assert.ErrorIs(t, err, ErrInvalidRoute)
}

func TestRouterClose(t *testing.T) {
	r := NewRouter()

	handler := func(t *Transport, msg Transferable, md *Metadata) error {
		return nil
	}

	err := r.Handle(RouteExchangeMessages, handler)
	require.NoError(t, err)

	r.Close()

	// Operations after close should fail
	err = r.Handle(RouteCloseTransport, handler)
	assert.ErrorIs(t, err, ErrRouterClosed)

	err = r.Dispatch(nil, RouteExchangeMessages, nil, nil)
	assert.ErrorIs(t, err, ErrRouterClosed)
}

func TestRouterDefaultHandler(t *testing.T) {
	r := NewRouter()
	defer r.Close()

	var defaultCalled bool
	r.SetDefault(func(t *Transport, msg Transferable, md *Metadata) error {
		defaultCalled = true
		return nil
	})

	// Dispatch to unregistered route should use default
	err := r.Dispatch(nil, RouteExchangeMessages, nil, nil)
	require.NoError(t, err)
	assert.True(t, defaultCalled)
}

func TestRouterNoHandler(t *testing.T) {
	r := NewRouter()
	defer r.Close()

	err := r.Dispatch(nil, RouteExchangeMessages, nil, nil)
	assert.ErrorIs(t, err, ErrNoHandler)
}

func TestRouterErrorHandler(t *testing.T) {
	r := NewRouter()
	defer r.Close()

	testErr := errors.New("test error")
	var capturedRoute Route
	var capturedErr error

	r.SetErrorHandler(func(route Route, err error) {
		capturedRoute = route
		capturedErr = err
	})

	r.SetDefault(func(t *Transport, msg Transferable, md *Metadata) error {
		return testErr
	})

	err := r.Dispatch(nil, RouteExchangeMessages, nil, nil)
	assert.ErrorIs(t, err, testErr)
	assert.Equal(t, RouteExchangeMessages, capturedRoute)
	assert.Equal(t, testErr, capturedErr)
}

func TestRouterMiddleware(t *testing.T) {
	r := NewRouter()
	defer r.Close()

	var order []string

	r.Use(func(next RouteHandler) RouteHandler {
		return func(t *Transport, msg Transferable, md *Metadata) error {
			order = append(order, "mw1-before")
			err := next(t, msg, md)
			order = append(order, "mw1-after")
			return err
		}
	})

	r.Use(func(next RouteHandler) RouteHandler {
		return func(t *Transport, msg Transferable, md *Metadata) error {
			order = append(order, "mw2-before")
			err := next(t, msg, md)
			order = append(order, "mw2-after")
			return err
		}
	})

	err := r.Handle(RouteExchangeMessages, func(t *Transport, msg Transferable, md *Metadata) error {
		order = append(order, "handler")
		return nil
	})
	require.NoError(t, err)

	err = r.Dispatch(nil, RouteExchangeMessages, nil, nil)
	require.NoError(t, err)

	expected := []string{
		"mw1-before",
		"mw2-before",
		"handler",
		"mw2-after",
		"mw1-after",
	}
	assert.Equal(t, expected, order)
}

func TestRouterClone(t *testing.T) {
	r := NewRouter()
	defer r.Close()

	err := r.Handle(RouteExchangeMessages, func(t *Transport, msg Transferable, md *Metadata) error {
		return nil
	})
	require.NoError(t, err)

	// Clone the router
	cloned := r.Clone()
	defer cloned.Close()

	// Add handler to clone
	err = cloned.Handle(RouteCloseTransport, func(t *Transport, msg Transferable, md *Metadata) error {
		return nil
	})
	require.NoError(t, err)

	// Original should have first handler
	assert.True(t, r.HasHandler(RouteExchangeMessages))
	assert.False(t, r.HasHandler(RouteCloseTransport))

	// Clone should have both
	assert.True(t, cloned.HasHandler(RouteExchangeMessages))
	assert.True(t, cloned.HasHandler(RouteCloseTransport))
}

func TestRouterGroup(t *testing.T) {
	r := NewRouter()
	defer r.Close()

	var middlewareCalled bool
	group := r.Group(func(next RouteHandler) RouteHandler {
		return func(t *Transport, msg Transferable, md *Metadata) error {
			middlewareCalled = true
			return next(t, msg, md)
		}
	})

	var handlerCalled bool
	err := group.Handle(RouteExchangeMessages, func(t *Transport, msg Transferable, md *Metadata) error {
		handlerCalled = true
		return nil
	})
	require.NoError(t, err)

	err = r.Dispatch(nil, RouteExchangeMessages, nil, nil)
	require.NoError(t, err)

	assert.True(t, middlewareCalled)
	assert.True(t, handlerCalled)
}

func TestRouterConcurrency(t *testing.T) {
	r := NewRouter()
	defer r.Close()

	var counter int64

	for i := 1; i <= 5; i++ {
		route := Route(i)
		err := r.Handle(route, func(t *Transport, msg Transferable, md *Metadata) error {
			atomic.AddInt64(&counter, 1)
			return nil
		})
		require.NoError(t, err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			route := Route((idx % 5) + 1)
			_ = r.Dispatch(nil, route, nil, nil)
		}(i)
	}

	wg.Wait()
	assert.Equal(t, int64(100), atomic.LoadInt64(&counter))
}

func TestRecoveryMiddleware(t *testing.T) {
	r := NewRouter()
	defer r.Close()

	var recoveredValue interface{}
	r.Use(RecoveryMiddleware(func(v interface{}) {
		recoveredValue = v
	}))

	err := r.Handle(RouteExchangeMessages, func(t *Transport, msg Transferable, md *Metadata) error {
		panic("test panic")
	})
	require.NoError(t, err)

	err = r.Dispatch(nil, RouteExchangeMessages, nil, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "panic")
	assert.Equal(t, "test panic", recoveredValue)
}

func TestSessionPhaseMiddleware(t *testing.T) {
	// Test that SessionPhaseMiddleware requires a valid phase
	// Since we can't easily create a Transport without a full handshake,
	// we test the middleware logic directly by checking its behavior

	mw := SessionPhaseMiddleware(PhaseEstablished)

	// Create a handler that tracks if it was called
	handlerCalled := false
	handler := func(t *Transport, msg Transferable, md *Metadata) error {
		handlerCalled = true
		return nil
	}

	wrapped := mw(handler)

	// With nil transport, this will panic - test that the middleware exists
	// and can wrap a handler (we just verify compilation and wrapping works)
	assert.NotNil(t, wrapped)
	assert.False(t, handlerCalled)
}

func TestSequenceTracker(t *testing.T) {
	tracker := NewSequenceTracker(nil)

	// Initial state
	send, recv := tracker.Sequences()
	assert.Equal(t, uint64(0), send)
	assert.Equal(t, uint64(0), recv)

	// NextSend
	assert.Equal(t, uint64(1), tracker.NextSend())
	assert.Equal(t, uint64(2), tracker.NextSend())
	assert.Equal(t, uint64(3), tracker.NextSend())

	send, recv = tracker.Sequences()
	assert.Equal(t, uint64(3), send)
	assert.Equal(t, uint64(0), recv)

	// NextRecv
	assert.Equal(t, uint64(1), tracker.NextRecv())
	assert.Equal(t, uint64(2), tracker.NextRecv())

	send, recv = tracker.Sequences()
	assert.Equal(t, uint64(3), send)
	assert.Equal(t, uint64(2), recv)
}

func TestSequenceTrackerFromState(t *testing.T) {
	state := &SessionState{
		SendSequence: 10,
		RecvSequence: 5,
	}

	tracker := NewSequenceTracker(state)

	send, recv := tracker.Sequences()
	assert.Equal(t, uint64(10), send)
	assert.Equal(t, uint64(5), recv)

	assert.Equal(t, uint64(11), tracker.NextSend())
	assert.Equal(t, uint64(6), tracker.NextRecv())
}

func TestSequenceTrackerValidateRecv(t *testing.T) {
	tracker := NewSequenceTracker(nil)

	// Valid sequence
	err := tracker.ValidateRecv(1)
	assert.NoError(t, err)

	err = tracker.ValidateRecv(2)
	assert.NoError(t, err)

	// Duplicate (already received seq 2, receiving again)
	err = tracker.ValidateRecv(2)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate")

	// Missing (expecting 3, but got 5)
	err = tracker.ValidateRecv(5)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing")
}

func TestSequenceEncoding(t *testing.T) {
	tracker := &SequenceTracker{
		sendSeq: 12345,
		recvSeq: 67890,
	}

	encoded := tracker.EncodeSequences()
	assert.Len(t, encoded, 16)

	send, recv, err := DecodeSequences(encoded)
	require.NoError(t, err)
	assert.Equal(t, uint64(12345), send)
	assert.Equal(t, uint64(67890), recv)

	// Too short data
	_, _, err = DecodeSequences([]byte{1, 2, 3})
	assert.Error(t, err)
}

func TestSessionState(t *testing.T) {
	state := &SessionState{
		SessionID:    "test-session-123",
		Phase:        PhaseEstablished,
		IsInitiator:  true,
		SendSequence: 100,
		RecvSequence: 50,
		SharedSecret: []byte("secret"),
		LocalSalt:    []byte("local"),
		RemoteSalt:   []byte("remote"),
	}

	assert.Equal(t, "test-session-123", state.SessionID)
	assert.Equal(t, PhaseEstablished, state.Phase)
	assert.True(t, state.IsInitiator)
	assert.Equal(t, uint64(100), state.SendSequence)
	assert.Equal(t, uint64(50), state.RecvSequence)
}

func TestRouteDispatcher(t *testing.T) {
	// Just test that it can be created with nil (will fail on actual use)
	// Real tests would require full transport setup
	assert.NotPanics(t, func() {
		rd := NewRouteDispatcher(nil)
		assert.NotNil(t, rd.Router())
		assert.Nil(t, rd.Transport())
	})
}

func TestBytesHelper(t *testing.T) {
	data := []byte("hello world")
	wrapper := Bytes(data)

	assert.IsType(t, &wrapperspb.BytesValue{}, wrapper)
	assert.Equal(t, data, wrapper.GetValue())

	// Nil case
	nilWrapper := Bytes(nil)
	assert.Nil(t, nilWrapper.GetValue())
}

func TestHandshakeTracker(t *testing.T) {
	tracker := NewHandshakeTracker(nil, 5*time.Minute)

	remotePubKey := []byte("remote-public-key-12345")
	localPubKey := []byte("local-public-key-67890")

	// Start a new handshake
	state, err := tracker.StartHandshake(remotePubKey, localPubKey, true)
	require.NoError(t, err)
	assert.NotNil(t, state)
	assert.Equal(t, PhaseIntroduction, state.Phase)
	assert.True(t, state.IsInitiator)
	assert.Equal(t, remotePubKey, state.RemotePublicKey)
	assert.Equal(t, localPubKey, state.LocalPublicKey)

	// Count should be 1
	assert.Equal(t, 1, tracker.ActiveHandshakes())

	// Get the handshake
	retrieved, err := tracker.GetHandshake(remotePubKey)
	require.NoError(t, err)
	assert.Equal(t, state.RemotePublicKey, retrieved.RemotePublicKey)

	// Starting same handshake should return error
	_, err = tracker.StartHandshake(remotePubKey, localPubKey, true)
	assert.ErrorIs(t, err, ErrHandshakeInProgress)

	// Update handshake
	err = tracker.UpdateHandshake(
		remotePubKey,
		PhaseHandshakeRequested,
		"session-123",
		[]byte("secret"),
		[]byte("local-salt"),
		[]byte("remote-salt"),
	)
	require.NoError(t, err)

	updated, err := tracker.GetHandshake(remotePubKey)
	require.NoError(t, err)
	assert.Equal(t, PhaseHandshakeRequested, updated.Phase)
	assert.Equal(t, "session-123", updated.SessionID)
	assert.Equal(t, []byte("secret"), updated.SharedSecret)

	// Complete handshake
	completed, err := tracker.CompleteHandshake(remotePubKey)
	require.NoError(t, err)
	assert.Equal(t, "session-123", completed.SessionID)

	// Should be gone now
	assert.Equal(t, 0, tracker.ActiveHandshakes())
	_, err = tracker.GetHandshake(remotePubKey)
	assert.ErrorIs(t, err, ErrHandshakeNotFound)
}

func TestHandshakeTrackerCancel(t *testing.T) {
	tracker := NewHandshakeTracker(nil, 5*time.Minute)

	remotePubKey := []byte("remote-key-cancel-test")
	localPubKey := []byte("local-key-cancel-test")

	_, err := tracker.StartHandshake(remotePubKey, localPubKey, false)
	require.NoError(t, err)
	assert.Equal(t, 1, tracker.ActiveHandshakes())

	tracker.CancelHandshake(remotePubKey)
	assert.Equal(t, 0, tracker.ActiveHandshakes())
}

func TestHandshakeTrackerExpiration(t *testing.T) {
	// Use very short timeout
	tracker := NewHandshakeTracker(nil, 1*time.Millisecond)

	remotePubKey := []byte("remote-key-expiry")
	localPubKey := []byte("local-key-expiry")

	_, err := tracker.StartHandshake(remotePubKey, localPubKey, true)
	require.NoError(t, err)

	// Wait for expiration
	time.Sleep(5 * time.Millisecond)

	// Should be expired
	_, err = tracker.GetHandshake(remotePubKey)
	assert.ErrorIs(t, err, ErrSessionExpired)

	// Cleanup should remove it
	cleaned := tracker.CleanupExpired()
	assert.Equal(t, 1, cleaned)
	assert.Equal(t, 0, tracker.ActiveHandshakes())
}

func TestHandshakeTrackerMultipleHandshakes(t *testing.T) {
	tracker := NewHandshakeTracker(nil, 5*time.Minute)

	// Start multiple handshakes with different peers
	for i := 0; i < 5; i++ {
		remotePubKey := []byte(fmt.Sprintf("remote-key-%d", i))
		localPubKey := []byte(fmt.Sprintf("local-key-%d", i))
		_, err := tracker.StartHandshake(remotePubKey, localPubKey, i%2 == 0)
		require.NoError(t, err)
	}

	assert.Equal(t, 5, tracker.ActiveHandshakes())

	// Complete some
	for i := 0; i < 3; i++ {
		remotePubKey := []byte(fmt.Sprintf("remote-key-%d", i))
		_, err := tracker.CompleteHandshake(remotePubKey)
		require.NoError(t, err)
	}

	assert.Equal(t, 2, tracker.ActiveHandshakes())
}

func TestHandshakeStateFields(t *testing.T) {
	now := time.Now()
	state := &HandshakeState{
		RemotePublicKey: []byte("remote"),
		LocalPublicKey:  []byte("local"),
		SessionID:       "session-xyz",
		Phase:           PhaseEstablished,
		IsInitiator:     true,
		SharedSecret:    []byte("secret"),
		LocalSalt:       []byte("local-salt"),
		RemoteSalt:      []byte("remote-salt"),
		CreatedAt:       now,
		UpdatedAt:       now,
	}

	assert.Equal(t, []byte("remote"), state.RemotePublicKey)
	assert.Equal(t, []byte("local"), state.LocalPublicKey)
	assert.Equal(t, "session-xyz", state.SessionID)
	assert.Equal(t, PhaseEstablished, state.Phase)
	assert.True(t, state.IsInitiator)
}

func TestPublicKeyHash(t *testing.T) {
	key1 := []byte("public-key-1")
	key2 := []byte("public-key-2")
	key1Copy := []byte("public-key-1")

	hash1 := publicKeyHash(key1)
	hash2 := publicKeyHash(key2)
	hash1Copy := publicKeyHash(key1Copy)

	// Same key should produce same hash
	assert.Equal(t, hash1, hash1Copy)

	// Different keys should produce different hashes
	assert.NotEqual(t, hash1, hash2)

	// Hash should be deterministic
	assert.Equal(t, hash1, publicKeyHash(key1))
}

func TestSessionManagerPublicKeyTracking(t *testing.T) {
	sm := NewSessionManager(nil, 24*time.Hour)

	sessionID := "test-session-abc"
	remotePubKey := []byte("remote-public-key-for-session")

	// Register session
	sm.RegisterSession(sessionID, remotePubKey)

	// Should be able to find it
	found, ok := sm.GetSessionByPublicKey(remotePubKey)
	assert.True(t, ok)
	assert.Equal(t, sessionID, found)

	// Different key should not find it
	_, ok = sm.GetSessionByPublicKey([]byte("different-key"))
	assert.False(t, ok)

	// Unregister
	sm.UnregisterSession(remotePubKey)
	_, ok = sm.GetSessionByPublicKey(remotePubKey)
	assert.False(t, ok)
}

func TestSessionManagerHandshakeTracker(t *testing.T) {
	sm := NewSessionManager(nil, 24*time.Hour)

	tracker := sm.HandshakeTracker()
	assert.NotNil(t, tracker)

	// Use the tracker
	remotePubKey := []byte("test-remote-key")
	localPubKey := []byte("test-local-key")

	state, err := tracker.StartHandshake(remotePubKey, localPubKey, true)
	require.NoError(t, err)
	assert.NotNil(t, state)
}

func TestSessionStateWithPublicKey(t *testing.T) {
	state := &SessionState{
		SessionID:       "session-with-pubkey",
		Phase:           PhaseEstablished,
		IsInitiator:     true,
		SendSequence:    100,
		RecvSequence:    50,
		SharedSecret:    []byte("shared-secret"),
		LocalSalt:       []byte("local-salt"),
		RemoteSalt:      []byte("remote-salt"),
		RemotePublicKey: []byte("remote-public-key"),
	}

	assert.Equal(t, "session-with-pubkey", state.SessionID)
	assert.Equal(t, []byte("remote-public-key"), state.RemotePublicKey)
	assert.Equal(t, PhaseEstablished, state.Phase)
}
