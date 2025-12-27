package kamune

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/kamune-org/kamune/internal/box/pb"
)

func TestRouteString(t *testing.T) {
	a := assert.New(t)
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
			a.Equal(tt.expected, tt.route.String())
		})
	}
}

func TestRouteIsValid(t *testing.T) {
	a := assert.New(t)
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
			a.True(route.IsValid())
		})
	}

	invalidRoutes := []Route{
		RouteInvalid,
		Route(-1),
		Route(999),
	}

	for _, route := range invalidRoutes {
		t.Run("invalid", func(t *testing.T) {
			a.False(route.IsValid())
		})
	}
}

func TestRouteIsHandshakeRoute(t *testing.T) {
	a := assert.New(t)
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
			a.True(route.IsHandshakeRoute())
		})
	}

	nonHandshakeRoutes := []Route{
		RouteExchangeMessages,
		RouteCloseTransport,
		RouteReconnect,
	}

	for _, route := range nonHandshakeRoutes {
		t.Run(route.String(), func(t *testing.T) {
			a.False(route.IsHandshakeRoute())
		})
	}
}

func TestRouteIsSessionRoute(t *testing.T) {
	a := assert.New(t)
	sessionRoutes := []Route{
		RouteExchangeMessages,
		RouteCloseTransport,
		RouteReconnect,
	}

	for _, route := range sessionRoutes {
		t.Run(route.String(), func(t *testing.T) {
			a.True(route.IsSessionRoute())
		})
	}

	nonSessionRoutes := []Route{
		RouteIdentity,
		RouteRequestHandshake,
		RouteAcceptHandshake,
	}

	for _, route := range nonSessionRoutes {
		t.Run(route.String(), func(t *testing.T) {
			a.False(route.IsSessionRoute())
		})
	}
}

func TestRouteProtoConversion(t *testing.T) {
	a := assert.New(t)
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
			a.Equal(tt.pbRoute, tt.route.ToProto())

			// Test FromProto
			a.Equal(tt.route, RouteFromProto(tt.pbRoute))
		})
	}
}

func TestExpectedRoutes(t *testing.T) {
	a := assert.New(t)
	initiatorRoutes := ExpectedRoutes(true)
	responderRoutes := ExpectedRoutes(false)

	a.NotEmpty(initiatorRoutes)
	a.NotEmpty(responderRoutes)
	a.Equal(len(initiatorRoutes), len(responderRoutes))

	// First route should be identity
	a.Equal(RouteIdentity, initiatorRoutes[0])
	a.Equal(RouteIdentity, responderRoutes[0])
}

func TestSessionPhaseString(t *testing.T) {
	a := assert.New(t)
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
			a.Equal(tt.expected, tt.phase.String())
		})
	}
}

func TestSessionPhaseProtoConversion(t *testing.T) {
	a := assert.New(t)
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
			a.Equal(tt.pbPhase, tt.phase.ToProto())

			// Test FromProto
			a.Equal(tt.phase, PhaseFromProto(tt.pbPhase))
		})
	}
}

func TestRouterBasic(t *testing.T) {
	a := assert.New(t)
	r := NewRouter()
	defer r.Close()

	handler := func(t *Transport, msg Transferable, md *Metadata) error {
		return nil
	}

	// Register handler
	err := r.Handle(RouteExchangeMessages, handler)
	a.NoError(err)

	// Check handler exists
	a.True(r.HasHandler(RouteExchangeMessages))
	a.False(r.HasHandler(RouteCloseTransport))

	// Try to register duplicate
	err = r.Handle(RouteExchangeMessages, handler)
	a.ErrorIs(err, ErrHandlerExists)

	// Remove handler
	removed := r.Remove(RouteExchangeMessages)
	a.True(removed)
	a.False(r.HasHandler(RouteExchangeMessages))

	// Remove non-existent handler
	removed = r.Remove(RouteExchangeMessages)
	a.False(removed)
}

func TestRouterRoutes(t *testing.T) {
	a := assert.New(t)
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
		a.NoError(err)
	}

	registeredRoutes := r.Routes()
	a.Len(registeredRoutes, len(routes))
}

func TestRouterValidation(t *testing.T) {
	a := assert.New(t)
	r := NewRouter()
	defer r.Close()

	// Nil handler
	err := r.Handle(RouteExchangeMessages, nil)
	a.ErrorIs(err, ErrInvalidHandler)

	// Invalid route
	err = r.Handle(RouteInvalid, func(t *Transport, msg Transferable, md *Metadata) error {
		return nil
	})
	a.ErrorIs(err, ErrInvalidRoute)
}

func TestRouterClose(t *testing.T) {
	a := assert.New(t)
	r := NewRouter()

	handler := func(t *Transport, msg Transferable, md *Metadata) error {
		return nil
	}

	err := r.Handle(RouteExchangeMessages, handler)
	a.NoError(err)

	r.Close()

	// Operations after close should fail
	err = r.Handle(RouteCloseTransport, handler)
	a.ErrorIs(err, ErrRouterClosed)

	err = r.Dispatch(nil, RouteExchangeMessages, nil, nil)
	a.ErrorIs(err, ErrRouterClosed)
}

func TestRouterDefaultHandler(t *testing.T) {
	a := assert.New(t)
	r := NewRouter()
	defer r.Close()

	var defaultCalled bool
	r.SetDefault(func(t *Transport, msg Transferable, md *Metadata) error {
		defaultCalled = true
		return nil
	})

	// Dispatch to unregistered route should use default
	err := r.Dispatch(nil, RouteExchangeMessages, nil, nil)
	a.NoError(err)
	a.True(defaultCalled)
}

func TestRouterNoHandler(t *testing.T) {
	a := assert.New(t)
	r := NewRouter()
	defer r.Close()

	err := r.Dispatch(nil, RouteExchangeMessages, nil, nil)
	a.ErrorIs(err, ErrNoHandler)
}

func TestRouterErrorHandler(t *testing.T) {
	a := assert.New(t)
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
	a.ErrorIs(err, testErr)
	a.Equal(RouteExchangeMessages, capturedRoute)
	a.Equal(testErr, capturedErr)
}

func TestRouterMiddleware(t *testing.T) {
	a := assert.New(t)
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
	a.NoError(err)

	err = r.Dispatch(nil, RouteExchangeMessages, nil, nil)
	a.NoError(err)

	expected := []string{
		"mw1-before",
		"mw2-before",
		"handler",
		"mw2-after",
		"mw1-after",
	}
	a.Equal(expected, order)
}

func TestRouterClone(t *testing.T) {
	a := assert.New(t)
	r := NewRouter()
	defer r.Close()

	err := r.Handle(RouteExchangeMessages, func(t *Transport, msg Transferable, md *Metadata) error {
		return nil
	})
	a.NoError(err)

	// Clone the router
	cloned := r.Clone()
	defer cloned.Close()

	// Add handler to clone
	err = cloned.Handle(RouteCloseTransport, func(t *Transport, msg Transferable, md *Metadata) error {
		return nil
	})
	a.NoError(err)

	// Original should have first handler
	a.True(r.HasHandler(RouteExchangeMessages))
	a.False(r.HasHandler(RouteCloseTransport))

	// Clone should have both
	a.True(cloned.HasHandler(RouteExchangeMessages))
	a.True(cloned.HasHandler(RouteCloseTransport))
}

func TestRouterGroup(t *testing.T) {
	a := assert.New(t)
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
	a.NoError(err)

	err = r.Dispatch(nil, RouteExchangeMessages, nil, nil)
	a.NoError(err)

	a.True(middlewareCalled)
	a.True(handlerCalled)
}

func TestRouterConcurrency(t *testing.T) {
	a := assert.New(t)
	r := NewRouter()
	defer r.Close()

	var counter int64

	for i := 1; i <= 5; i++ {
		route := Route(i)
		err := r.Handle(route, func(t *Transport, msg Transferable, md *Metadata) error {
			atomic.AddInt64(&counter, 1)
			return nil
		})
		a.NoError(err)
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
	a.Equal(int64(100), atomic.LoadInt64(&counter))
}

func TestRecoveryMiddleware(t *testing.T) {
	a := assert.New(t)
	r := NewRouter()
	defer r.Close()

	var recoveredValue interface{}
	r.Use(RecoveryMiddleware(func(v interface{}) {
		recoveredValue = v
	}))

	err := r.Handle(RouteExchangeMessages, func(t *Transport, msg Transferable, md *Metadata) error {
		panic("test panic")
	})
	a.NoError(err)

	err = r.Dispatch(nil, RouteExchangeMessages, nil, nil)
	a.Error(err)
	a.Contains(err.Error(), "panic")
	a.Equal("test panic", recoveredValue)
}

func TestSessionPhaseMiddleware(t *testing.T) {
	a := assert.New(t)
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
	a.NotNil(wrapped)
	a.False(handlerCalled)
}

func TestSequenceTracker(t *testing.T) {
	a := assert.New(t)
	tracker := NewSequenceTracker(nil)

	// Initial state
	send, recv := tracker.Sequences()
	a.Equal(uint64(0), send)
	a.Equal(uint64(0), recv)

	// NextSend
	a.Equal(uint64(1), tracker.NextSend())
	a.Equal(uint64(2), tracker.NextSend())
	a.Equal(uint64(3), tracker.NextSend())

	send, recv = tracker.Sequences()
	a.Equal(uint64(3), send)
	a.Equal(uint64(0), recv)

	// NextRecv
	a.Equal(uint64(1), tracker.NextRecv())
	a.Equal(uint64(2), tracker.NextRecv())

	send, recv = tracker.Sequences()
	a.Equal(uint64(3), send)
	a.Equal(uint64(2), recv)
}

func TestSequenceTrackerFromState(t *testing.T) {
	a := assert.New(t)
	state := &SessionState{
		SendSequence: 10,
		RecvSequence: 5,
	}

	tracker := NewSequenceTracker(state)

	send, recv := tracker.Sequences()
	a.Equal(uint64(10), send)
	a.Equal(uint64(5), recv)

	a.Equal(uint64(11), tracker.NextSend())
	a.Equal(uint64(6), tracker.NextRecv())
}

func TestSequenceTrackerValidateRecv(t *testing.T) {
	a := assert.New(t)
	tracker := NewSequenceTracker(nil)

	// Valid sequence
	err := tracker.ValidateRecv(1)
	a.NoError(err)

	err = tracker.ValidateRecv(2)
	a.NoError(err)

	// Duplicate (already received seq 2, receiving again)
	err = tracker.ValidateRecv(2)
	a.Error(err)
	a.Contains(err.Error(), "duplicate")

	// Missing (expecting 3, but got 5)
	err = tracker.ValidateRecv(5)
	a.Error(err)
	a.Contains(err.Error(), "missing")
}

func TestSequenceEncoding(t *testing.T) {
	a := assert.New(t)
	tracker := &SequenceTracker{
		sendSeq: 12345,
		recvSeq: 67890,
	}

	encoded := tracker.EncodeSequences()
	a.Len(encoded, 16)

	send, recv, err := DecodeSequences(encoded)
	a.NoError(err)
	a.Equal(uint64(12345), send)
	a.Equal(uint64(67890), recv)

	// Too short data
	_, _, err = DecodeSequences([]byte{1, 2, 3})
	a.Error(err)
}

func TestSessionState(t *testing.T) {
	a := assert.New(t)
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

	a.Equal("test-session-123", state.SessionID)
	a.Equal(PhaseEstablished, state.Phase)
	a.True(state.IsInitiator)
	a.Equal(uint64(100), state.SendSequence)
	a.Equal(uint64(50), state.RecvSequence)
}

func TestRouteDispatcher(t *testing.T) {
	a := assert.New(t)
	// Just test that it can be created with nil (will fail on actual use)
	// Real tests would require full transport setup
	a.NotPanics(func() {
		rd := NewRouteDispatcher(nil)
		a.NotNil(rd.Router())
		a.Nil(rd.Transport())
	})
}

func TestBytesHelper(t *testing.T) {
	a := assert.New(t)
	data := []byte("hello world")
	wrapper := Bytes(data)

	a.IsType(&wrapperspb.BytesValue{}, wrapper)
	a.Equal(data, wrapper.GetValue())

	// Nil case
	nilWrapper := Bytes(nil)
	a.Nil(nilWrapper.GetValue())
}

func TestHandshakeTracker(t *testing.T) {
	a := assert.New(t)
	tracker := NewHandshakeTracker(nil, 5*time.Minute)

	remotePubKey := []byte("remote-public-key-12345")
	localPubKey := []byte("local-public-key-67890")

	// Start a new handshake
	state, err := tracker.StartHandshake(remotePubKey, localPubKey, true)
	a.NoError(err)
	a.NotNil(state)
	a.Equal(PhaseIntroduction, state.Phase)
	a.True(state.IsInitiator)
	a.Equal(remotePubKey, state.RemotePublicKey)
	a.Equal(localPubKey, state.LocalPublicKey)

	// Count should be 1
	a.Equal(1, tracker.ActiveHandshakes())

	// Get the handshake
	retrieved, err := tracker.GetHandshake(remotePubKey)
	a.NoError(err)
	a.Equal(state.RemotePublicKey, retrieved.RemotePublicKey)

	// Starting same handshake should return error
	_, err = tracker.StartHandshake(remotePubKey, localPubKey, true)
	a.ErrorIs(err, ErrHandshakeInProgress)

	// Update handshake
	err = tracker.UpdateHandshake(
		remotePubKey,
		PhaseHandshakeRequested,
		"session-123",
		[]byte("secret"),
		[]byte("local-salt"),
		[]byte("remote-salt"),
	)
	a.NoError(err)

	updated, err := tracker.GetHandshake(remotePubKey)
	a.NoError(err)
	a.Equal(PhaseHandshakeRequested, updated.Phase)
	a.Equal("session-123", updated.SessionID)
	a.Equal([]byte("secret"), updated.SharedSecret)

	// Complete handshake
	completed, err := tracker.CompleteHandshake(remotePubKey)
	a.NoError(err)
	a.Equal("session-123", completed.SessionID)

	// Should be gone now
	a.Equal(0, tracker.ActiveHandshakes())
	_, err = tracker.GetHandshake(remotePubKey)
	a.ErrorIs(err, ErrHandshakeNotFound)
}

func TestHandshakeTrackerCancel(t *testing.T) {
	a := assert.New(t)
	tracker := NewHandshakeTracker(nil, 5*time.Minute)

	remotePubKey := []byte("remote-key-cancel-test")
	localPubKey := []byte("local-key-cancel-test")

	_, err := tracker.StartHandshake(remotePubKey, localPubKey, false)
	a.NoError(err)
	a.Equal(1, tracker.ActiveHandshakes())

	tracker.CancelHandshake(remotePubKey)
	a.Equal(0, tracker.ActiveHandshakes())
}

func TestHandshakeTrackerExpiration(t *testing.T) {
	a := assert.New(t)
	// Use very short timeout
	tracker := NewHandshakeTracker(nil, 1*time.Millisecond)

	remotePubKey := []byte("remote-key-expiry")
	localPubKey := []byte("local-key-expiry")

	_, err := tracker.StartHandshake(remotePubKey, localPubKey, true)
	a.NoError(err)

	// Wait for expiration
	time.Sleep(5 * time.Millisecond)

	// Should be expired
	_, err = tracker.GetHandshake(remotePubKey)
	a.ErrorIs(err, ErrSessionExpired)

	// Cleanup should remove it
	cleaned := tracker.CleanupExpired()
	a.Equal(1, cleaned)
	a.Equal(0, tracker.ActiveHandshakes())
}

func TestHandshakeTrackerMultipleHandshakes(t *testing.T) {
	a := assert.New(t)
	tracker := NewHandshakeTracker(nil, 5*time.Minute)

	// Start multiple handshakes with different peers
	for i := 0; i < 5; i++ {
		remotePubKey := []byte(fmt.Sprintf("remote-key-%d", i))
		localPubKey := []byte(fmt.Sprintf("local-key-%d", i))
		_, err := tracker.StartHandshake(remotePubKey, localPubKey, i%2 == 0)
		a.NoError(err)
	}

	a.Equal(5, tracker.ActiveHandshakes())

	// Complete some
	for i := 0; i < 3; i++ {
		remotePubKey := []byte(fmt.Sprintf("remote-key-%d", i))
		_, err := tracker.CompleteHandshake(remotePubKey)
		a.NoError(err)
	}

	a.Equal(2, tracker.ActiveHandshakes())
}

func TestHandshakeStateFields(t *testing.T) {
	a := assert.New(t)
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

	a.Equal([]byte("remote"), state.RemotePublicKey)
	a.Equal([]byte("local"), state.LocalPublicKey)
	a.Equal("session-xyz", state.SessionID)
	a.Equal(PhaseEstablished, state.Phase)
	a.True(state.IsInitiator)
}

func TestPublicKeyHash(t *testing.T) {
	a := assert.New(t)
	key1 := []byte("public-key-1")
	key2 := []byte("public-key-2")
	key1Copy := []byte("public-key-1")

	hash1 := publicKeyHash(key1)
	hash2 := publicKeyHash(key2)
	hash1Copy := publicKeyHash(key1Copy)

	// Same key should produce same hash
	a.Equal(hash1, hash1Copy)

	// Different keys should produce different hashes
	a.NotEqual(hash1, hash2)

	// Hash should be deterministic
	a.Equal(hash1, publicKeyHash(key1))
}

func TestSessionManagerPublicKeyTracking(t *testing.T) {
	a := assert.New(t)
	sm := NewSessionManager(nil, 24*time.Hour)

	sessionID := "test-session-abc"
	remotePubKey := []byte("remote-public-key-for-session")

	// Register session
	sm.RegisterSession(sessionID, remotePubKey)

	// Should be able to find it
	found, ok := sm.GetSessionByPublicKey(remotePubKey)
	a.True(ok)
	a.Equal(sessionID, found)

	// Different key should not find it
	_, ok = sm.GetSessionByPublicKey([]byte("different-key"))
	a.False(ok)

	// Unregister
	sm.UnregisterSession(remotePubKey)
	_, ok = sm.GetSessionByPublicKey(remotePubKey)
	a.False(ok)
}

func TestSessionManagerHandshakeTracker(t *testing.T) {
	a := assert.New(t)
	sm := NewSessionManager(nil, 24*time.Hour)

	tracker := sm.HandshakeTracker()
	a.NotNil(tracker)

	// Use the tracker
	remotePubKey := []byte("test-remote-key")
	localPubKey := []byte("test-local-key")

	state, err := tracker.StartHandshake(remotePubKey, localPubKey, true)
	a.NoError(err)
	a.NotNil(state)
}

func TestSessionStateWithPublicKey(t *testing.T) {
	a := assert.New(t)
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

	a.Equal("session-with-pubkey", state.SessionID)
	a.Equal([]byte("remote-public-key"), state.RemotePublicKey)
	a.Equal(PhaseEstablished, state.Phase)
}
