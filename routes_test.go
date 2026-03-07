package kamune

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"

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
		{RouteExchangeMessages, "ExchangeMessages"},
		{RouteCloseTransport, "CloseTransport"},
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
		RouteExchangeMessages,
		RouteCloseTransport,
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
	}

	for _, route := range handshakeRoutes {
		t.Run(route.String(), func(t *testing.T) {
			a.True(route.IsHandshakeRoute())
		})
	}

	nonHandshakeRoutes := []Route{
		RouteExchangeMessages,
		RouteCloseTransport,
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
		{RouteExchangeMessages, pb.Route_ROUTE_EXCHANGE_MESSAGES},
		{RouteCloseTransport, pb.Route_ROUTE_CLOSE_TRANSPORT},
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
	err = r.Handle(RouteInvalid, func(
		t *Transport, msg Transferable, md *Metadata,
	) error {
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

	err := r.Handle(RouteExchangeMessages, func(
		t *Transport, msg Transferable, md *Metadata,
	) error {
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

	err := r.Handle(RouteExchangeMessages, func(
		t *Transport, msg Transferable, md *Metadata,
	) error {
		return nil
	})
	a.NoError(err)

	// Clone the router
	cloned := r.Clone()
	defer cloned.Close()

	// Add handler to clone
	err = cloned.Handle(RouteCloseTransport, func(
		t *Transport, msg Transferable, md *Metadata,
	) error {
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
	err := group.Handle(RouteExchangeMessages, func(
		t *Transport, msg Transferable, md *Metadata,
	) error {
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
		err := r.Handle(route, func(
			t *Transport, msg Transferable, md *Metadata,
		) error {
			atomic.AddInt64(&counter, 1)
			return nil
		})
		a.NoError(err)
	}

	var wg sync.WaitGroup
	for i := range 100 {
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

	var recoveredValue any
	r.Use(RecoveryMiddleware(func(v any) {
		recoveredValue = v
	}))

	err := r.Handle(RouteExchangeMessages, func(
		t *Transport, msg Transferable, md *Metadata,
	) error {
		panic("test panic")
	})
	a.NoError(err)

	err = r.Dispatch(nil, RouteExchangeMessages, nil, nil)
	a.Error(err)
	a.Contains(err.Error(), "panic")
	a.Equal("test panic", recoveredValue)
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
