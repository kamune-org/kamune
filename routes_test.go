package kamune

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/kamune-org/kamune/internal/box/pb"
)

func TestRouteString(t *testing.T) {
	a := assert.New(t)
	tests := []struct {
		expected string
		route    Route
	}{
		{"Invalid", RouteInvalid},
		{"Identity", RouteIdentity},
		{"RequestHandshake", RouteRequestHandshake},
		{"AcceptHandshake", RouteAcceptHandshake},
		{"FinalizeHandshake", RouteFinalizeHandshake},
		{"SendChallenge", RouteSendChallenge},
		{"VerifyChallenge", RouteVerifyChallenge},
		{"ExchangeMessages", RouteExchangeMessages},
		{"CloseTransport", RouteCloseTransport},
		{"Ping", RoutePing},
		{"Pong", RoutePong},
		{"Invalid", Route(999)},
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
		RoutePing,
		RoutePong,
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
		{RoutePing, pb.Route_ROUTE_PING},
		{RoutePong, pb.Route_ROUTE_PONG},
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
