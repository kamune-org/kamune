package kamune

import (
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/kamune-org/kamune/internal/box/pb"
)

func TestRouteString(t *testing.T) {
	a := require.New(t)
	tests := []struct {
		expected string
		route    Route
	}{
		{"Invalid", RouteInvalid},
		{"ExchangeMessages", RouteExchangeMessages},
		{"CloseTransport", RouteCloseTransport},
		{"Ping", RoutePing},
		{"Pong", RoutePong},
		{"SessionData", RouteSessionData},
		{"Invalid", Route(1)},
		{"Invalid", Route(11)},
		{"Invalid", Route(999)},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			a.Equal(tt.expected, tt.route.String())
		})
	}
}

func TestRouteIsValid(t *testing.T) {
	a := require.New(t)
	validRoutes := []Route{
		RouteExchangeMessages,
		RouteCloseTransport,
		RoutePing,
		RoutePong,
		RouteSessionData,
	}

	for _, route := range validRoutes {
		t.Run(route.String(), func(t *testing.T) {
			a.True(route.IsValid())
		})
	}

	invalidRoutes := []Route{
		RouteInvalid,
		Route(1),
		Route(6),
		Route(11),
		Route(12),
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
	a := require.New(t)
	tests := []struct {
		route   Route
		pbRoute pb.Route
	}{
		{RouteExchangeMessages, pb.Route_ROUTE_EXCHANGE_MESSAGES},
		{RouteCloseTransport, pb.Route_ROUTE_CLOSE_TRANSPORT},
		{RoutePing, pb.Route_ROUTE_PING},
		{RoutePong, pb.Route_ROUTE_PONG},
		{RouteSessionData, pb.Route_ROUTE_SESSION_DATA},
		{RouteInvalid, pb.Route_ROUTE_INVALID},
	}

	for _, tt := range tests {
		t.Run(tt.route.String(), func(t *testing.T) {
			a.Equal(tt.pbRoute, tt.route.ToProto())
			a.Equal(tt.route, RouteFromProto(tt.pbRoute))
		})
	}
	a.Equal(pb.Route_ROUTE_INVALID, Route(1).ToProto())
	a.Equal(RouteInvalid, RouteFromProto(pb.Route(1)))
}

func TestBytesHelper(t *testing.T) {
	a := require.New(t)
	data := []byte("hello world")
	wrapper := Bytes(data)

	a.IsType(&wrapperspb.BytesValue{}, wrapper)
	a.Equal(data, wrapper.GetValue())

	a.Nil(Bytes(nil).GetValue())
}
