package kamune

import (
	"github.com/kamune-org/kamune/internal/box/pb"
)

// Route represents a communication route identifier used for message dispatch.
type Route int32

const (
	RouteInvalid          Route = 0
	RouteExchangeMessages Route = 7
	RouteCloseTransport   Route = 8
	RoutePing             Route = 9
	RoutePong             Route = 10
	RouteSessionData      Route = 13
)

// String returns the string representation of the route.
func (r Route) String() string {
	switch r {
	case RouteExchangeMessages:
		return "ExchangeMessages"
	case RouteCloseTransport:
		return "CloseTransport"
	case RoutePing:
		return "Ping"
	case RoutePong:
		return "Pong"
	case RouteSessionData:
		return "SessionData"
	default:
		return "Invalid"
	}
}

// IsValid returns true if the route is a kept session route.
func (r Route) IsValid() bool {
	return r.isSessionRoute()
}

func (r Route) isSessionRoute() bool {
	switch r {
	case RouteExchangeMessages, RouteCloseTransport,
		RoutePing, RoutePong, RouteSessionData:
		return true
	default:
		return false
	}
}

// ToProto converts the Route to its protobuf enum representation.
func (r Route) ToProto() pb.Route {
	switch r {
	case RouteExchangeMessages:
		return pb.Route_ROUTE_EXCHANGE_MESSAGES
	case RouteCloseTransport:
		return pb.Route_ROUTE_CLOSE_TRANSPORT
	case RoutePing:
		return pb.Route_ROUTE_PING
	case RoutePong:
		return pb.Route_ROUTE_PONG
	case RouteSessionData:
		return pb.Route_ROUTE_SESSION_DATA
	default:
		return pb.Route_ROUTE_INVALID
	}
}

// RouteFromProto converts a protobuf Route enum to the local Route type.
func RouteFromProto(r pb.Route) Route {
	switch r {
	case pb.Route_ROUTE_EXCHANGE_MESSAGES:
		return RouteExchangeMessages
	case pb.Route_ROUTE_CLOSE_TRANSPORT:
		return RouteCloseTransport
	case pb.Route_ROUTE_PING:
		return RoutePing
	case pb.Route_ROUTE_PONG:
		return RoutePong
	case pb.Route_ROUTE_SESSION_DATA:
		return RouteSessionData
	default:
		return RouteInvalid
	}
}
