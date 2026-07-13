package kamune

import (
	"github.com/kamune-org/kamune/internal/box/pb"
)

// Route represents a communication route identifier used for message dispatch.
type Route int32

const (
	RouteInvalid Route = iota
	RouteIdentity
	RouteRequestHandshake
	RouteAcceptHandshake
	RouteFinalizeHandshake
	RouteSendChallenge
	RouteVerifyChallenge
	RouteExchangeMessages
	RouteCloseTransport
	RoutePing
	RoutePong
	RouteResumeRequest
	RouteResumeAccept
	RouteSessionData
)

// String returns the string representation of the route.
func (r Route) String() string {
	switch r {
	case RouteIdentity:
		return "Identity"
	case RouteRequestHandshake:
		return "RequestHandshake"
	case RouteAcceptHandshake:
		return "AcceptHandshake"
	case RouteFinalizeHandshake:
		return "FinalizeHandshake"
	case RouteSendChallenge:
		return "SendChallenge"
	case RouteVerifyChallenge:
		return "VerifyChallenge"
	case RouteExchangeMessages:
		return "ExchangeMessages"
	case RouteCloseTransport:
		return "CloseTransport"
	case RoutePing:
		return "Ping"
	case RoutePong:
		return "Pong"
	case RouteResumeRequest:
		return "ResumeRequest"
	case RouteResumeAccept:
		return "ResumeAccept"
	case RouteSessionData:
		return "SessionData"
	default:
		return "Invalid"
	}
}

// IsValid returns true if the route is a valid, non-invalid route.
func (r Route) IsValid() bool {
	return r > RouteInvalid && r <= RouteSessionData
}

// ToProto converts the Route to its protobuf enum representation.
func (r Route) ToProto() pb.Route {
	switch r {
	case RouteIdentity:
		return pb.Route_ROUTE_IDENTITY
	case RouteRequestHandshake:
		return pb.Route_ROUTE_REQUEST_HANDSHAKE
	case RouteAcceptHandshake:
		return pb.Route_ROUTE_ACCEPT_HANDSHAKE
	case RouteFinalizeHandshake:
		return pb.Route_ROUTE_FINALIZE_HANDSHAKE
	case RouteSendChallenge:
		return pb.Route_ROUTE_SEND_CHALLENGE
	case RouteVerifyChallenge:
		return pb.Route_ROUTE_VERIFY_CHALLENGE
	case RouteExchangeMessages:
		return pb.Route_ROUTE_EXCHANGE_MESSAGES
	case RouteCloseTransport:
		return pb.Route_ROUTE_CLOSE_TRANSPORT
	case RoutePing:
		return pb.Route_ROUTE_PING
	case RoutePong:
		return pb.Route_ROUTE_PONG
	case RouteResumeRequest:
		return pb.Route_ROUTE_RESUME_REQUEST
	case RouteResumeAccept:
		return pb.Route_ROUTE_RESUME_ACCEPT
	case RouteSessionData:
		return pb.Route_ROUTE_SESSION_DATA
	default:
		return pb.Route_ROUTE_INVALID
	}
}

// RouteFromProto converts a protobuf Route enum to the local Route type.
func RouteFromProto(r pb.Route) Route {
	switch r {
	case pb.Route_ROUTE_IDENTITY:
		return RouteIdentity
	case pb.Route_ROUTE_REQUEST_HANDSHAKE:
		return RouteRequestHandshake
	case pb.Route_ROUTE_ACCEPT_HANDSHAKE:
		return RouteAcceptHandshake
	case pb.Route_ROUTE_FINALIZE_HANDSHAKE:
		return RouteFinalizeHandshake
	case pb.Route_ROUTE_SEND_CHALLENGE:
		return RouteSendChallenge
	case pb.Route_ROUTE_VERIFY_CHALLENGE:
		return RouteVerifyChallenge
	case pb.Route_ROUTE_EXCHANGE_MESSAGES:
		return RouteExchangeMessages
	case pb.Route_ROUTE_CLOSE_TRANSPORT:
		return RouteCloseTransport
	case pb.Route_ROUTE_PING:
		return RoutePing
	case pb.Route_ROUTE_PONG:
		return RoutePong
	case pb.Route_ROUTE_RESUME_REQUEST:
		return RouteResumeRequest
	case pb.Route_ROUTE_RESUME_ACCEPT:
		return RouteResumeAccept
	case pb.Route_ROUTE_SESSION_DATA:
		return RouteSessionData
	default:
		return RouteInvalid
	}
}
