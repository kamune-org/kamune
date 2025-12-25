package kamune

import "github.com/kamune-org/kamune/internal/box/pb"

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

	RouteInitializeDoubleRatchet
	RouteConfirmDoubleRatchet

	RouteExchangeMessages
	RouteCloseTransport
	RouteReconnect
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
	case RouteInitializeDoubleRatchet:
		return "InitializeDoubleRatchet"
	case RouteConfirmDoubleRatchet:
		return "ConfirmDoubleRatchet"
	case RouteExchangeMessages:
		return "ExchangeMessages"
	case RouteCloseTransport:
		return "CloseTransport"
	case RouteReconnect:
		return "Reconnect"
	default:
		return "Invalid"
	}
}

// IsValid returns true if the route is a valid, non-invalid route.
func (r Route) IsValid() bool {
	return r > RouteInvalid && r <= RouteReconnect
}

// IsHandshakeRoute returns true if the route is part of the handshake process.
func (r Route) IsHandshakeRoute() bool {
	switch r {
	case RouteIdentity,
		RouteRequestHandshake,
		RouteAcceptHandshake,
		RouteFinalizeHandshake,
		RouteSendChallenge,
		RouteVerifyChallenge,
		RouteInitializeDoubleRatchet,
		RouteConfirmDoubleRatchet:
		return true
	default:
		return false
	}
}

// IsSessionRoute returns true if the route is part of an established session.
func (r Route) IsSessionRoute() bool {
	switch r {
	case RouteExchangeMessages,
		RouteCloseTransport,
		RouteReconnect:
		return true
	default:
		return false
	}
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
	case RouteInitializeDoubleRatchet:
		return pb.Route_ROUTE_INITIALIZE_DOUBLE_RATCHET
	case RouteConfirmDoubleRatchet:
		return pb.Route_ROUTE_CONFIRM_DOUBLE_RATCHET
	case RouteExchangeMessages:
		return pb.Route_ROUTE_EXCHANGE_MESSAGES
	case RouteCloseTransport:
		return pb.Route_ROUTE_CLOSE_TRANSPORT
	case RouteReconnect:
		return pb.Route_ROUTE_RECONNECT
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
	case pb.Route_ROUTE_INITIALIZE_DOUBLE_RATCHET:
		return RouteInitializeDoubleRatchet
	case pb.Route_ROUTE_CONFIRM_DOUBLE_RATCHET:
		return RouteConfirmDoubleRatchet
	case pb.Route_ROUTE_EXCHANGE_MESSAGES:
		return RouteExchangeMessages
	case pb.Route_ROUTE_CLOSE_TRANSPORT:
		return RouteCloseTransport
	case pb.Route_ROUTE_RECONNECT:
		return RouteReconnect
	default:
		return RouteInvalid
	}
}

// handshakeRouteOrder defines the expected order of routes during handshake.
//
// Note: The initiator/responder orders differ after RouteAcceptHandshake.
// See `requestHandshake` and `acceptHandshake` in `handshake.go`.
//
// Initiator (client):
//   - sends challenge
//   - accepts peer's challenge
//   - sends ratchet init
//   - receives ratchet confirm
var handshakeRouteOrderInitiator = []Route{
	RouteIdentity,
	RouteRequestHandshake,
	RouteAcceptHandshake,
	RouteSendChallenge,
	RouteVerifyChallenge,
	RouteInitializeDoubleRatchet,
	RouteConfirmDoubleRatchet,
}

// Responder (server):
//   - receives challenge
//   - verifies (echoes) it
//   - sends its own challenge
//   - receives verification
//   - receives ratchet init
//   - sends ratchet confirm
var handshakeRouteOrderResponder = []Route{
	RouteIdentity,
	RouteRequestHandshake,
	RouteAcceptHandshake,
	RouteSendChallenge,
	RouteVerifyChallenge,
	// Responder receives the initiator's ratchet init first, then confirms.
	RouteInitializeDoubleRatchet,
	RouteConfirmDoubleRatchet,
}

// ExpectedRoutes returns the sequence of routes expected during handshake.
func ExpectedRoutes(isInitiator bool) []Route {
	if isInitiator {
		return handshakeRouteOrderInitiator
	}
	return handshakeRouteOrderResponder
}
