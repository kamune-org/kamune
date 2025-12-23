package kamune

type Route int64

const (
	invalidRoute Route = 2 << iota

	RouteIdentity

	RouteRequestHandshake
	RouteAcceptHandshake
	RouteFinalizeHandshake

	RouteSendChallange
	RouteVerifyChallange

	RouteInitializeDoubleRatchet
	RouteConfirmDoubleRatchet

	RouteExchangeMessages
	RouteCloseTransport
	RouteReconnect
)
