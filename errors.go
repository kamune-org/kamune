package kamune

import "errors"

var (
	// ErrVersionMismatch is returned when the remote peer's application version
	// is incompatible with the local version.
	ErrVersionMismatch = errors.New("version mismatch")
	// ErrClosedServer is returned when an operation is attempted on a server
	// that has been shut down.
	ErrClosedServer = errors.New("server is closed")
	// ErrConnClosed is returned when an operation is attempted on a connection
	// that has already been closed.
	ErrConnClosed = errors.New("connection has been closed")
	// ErrPeerDisconnected is returned when the remote peer sends a
	// RouteCloseTransport frame, indicating a graceful disconnect.
	ErrPeerDisconnected = errors.New("peer disconnected")
	// ErrInvalidSignature is returned when a cryptographic signature fails
	// verification.
	ErrInvalidSignature = errors.New("invalid signature")
	// ErrVerificationFailed is returned when a peer verification check
	// (e.g. challenge-response, remote verifier) does not pass.
	ErrVerificationFailed = errors.New("verification failed")
	// ErrMessageTooLarge is returned when a frame exceeds maxTransportSize.
	ErrMessageTooLarge = errors.New("message is too large")
	// ErrOutOfSync is returned when received message sequence numbers indicate
	// duplicates, gaps, or out-of-order delivery.
	ErrOutOfSync = errors.New("peers are out of sync")
	// ErrUnexpectedRoute is returned when the received protocol route does not
	// match the expected route for the current protocol phase.
	ErrUnexpectedRoute = errors.New("unexpected route received")
	// ErrInvalidRoute is returned when a route is not a recognized protocol
	// route (e.g. when used with Transport.Send).
	ErrInvalidRoute = errors.New("invalid route")
	// ErrReceiveTimeout is returned when Transport.Receive exceeds its deadline.
	ErrReceiveTimeout = errors.New("receive timed out")
)
