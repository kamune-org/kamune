package kamune

import "errors"

var (
	// ErrVersionMismatch is returned when the remote peer's application version
	// is incompatible with the local version.
	ErrVersionMismatch    = errors.New("version mismatch")
	ErrClosedServer       = errors.New("server is closed")
	ErrConnClosed         = errors.New("connection has been closed")
	ErrPeerDisconnected   = errors.New("peer disconnected")
	ErrInvalidSignature   = errors.New("invalid signature")
	ErrVerificationFailed = errors.New("verification failed")
	ErrMessageTooLarge    = errors.New("message is too large")
	ErrOutOfSync          = errors.New("peers are out of sync")
	ErrUnexpectedRoute    = errors.New("unexpected route received")
	ErrInvalidRoute       = errors.New("invalid route")
	ErrReceiveTimeout     = errors.New("receive timed out")
)
