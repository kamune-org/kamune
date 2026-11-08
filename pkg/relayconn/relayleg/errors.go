package relayleg

import "errors"

var (
	// ErrInvalidRelayKey means a relay public key is missing,
	// malformed, not canonical, or all zeros. Initiate also
	// returns it when encapsulation to the relay key fails, as
	// it does for a low-order point, and writes nothing.
	ErrInvalidRelayKey = errors.New("invalid relay key")

	// ErrInvalidPSK means an access key is missing, malformed, not
	// canonical, or all zeros.
	ErrInvalidPSK = errors.New("invalid PSK")

	// ErrKeyUsage means ExtractShared was called with a domain that
	// does not start with "kamune broker v2".
	ErrKeyUsage = errors.New("invalid key usage")

	// ErrBadMessage means a handshake frame has the wrong magic,
	// type, length or reserved flags, an unknown alert code, or
	// key material the receiver cannot use. A relay without an
	// access key sends alert 1 for these.
	ErrBadMessage = errors.New("bad handshake message")

	// ErrUnsupportedVersion means the client read a frame whose
	// magic is KR and whose version byte is not 2. The check
	// includes alerts.
	ErrUnsupportedVersion = errors.New("unsupported relay leg version")

	// ErrRelayAuthFailed means the client rejected ServerHello
	// because finished_r did not match.
	ErrRelayAuthFailed = errors.New("relay authentication failed")

	// ErrPSKUnexpected means the relay has no access key and the
	// client set the PSK flag. It is alert 2.
	ErrPSKUnexpected = errors.New("unexpected access key")

	// ErrRelayKeyNotHeld means the ClientHello key hint is not the
	// hint of the key the relay holds. It is alert 3.
	ErrRelayKeyNotHeld = errors.New("relay does not hold this key")

	// ErrHandshakeRejected means the peer closed the connection
	// before ServerHello and sent no alert. The access key may be
	// wrong or missing, or the peer may not be a kamune v2 relay.
	ErrHandshakeRejected = errors.New("the relay closed the " +
		"connection during the relay-leg handshake: wrong or " +
		"missing access key, or not a kamune v2 relay")

	// ErrSilentReject means Accept refused the first frame and
	// wrote nothing. The caller waits for SilentDelay, then closes.
	ErrSilentReject = errors.New("silent reject")

	// ErrRecordAuth means a record failed to open. The caller
	// closes the channel. A reordered, replayed, modified or
	// dropped record fails this way.
	ErrRecordAuth = errors.New("record authentication failed")

	// ErrFrameTooLarge is returned by a Channel write when the
	// sealed frame would exceed the limit reported by the
	// underlying FrameLimiter. The frame is rejected before
	// encryption, so the Channel stays usable.
	ErrFrameTooLarge = errors.New("sealed frame exceeds the frame limit")

	// ErrChannelBroken is returned by every Channel write after a
	// sealed frame could not be written, and when a direction's
	// sequence number reaches 2^64-1. The failed frame consumed a
	// sequence number the peer never saw, so no later frame could
	// be opened by the peer.
	ErrChannelBroken = errors.New("channel broken by a failed write")
)
