package relayleg

import "errors"

var (
	// ErrInvalidRelayKey means a relay public key is missing,
	// malformed, not canonical, or all zeros.
	ErrInvalidRelayKey = errors.New("invalid relay key")

	// ErrInvalidPSK means an access key is missing, malformed, not
	// canonical, or all zeros.
	ErrInvalidPSK = errors.New("invalid PSK")

	// ErrKeyUsage means ExtractShared was called with a domain that
	// does not start with "kamune broker v2".
	ErrKeyUsage = errors.New("invalid key usage")
)
