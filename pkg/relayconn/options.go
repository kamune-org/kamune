package relayconn

type options struct {
	password string
	token    []byte
}

type Option func(*options)

// WithPassword sets a pre-shared key for relay authentication. The
// password is sent to the relay server after HPKE key exchange but
// before registration.
func WithPassword(pass string) Option {
	return func(o *options) {
		o.password = pass
	}
}

// WithToken sets a precomputed session token for the listener. When
// non-empty, the listener sends Register{Mode: MODE_CREATE, Token: t}
// instead of asking the relay to generate one. Use with TokenFromKeys
// to derive the token from the two contacts' public keys.
func WithToken(t []byte) Option {
	return func(o *options) {
		o.token = t
	}
}
