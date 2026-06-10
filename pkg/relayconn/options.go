package relayconn

type options struct {
	password string
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
