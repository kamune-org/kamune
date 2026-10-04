package relayconn

import (
	"context"
	"slices"
	"time"
)

// DefaultHandshakeTimeout bounds the relay handshake of the Dial and
// Listen helpers when WithHandshakeTimeout is not given: connecting to
// the relay, TLS, the HPKE exchange, PSK auth and the relay's Registered
// reply. It does not limit the connection once the handshake is done.
const DefaultHandshakeTimeout = 30 * time.Second

type options struct {
	deadline         time.Time
	password         string
	token            []byte
	handshakeTimeout time.Duration
}

type Option func(*options)

func buildOptions(opts []Option) options {
	o := options{handshakeTimeout: DefaultHandshakeTimeout}
	for _, opt := range opts {
		opt(&o)
	}
	return o
}

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

// WithHandshakeTimeout bounds the relay handshake of the Dial and Listen
// helpers: connecting to the relay, TLS, the HPKE exchange, PSK auth and
// the relay's Registered reply. The context passed to the helper still
// applies, so the earlier of the two ends the handshake. A zero or
// negative d removes the bound, leaving only the context. The default is
// DefaultHandshakeTimeout.
func WithHandshakeTimeout(d time.Duration) Option {
	return func(o *options) {
		o.handshakeTimeout = d
	}
}

// withHandshakeDeadline makes the relay handshake end at t. The Dial
// and Listen helpers set it so that the handshake shares one deadline
// with the connect that comes before it.
func withHandshakeDeadline(t time.Time) Option {
	return func(o *options) {
		o.deadline = t
	}
}

// startHandshake applies the handshake timeout from opts. It returns
// the context to connect to the relay with and the options to pass to
// the handshake, which carry the same deadline. The caller must call
// the returned cancel function.
func startHandshake(
	ctx context.Context, opts []Option,
) (context.Context, context.CancelFunc, []Option) {
	o := buildOptions(opts)
	if o.handshakeTimeout <= 0 {
		return ctx, func() {}, opts
	}
	deadline := time.Now().Add(o.handshakeTimeout)
	dctx, cancel := context.WithDeadline(ctx, deadline)
	opts = append(slices.Clip(opts), withHandshakeDeadline(deadline))
	return dctx, cancel, opts
}

// handshakeContext returns the context that bounds the relay handshake:
// ctx, cut short by the deadline in o when there is one.
func (o *options) handshakeContext(
	ctx context.Context,
) (context.Context, context.CancelFunc) {
	if o.deadline.IsZero() {
		return context.WithCancel(ctx)
	}
	return context.WithDeadline(ctx, o.deadline)
}
