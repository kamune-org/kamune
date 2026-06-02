package relayconn

type options struct {
	password string
}

type Option func(*options)

func WithPassword(pass string) Option {
	return func(o *options) {
		o.password = pass
	}
}
