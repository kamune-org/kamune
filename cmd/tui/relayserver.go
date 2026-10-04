package main

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/kamune-org/kamune"
	"github.com/kamune-org/kamune/pkg/relayconn"
	"github.com/kamune-org/kamune/pkg/storage"
)

// relayServe registers with the relay r and starts a server on the
// registration, which hands its session to deliver as serve does, with
// the time the relay ends that session, or the zero time if it does not.
// It returns the server, the token for the peer and the relay's session
// TTL. Cancelling ctx ends the registration while it is in progress; the
// server then lasts until it is closed. The registration takes a single
// connection: once that ends, or the relay drops the registration, the
// server stops and stopped gets what ListenAndServe returned.
func relayServe(
	ctx context.Context, r relayTarget, password string,
	store *storage.Storage,
	verifyFn kamune.RemoteVerifier,
	deliver func(
		t *kamune.Transport, release chan struct{}, expiry time.Time,
	),
	stopped func(error),
) (*kamune.Server, []byte, time.Duration, error) {
	var relayOpts []relayconn.Option
	if password != "" {
		relayOpts = append(relayOpts, relayconn.WithPassword(password))
	}

	result, err := r.listen(ctx, relayOpts...)
	if err != nil {
		return nil, nil, 0, fmt.Errorf(
			"relay listen: %w", hungUp(err, "the relay password"),
		)
	}

	l := &joinListener{Listener: result.Listener}
	ttl := result.SessionTTL
	srv, err := serve("", store, verifyFn,
		func(t *kamune.Transport, release chan struct{}) {
			deliver(t, release, l.expiry(ttl))
		},
		stopped, kamune.ServeWithListener(l),
	)
	if err != nil {
		_ = result.Listener.Close()
		return nil, nil, 0, err
	}

	return srv, result.Token, result.SessionTTL, nil
}

// joinListener is a relay listener that notes when it accepts its
// connection. The relay starts the lifetime of a session when the peer
// joins it, and passes on the peer's first frame right after, which is
// when Accept returns.
type joinListener struct {
	kamune.Listener
	joined atomic.Pointer[time.Time]
}

func (l *joinListener) Accept() (kamune.Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil {
		now := time.Now()
		l.joined.CompareAndSwap(nil, &now)
	}
	return c, err
}

// expiry returns when the relay ends the session that l accepted, given
// the relay's session TTL, or the zero time if it does not end it.
func (l *joinListener) expiry(ttl time.Duration) time.Time {
	joined := l.joined.Load()
	if ttl <= 0 || joined == nil {
		return time.Time{}
	}
	return joined.Add(ttl)
}
