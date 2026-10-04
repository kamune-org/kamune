package main

import (
	"context"
	"fmt"
	"time"

	"github.com/kamune-org/kamune"
	"github.com/kamune-org/kamune/pkg/relayconn"
	"github.com/kamune-org/kamune/pkg/storage"
)

// relayServe registers with the relay and starts a server on the
// registration, which hands its session to deliver as serve does. It
// returns the server and the token for the peer. Cancelling ctx ends the
// registration while it is in progress; the server then lasts until it is
// closed.
func relayServe(
	ctx context.Context, relayAddr, password string, store *storage.Storage,
	verifyFn kamune.RemoteVerifier,
	deliver func(t *kamune.Transport, release chan struct{}),
) (*kamune.Server, []byte, time.Duration, error) {
	var relayOpts []relayconn.Option
	if password != "" {
		relayOpts = append(relayOpts, relayconn.WithPassword(password))
	}

	result, err := relayconn.ListenRelay(ctx, relayAddr, relayOpts...)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("relay listen: %w", err)
	}

	srv, err := serve("", store, verifyFn, deliver,
		kamune.ServeWithListener(result.Listener),
	)
	if err != nil {
		_ = result.Listener.Close()
		return nil, nil, 0, err
	}

	return srv, result.Token, result.SessionTTL, nil
}
