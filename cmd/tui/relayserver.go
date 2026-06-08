package main

import (
	"context"
	"fmt"
	"time"

	"github.com/kamune-org/kamune"
	"github.com/kamune-org/kamune/pkg/relayconn"
	"github.com/kamune-org/kamune/pkg/storage"
)

func relayServe(relayAddr, password string, store *storage.Storage, verifyFn kamune.RemoteVerifier,
	connCh chan<- *kamune.Transport, doneCh <-chan struct{},
) (*kamune.Server, []byte, time.Duration, error) {
	ctx := context.Background()
	var relayOpts []relayconn.Option
	if password != "" {
		relayOpts = append(relayOpts, relayconn.WithPassword(password))
	}

	result, err := relayconn.ListenRelay(ctx, relayAddr, relayOpts...)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("relay listen: %w", err)
	}

	srv, err := serve("", store, verifyFn, connCh, doneCh,
		kamune.ServeWithListener(result.Listener),
	)
	if err != nil {
		return nil, nil, 0, err
	}

	return srv, result.Token, result.SessionTTL, nil
}
