package main

import (
	"context"
	"fmt"

	"github.com/kamune-org/kamune"
	"github.com/kamune-org/kamune/pkg/relayconn"
	"github.com/kamune-org/kamune/pkg/storage"
)

func relayServe(relayAddr, password string, store *storage.Storage, verifyFn kamune.RemoteVerifier,
	connCh chan<- *kamune.Transport, doneCh <-chan struct{},
) (*kamune.Server, []byte, error) {
	ctx := context.Background()
	var relayOpts []relayconn.Option
	if password != "" {
		relayOpts = append(relayOpts, relayconn.WithPassword(password))
	}

	listener, token, err := relayconn.ListenRelay(ctx, relayAddr, relayOpts...)
	if err != nil {
		return nil, nil, fmt.Errorf("relay listen: %w", err)
	}

	srv, err := serve("", store, verifyFn, connCh, doneCh,
		kamune.ServeWithListener(listener),
	)
	if err != nil {
		return nil, nil, err
	}

	return srv, token, nil
}
