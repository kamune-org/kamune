package main

import (
	"fmt"

	"github.com/kamune-org/kamune"
	"github.com/kamune-org/kamune/pkg/storage"
)

func serve(addr string, store *storage.Storage, verifyFn kamune.RemoteVerifier,
	connCh chan<- *kamune.Transport, doneCh <-chan struct{},
	opts ...kamune.ServerOptions,
) (*kamune.Server, error) {
	handler := func(t *kamune.Transport) error {
		connCh <- t
		<-doneCh
		return nil
	}

	srvOpts := []kamune.ServerOptions{
		kamune.ServeWithRemoteVerifier(verifyFn),
	}
	srvOpts = append(srvOpts, opts...)

	srv, err := kamune.NewServer(addr, handler, store, srvOpts...)
	if err != nil {
		return nil, fmt.Errorf("create server: %w", err)
	}

	go func() {
		srv.ListenAndServe()
	}()

	return srv, nil
}
