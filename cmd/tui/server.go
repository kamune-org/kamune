package main

import (
	"fmt"

	"github.com/kamune-org/kamune"
	"github.com/kamune-org/kamune/pkg/storage"
)

// serve starts a server on addr that hands each session it establishes to
// deliver, with a release channel. The handler then waits until release
// is closed, since the session's connection is closed when it returns.
func serve(addr string, store *storage.Storage, verifyFn kamune.RemoteVerifier,
	deliver func(t *kamune.Transport, release chan struct{}),
	opts ...kamune.ServerOptions,
) (*kamune.Server, error) {
	handler := func(t *kamune.Transport) error {
		release := make(chan struct{})
		deliver(t, release)
		<-release
		return nil
	}

	srv, err := kamune.NewServer(addr, handler, store, verifyFn, opts...)
	if err != nil {
		return nil, fmt.Errorf("create server: %w", err)
	}

	go func() {
		srv.ListenAndServe()
	}()

	return srv, nil
}
