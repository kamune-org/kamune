package main

import (
	"fmt"

	"github.com/kamune-org/kamune"
	"github.com/kamune-org/kamune/pkg/storage"
)

func dial(addr string, store *storage.Storage, verifyFn kamune.RemoteVerifier) (*kamune.Transport, error) {
	dialer, err := kamune.NewDialer(addr, store, verifyFn)
	if err != nil {
		return nil, fmt.Errorf("create dialer: %w", err)
	}
	return dialer.Dial()
}
