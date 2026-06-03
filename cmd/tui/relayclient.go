package main

import (
	"context"
	"encoding/hex"
	"fmt"

	"github.com/kamune-org/kamune"
	"github.com/kamune-org/kamune/pkg/relayconn"
	"github.com/kamune-org/kamune/pkg/storage"
)

func relayDial(relayAddr, tokenHex, password string, store *storage.Storage, verifyFn kamune.RemoteVerifier) (*kamune.Transport, error) {
	token, err := hex.DecodeString(tokenHex)
	if err != nil {
		return nil, fmt.Errorf("decode token: %w", err)
	}

	ctx := context.Background()
	var opts []relayconn.Option
	if password != "" {
		opts = append(opts, relayconn.WithPassword(password))
	}

	dialer, err := kamune.NewDialer(relayAddr, store,
		kamune.DialWithRemoteVerifier(verifyFn),
		kamune.DialWithFunc(func(addr string) (kamune.Conn, error) {
			return relayconn.DialRelay(ctx, addr, token, opts...)
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("create dialer: %w", err)
	}
	return dialer.Dial()
}
