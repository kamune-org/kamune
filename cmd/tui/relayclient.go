package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/kamune-org/kamune"
	"github.com/kamune-org/kamune/pkg/relayconn"
	"github.com/kamune-org/kamune/pkg/storage"
)

func relayDial(relayAddr, tokenHex, password string, store *storage.Storage, verifyFn kamune.RemoteVerifier) (*kamune.Transport, time.Duration, error) {
	token, err := hex.DecodeString(tokenHex)
	if err != nil {
		return nil, 0, fmt.Errorf("decode token: %w", err)
	}

	ctx := context.Background()
	var opts []relayconn.Option
	if password != "" {
		opts = append(opts, relayconn.WithPassword(password))
	}

	var sessionTTL time.Duration
	dialer, err := kamune.NewDialer(relayAddr, store,
		kamune.DialWithRemoteVerifier(verifyFn),
		kamune.DialWithFunc(func(addr string) (kamune.Conn, error) {
			conn, err := relayconn.DialRelay(ctx, addr, token, opts...)
			if err != nil {
				return nil, err
			}
			sessionTTL = conn.SessionTTL()
			return conn, nil
		}),
	)
	if err != nil {
		return nil, 0, fmt.Errorf("create dialer: %w", err)
	}
	t, err := dialer.Dial()
	if err != nil {
		return nil, 0, err
	}
	return t, sessionTTL, nil
}
