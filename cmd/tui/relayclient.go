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

// relayDial joins the relay session named by tokenHex and runs the kamune
// handshake through it. Cancelling ctx ends the dial at any step.
func relayDial(
	ctx context.Context, relayAddr, tokenHex, password string,
	store *storage.Storage, verifyFn kamune.RemoteVerifier,
) (*kamune.Transport, time.Duration, error) {
	token, err := hex.DecodeString(tokenHex)
	if err != nil {
		return nil, 0, fmt.Errorf("decode token: %w", err)
	}

	var opts []relayconn.Option
	if password != "" {
		opts = append(opts, relayconn.WithPassword(password))
	}

	var sessionTTL time.Duration
	t, err := dialBound(ctx, relayAddr, store, verifyFn,
		func(ctx context.Context, addr string) (kamune.Conn, error) {
			conn, err := relayconn.DialRelay(ctx, addr, token, opts...)
			if err != nil {
				return nil, err
			}
			sessionTTL = conn.SessionTTL()
			return conn, nil
		},
	)
	if err != nil {
		return nil, 0, err
	}
	return t, sessionTTL, nil
}
