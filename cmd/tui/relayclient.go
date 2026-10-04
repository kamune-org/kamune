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

// relayDial joins the session named by tokenHex on the relay r and runs
// the kamune handshake through it. Cancelling ctx ends the dial at any
// step.
func relayDial(
	ctx context.Context, r relayTarget, tokenHex, password string,
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
	t, err := dialBound(ctx, r.host, store, verifyFn,
		func(ctx context.Context, _ string) (kamune.Conn, error) {
			conn, err := r.dial(ctx, token, opts...)
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
