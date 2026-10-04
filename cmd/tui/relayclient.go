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
// the kamune handshake through it. It returns the session and the time
// the relay ends it, or the zero time if the relay does not. Cancelling
// ctx ends the dial at any step.
func relayDial(
	ctx context.Context, r relayTarget, tokenHex, password string,
	store *storage.Storage, verifyFn kamune.RemoteVerifier,
) (*kamune.Transport, time.Time, error) {
	token, err := hex.DecodeString(tokenHex)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("decode token: %w", err)
	}

	var opts []relayconn.Option
	if password != "" {
		opts = append(opts, relayconn.WithPassword(password))
	}

	var expiry time.Time
	t, err := dialBound(ctx, r.host, store, verifyFn,
		func(ctx context.Context, _ string) (kamune.Conn, error) {
			// The relay starts the session's lifetime when the dialer
			// joins, which is after this and before the dial returns.
			// Count from here, so as not to promise too much time.
			start := time.Now()
			conn, err := r.dial(ctx, token, opts...)
			if err != nil {
				return nil, hungUp(err, "the relay password and the token")
			}
			if ttl := conn.SessionTTL(); ttl > 0 {
				expiry = start.Add(ttl)
			}
			return conn, nil
		},
	)
	if err != nil {
		return nil, time.Time{}, err
	}
	return t, expiry, nil
}
