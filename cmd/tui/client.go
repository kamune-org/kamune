package main

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/kamune-org/kamune"
	"github.com/kamune-org/kamune/pkg/storage"
)

// tcpDialTimeout bounds the TCP connect of a direct dial, as the kamune
// dialer does by default.
const tcpDialTimeout = 10 * time.Second

// dial connects to addr over TCP and runs the kamune handshake. Cancelling
// ctx ends the dial at any step.
func dial(
	ctx context.Context, addr string, store *storage.Storage,
	verifyFn kamune.RemoteVerifier,
) (*kamune.Transport, error) {
	return dialBound(ctx, addr, store, verifyFn,
		func(ctx context.Context, addr string) (kamune.Conn, error) {
			d := net.Dialer{Timeout: tcpDialTimeout}
			c, err := d.DialContext(ctx, "tcp", addr)
			if err != nil {
				return nil, fmt.Errorf("dialing tcp: %w", err)
			}
			return kamune.NewConn(c), nil
		},
	)
}

// dialBound runs a kamune dial to addr over the connection that connect
// opens, and ties it to ctx: connect gets ctx, and when ctx ends before
// the handshake does, the connection is closed, which ends the handshake.
// It returns an error wrapping ctx.Err() when ctx ends before the dial
// returns.
func dialBound(
	ctx context.Context, addr string, store *storage.Storage,
	verifyFn kamune.RemoteVerifier,
	connect func(context.Context, string) (kamune.Conn, error),
) (*kamune.Transport, error) {
	// stop is set by the dial function, which Dial calls on this
	// goroutine.
	stop := func() bool { return ctx.Err() == nil }
	dialer, err := kamune.NewDialer(addr, store, verifyFn,
		kamune.DialWithFunc(func(addr string) (kamune.Conn, error) {
			cn, err := connect(ctx, addr)
			if err != nil {
				return nil, err
			}
			stop = context.AfterFunc(ctx, func() { _ = cn.Close() })
			return cn, nil
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("create dialer: %w", err)
	}
	t, err := dialer.Dial()
	if !stop() {
		// ctx ended, and the connection was closed or is closing.
		if t != nil {
			_ = t.Close()
		}
		return nil, fmt.Errorf("dial cancelled: %w", ctx.Err())
	}
	return t, err
}
