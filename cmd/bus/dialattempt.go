package main

import (
	"context"
	"io"
	"net"
	"slices"
	"sync"
	"time"

	"github.com/xtaci/kcp-go/v5"

	"github.com/kamune-org/kamune"
)

// dialTimeout bounds a TCP connect, as the kamune dialer's default does.
const dialTimeout = 10 * time.Second

// dialAttempt is a ConnectToServer call in progress, which CancelConnect
// cancels through ctx. Every step of the call that waits on the network
// or on the user ends with ctx: the broker match and hole punch, the
// relay handshake, the verification prompt, and, by closing the
// connection under it, the kamune handshake.
type dialAttempt struct {
	ctx    context.Context
	cancel context.CancelFunc
	// id is the attempt ID that the window gave the call, by which
	// CancelConnect finds it. An attempt without one can only end with
	// the app.
	id string

	mu sync.Mutex
	// stops unregisters the closing of each connection of the attempt
	// on cancel; see closeOnCancel.
	stops []func() bool
}

// closeOnCancel closes c once the attempt is cancelled, until keep. It
// closes c at once when the attempt is already cancelled.
func (d *dialAttempt) closeOnCancel(c io.Closer) {
	stop := context.AfterFunc(d.ctx, func() { _ = c.Close() })
	d.mu.Lock()
	d.stops = append(d.stops, stop)
	d.mu.Unlock()
}

// guard wraps fn so that the connection it returns is closed once the
// attempt is cancelled, until keep.
func (d *dialAttempt) guard(
	fn func(addr string) (kamune.Conn, error),
) func(addr string) (kamune.Conn, error) {
	return func(addr string) (kamune.Conn, error) {
		if err := d.ctx.Err(); err != nil {
			return nil, err
		}
		c, err := fn(addr)
		if err != nil {
			return nil, err
		}
		d.closeOnCancel(c)
		return c, nil
	}
}

// keep ends the attempt's hold on its connections, so that they stay
// open after the attempt, and reports whether it was not cancelled
// first. A cancelled attempt has closed its connections, or is closing
// them.
func (d *dialAttempt) keep() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	kept := d.ctx.Err() == nil
	for _, stop := range d.stops {
		if !stop() {
			kept = false
		}
	}
	d.stops = nil
	return kept
}

// dialTCPWithin returns a dial function for TCP whose connect ends with
// ctx.
func dialTCPWithin(
	ctx context.Context,
) func(addr string) (kamune.Conn, error) {
	return func(addr string) (kamune.Conn, error) {
		d := net.Dialer{Timeout: dialTimeout}
		c, err := d.DialContext(ctx, "tcp", addr)
		if err != nil {
			return nil, err
		}
		return kamune.NewConn(c), nil
	}
}

// dialUDP dials a KCP session over UDP, as kamune.DialWithUDP does.
func dialUDP(addr string) (kamune.Conn, error) {
	c, err := kcp.Dial(addr)
	if err != nil {
		return nil, err
	}
	return kamune.NewConn(c), nil
}

// beginDial registers a new dial attempt with the attempt ID id, which
// CancelConnect and shutdown cancel. It is cancelled from the start when
// CancelConnect named id before it began. The caller ends it with
// endDial.
func (a *App) beginDial(id string) *dialAttempt {
	ctx, cancel := context.WithCancel(a.lifeCtx())
	d := &dialAttempt{ctx: ctx, cancel: cancel, id: id}
	a.mu.Lock()
	if a.dialAttempts == nil {
		a.dialAttempts = make(map[*dialAttempt]struct{})
	}
	a.dialAttempts[d] = struct{}{}
	if i := slices.Index(a.earlyCancels, id); id != "" && i >= 0 {
		a.earlyCancels = slices.Delete(a.earlyCancels, i, i+1)
		cancel()
	}
	a.mu.Unlock()
	return d
}

// keepDial takes d out of reach of CancelConnect and keeps its
// connections open. It reports false, and the caller must drop what d
// dialed, when d was cancelled first.
func (a *App) keepDial(d *dialAttempt) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.dialAttempts, d)
	return d.keep()
}

// endDial ends d. A connection that keepDial did not keep is closed.
func (a *App) endDial(d *dialAttempt) {
	a.mu.Lock()
	delete(a.dialAttempts, d)
	a.mu.Unlock()
	d.cancel()
}

// maxEarlyCancels bounds the attempt IDs that CancelConnect keeps for
// attempts that it did not find; see CancelConnect.
const maxEarlyCancels = 8

// CancelConnect cancels the ConnectToServer call with the attempt ID
// attemptID, and no other. A call that has not established its session
// yet stops, closes what it opened and returns the error code
// "cancelled"; one that has goes on, and its session is listed as usual.
//
// The window's calls may reach the app out of order, so a call that is
// not found yet is cancelled once it begins. CancelConnect keeps the
// last maxEarlyCancels such IDs, and ignores an empty one.
func (a *App) CancelConnect(attemptID string) {
	if attemptID == "" {
		return
	}
	a.mu.Lock()
	found := false
	for d := range a.dialAttempts {
		if d.id == attemptID {
			d.cancel()
			found = true
		}
	}
	if !found && !slices.Contains(a.earlyCancels, attemptID) {
		a.earlyCancels = append(a.earlyCancels, attemptID)
		if n := len(a.earlyCancels) - maxEarlyCancels; n > 0 {
			a.earlyCancels = slices.Delete(a.earlyCancels, 0, n)
		}
	}
	a.mu.Unlock()
	if found {
		a.addLogEntry("INFO", "Connection attempt cancelled by user")
	}
}
