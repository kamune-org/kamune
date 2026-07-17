package services

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/kamune-org/kamune/pkg/exchange"
	"github.com/kamune-org/kamune/pkg/relayconn"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/kamune-org/kamune/pkg/relayconn/pb"
)

// pipeChans returns a pair of *exchange.Channel values backed by an
// in-memory net.Pipe. One end Initiates, the other Accepts. Either can be
// closed independently to simulate a peer disconnect. The returned cleanup
// function closes the underlying pipes.
func pipeChans(t *testing.T) (a, b *exchange.Channel, cleanup func()) {
	t.Helper()
	r := require.New(t)

	c, s := net.Pipe()

	var (
		mu       sync.Mutex
		chB      *exchange.Channel
		acceptCh = make(chan error, 1)
	)

	go func() {
		ch, err := exchange.Accept(&testAdapter{conn: s})
		mu.Lock()
		chB = ch
		mu.Unlock()
		acceptCh <- err
	}()

	chA, err := exchange.Initiate(&testAdapter{conn: c})
	r.NoError(err, "exchange.Initiate")
	r.NoError(<-acceptCh, "exchange.Accept")

	mu.Lock()
	defer mu.Unlock()
	r.NotNil(chB, "accept did not complete")

	cleanup = func() {
		_ = c.Close()
		_ = s.Close()
	}
	return chA, chB, cleanup
}

// testAdapter is a length-prefixed framing adapter used to drive the
// HPKE exchange over net.Pipe. Framing matches cmd/relay's rawTCPAdapter
// and pkg/relayconn's tcpAdapter.
type testAdapter struct {
	conn net.Conn
}

func (t *testAdapter) ReadBytes() ([]byte, error) {
	var length uint16
	if err := binary.Read(t.conn, binary.BigEndian, &length); err != nil {
		return nil, err
	}
	buf := make([]byte, length)
	if _, err := io.ReadFull(t.conn, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func (t *testAdapter) WriteBytes(data []byte) error {
	if err := binary.Write(t.conn, binary.BigEndian, uint16(len(data))); err != nil {
		return err
	}
	_, err := t.conn.Write(data)
	return err
}

func (t *testAdapter) Close() error                { return t.conn.Close() }
func (t *testAdapter) SetDeadline(time.Time) error { return nil }

// drainRead discards all incoming bytes on the channel by reading frames
// until an error is returned. Used in tests to unblock a peer's HPKE
// exchange or registration flow.
func drainRead(t *testing.T, ch *exchange.Channel) {
	t.Helper()
	go func() {
		for {
			if _, err := ch.ReadBytes(); err != nil {
				return
			}
		}
	}()
}

// sendFrame marshals and writes a Frame over the exchange channel.
func sendFrame(t *testing.T, ch *exchange.Channel, f *pb.Frame) {
	t.Helper()
	a := require.New(t)
	b, err := proto.Marshal(f)
	a.NoError(err, "marshal")
	a.NoError(ch.WriteBytes(b), "write")
}

func newTestSessionManager(tokenTTL, sessionTTL time.Duration, maxConns int) *SessionManager {
	return NewSessionManager(tokenTTL, maxConns, sessionTTL)
}

// --- SessionManager tests ------------------------------------------------

func TestSessionManager_Create_Roundtrip(t *testing.T) {
	a := require.New(t)
	sm := newTestSessionManager(time.Minute, 0, 10)
	defer sm.Remove(nil) // no-op, just to ensure no panic

	listener, _, cleanup := pipeChans(t)
	defer cleanup()
	defer listener.Close()

	token, err := sm.Create(listener)
	a.NoError(err, "Create")
	a.Len(token, 16)
	a.Equal(1, sm.Len())
}

func TestSessionManager_Create_RespectsMaxConns(t *testing.T) {
	a := require.New(t)
	sm := newTestSessionManager(time.Minute, 0, 2)
	for range 2 {
		_, _, cleanup := pipeChans(t)
		// We don't keep the channel around — we only need to fill the map.
		// But we need to keep the channel alive, so do it differently.
		cleanup()
	}

	// Re-do with proper channel retention.
	sm = newTestSessionManager(time.Minute, 0, 2)

	l1, _, c1 := pipeChans(t)
	defer c1()
	defer l1.Close()
	_, err := sm.Create(l1)
	a.NoError(err, "Create 1")

	l2, _, c2 := pipeChans(t)
	defer c2()
	defer l2.Close()
	_, err = sm.Create(l2)
	a.NoError(err, "Create 2")

	// Third should fail.
	l3, _, c3 := pipeChans(t)
	defer c3()
	defer l3.Close()
	_, err = sm.Create(l3)
	a.ErrorIs(err, ErrSessionFull)
}

func TestSessionManager_Join_RejectsUnknownToken(t *testing.T) {
	a := require.New(t)
	sm := newTestSessionManager(time.Minute, 0, 10)

	dialer, _, cleanup := pipeChans(t)
	defer cleanup()
	defer dialer.Close()

	err := sm.Join([]byte("doesnt-exist"), dialer)
	a.ErrorIs(err, ErrTokenNotFound)
}

func TestSessionManager_Join_RejectsConsumed(t *testing.T) {
	a := require.New(t)
	sm := newTestSessionManager(time.Minute, 0, 10)

	listener, _, cleanup := pipeChans(t)
	defer cleanup()
	defer listener.Close()

	token, err := sm.Create(listener)
	a.NoError(err, "Create")

	dialer1, dialerRemote1, cleanup1 := pipeChans(t)
	defer cleanup1()
	a.NoError(sm.Join(token, dialer1), "first Join")
	_ = dialerRemote1

	// Second join with the same token must fail.
	dialer2, _, cleanup2 := pipeChans(t)
	defer cleanup2()
	defer dialer2.Close()
	a.ErrorIs(sm.Join(token, dialer2), ErrTokenConsumed)
}

func TestSessionManager_Join_RejectsExpired(t *testing.T) {
	a := require.New(t)
	sm := newTestSessionManager(10*time.Millisecond, 0, 10)

	listener, _, cleanup := pipeChans(t)
	defer cleanup()
	defer listener.Close()

	token, err := sm.Create(listener)
	a.NoError(err, "Create")

	time.Sleep(20 * time.Millisecond)

	dialer, _, cleanup2 := pipeChans(t)
	defer cleanup2()
	defer dialer.Close()
	a.ErrorIs(sm.Join(token, dialer), ErrSessionExpired)
}

func TestSessionManager_Recipient_DirectionAware(t *testing.T) {
	a := require.New(t)
	sm := newTestSessionManager(time.Minute, 0, 10)

	listener, _, cleanup := pipeChans(t)
	defer cleanup()
	defer listener.Close()
	dialer, _, cleanup2 := pipeChans(t)
	defer cleanup2()
	defer dialer.Close()

	token, err := sm.Create(listener)
	a.NoError(err, "Create")
	a.NoError(sm.Join(token, dialer), "Join")

	// From listener's perspective, recipient is the dialer.
	got, err := sm.Recipient(token, listener)
	a.NoError(err, "Recipient(listener)")
	a.Equal(dialer, got, "Recipient(listener) returned wrong peer")

	// From dialer's perspective, recipient is the listener.
	got, err = sm.Recipient(token, dialer)
	a.NoError(err, "Recipient(dialer)")
	a.Equal(listener, got, "Recipient(dialer) returned wrong peer")

	// From a stranger, returns error.
	stranger, _, cleanup3 := pipeChans(t)
	defer cleanup3()
	defer stranger.Close()
	_, err = sm.Recipient(token, stranger)
	a.ErrorIs(err, ErrPeerNotFound)
}

func TestSessionManager_Recipient_ListenerOnlyHasNoPeer(t *testing.T) {
	a := require.New(t)
	sm := newTestSessionManager(time.Minute, 0, 10)

	listener, _, cleanup := pipeChans(t)
	defer cleanup()
	defer listener.Close()

	token, err := sm.Create(listener)
	a.NoError(err, "Create")

	_, err = sm.Recipient(token, listener)
	a.ErrorIs(err, ErrPeerNotFound, "Recipient(listener, no peer)")
}

func TestSessionManager_ClosePeerChannel_ClosesPeer(t *testing.T) {
	a := require.New(t)
	sm := newTestSessionManager(time.Minute, 0, 10)

	listener, dialerRemote, cleanup := pipeChans(t)
	defer cleanup()
	dialer, dialerRemote2, cleanup2 := pipeChans(t)
	defer cleanup2()

	token, err := sm.Create(listener)
	a.NoError(err, "Create")
	a.NoError(sm.Join(token, dialer), "Join")
	_ = dialerRemote
	_ = dialerRemote2

	// Drain the remote ends so peer Close() doesn't block on a write to
	// the disconnected half of net.Pipe.
	drainRead(t, dialerRemote)
	drainRead(t, dialerRemote2)

	// Closing the listener should close the dialer.
	sm.ClosePeerChannel(token, listener)

	// The dialer should now be closed: a ReadBytes on its pipe should
	// return an error shortly.
	done := make(chan error, 1)
	go func() {
		_, err := dialer.ReadBytes()
		done <- err
	}()
	select {
	case err := <-done:
		a.Error(err, "dialer ReadBytes returned nil after peer close")
	case <-time.After(2 * time.Second):
		a.FailNow("dialer ReadBytes did not return after peer close")
	}
}

func TestSessionManager_Remove_Idempotent(t *testing.T) {
	a := require.New(t)
	sm := newTestSessionManager(time.Minute, 0, 10)

	listener, _, cleanup := pipeChans(t)
	defer cleanup()
	defer listener.Close()

	token, err := sm.Create(listener)
	a.NoError(err, "Create")

	sm.Remove(token)
	a.Equal(0, sm.Len())

	// Remove again — must not panic.
	sm.Remove(token)
	sm.Remove([]byte("never-existed"))
}

func TestSessionManager_PurgeExpired_UnpairedSession(t *testing.T) {
	a := require.New(t)
	sm := newTestSessionManager(20*time.Millisecond, 0, 10)

	listener, _, cleanup := pipeChans(t)
	defer cleanup()

	// drain the remote end so listener.Close() during purge doesn't block
	drainRead(t, listener)

	token, err := sm.Create(listener)
	a.NoError(err, "Create")

	// Wait past the token TTL.
	time.Sleep(40 * time.Millisecond)

	// Purge manually.
	sm.purgeExpired()

	// Session is gone.
	a.Equal(0, sm.Len())

	_ = token
}

func TestSessionManager_PurgeExpired_PairedSession(t *testing.T) {
	a := require.New(t)
	sm := newTestSessionManager(time.Minute, 30*time.Millisecond, 10)

	listener, listenerRemote, cleanup := pipeChans(t)
	defer cleanup()
	dialer, dialerRemote, cleanup2 := pipeChans(t)
	defer cleanup2()

	drainRead(t, listenerRemote)
	drainRead(t, dialerRemote)

	token, err := sm.Create(listener)
	a.NoError(err, "Create")
	a.NoError(sm.Join(token, dialer), "Join")

	// Session should still be alive before expiry.
	a.Equal(1, sm.Len())

	time.Sleep(60 * time.Millisecond)
	sm.purgeExpired()

	a.Equal(0, sm.Len())
}

func TestSessionManager_PurgeExpired_NeverExpiresWhenSessionTTLZero(t *testing.T) {
	a := require.New(t)
	sm := newTestSessionManager(10*time.Millisecond, 0, 10)

	listener, listenerRemote, cleanup := pipeChans(t)
	defer cleanup()
	dialer, dialerRemote, cleanup2 := pipeChans(t)
	defer cleanup2()

	drainRead(t, listenerRemote)
	drainRead(t, dialerRemote)

	token, err := sm.Create(listener)
	a.NoError(err, "Create")
	a.NoError(sm.Join(token, dialer), "Join")

	time.Sleep(30 * time.Millisecond)
	sm.purgeExpired()

	// sessionTTL=0 → paired sessions should not be purged.
	a.Equal(1, sm.Len(), "sessionTTL=0 should disable purge")
}

func TestSessionManager_TTL_And_SessionTTL(t *testing.T) {
	a := require.New(t)
	sm := NewSessionManager(5*time.Minute, 10, 30*time.Minute)
	a.Equal(5*time.Minute, sm.TTL())
	a.Equal(30*time.Minute, sm.SessionTTL())
}

// --- CreateWith (static-token mode) ---------------------------------------

// makeToken builds a deterministic 32-byte token with byte i set to i+seed.
func makeToken(seed byte) []byte {
	tok := make([]byte, 32)
	for i := range tok {
		tok[i] = seed + byte(i)
	}
	return tok
}

func TestSessionManager_CreateWith_HappyPath(t *testing.T) {
	a := require.New(t)
	sm := newTestSessionManager(time.Minute, 0, 10)

	listener, listenerRemote, cleanup := pipeChans(t)
	defer cleanup()
	dialer, dialerRemote, cleanup2 := pipeChans(t)
	defer cleanup2()
	drainRead(t, listenerRemote)
	drainRead(t, dialerRemote)

	token := makeToken(0x10)
	a.NoError(sm.CreateWith(listener, token), "CreateWith")
	a.Equal(1, sm.Len())

	a.NoError(sm.Join(token, dialer), "Join")
}

func TestSessionManager_CreateWith_RejectsDuplicate(t *testing.T) {
	a := require.New(t)
	sm := newTestSessionManager(time.Minute, 0, 10)

	listener1, _, c1 := pipeChans(t)
	defer c1()
	defer listener1.Close()
	listener2, _, c2 := pipeChans(t)
	defer c2()
	defer listener2.Close()

	token := makeToken(0x20)
	a.NoError(sm.CreateWith(listener1, token), "first CreateWith")
	a.ErrorIs(sm.CreateWith(listener2, token), ErrTokenInUse, "second CreateWith err")
}

func TestSessionManager_CreateWith_RejectsWhenFull(t *testing.T) {
	a := require.New(t)
	sm := newTestSessionManager(time.Minute, 0, 1)

	l1, _, c1 := pipeChans(t)
	defer c1()
	defer l1.Close()
	a.NoError(sm.CreateWith(l1, makeToken(0x30)), "first CreateWith")

	// Server is at capacity; a fresh token must report ErrSessionFull,
	// not ErrTokenInUse (capacity precedes uniqueness).
	l2, _, c2 := pipeChans(t)
	defer c2()
	defer l2.Close()
	a.ErrorIs(sm.CreateWith(l2, makeToken(0x40)), ErrSessionFull, "CreateWith on full server")
}

func TestSessionManager_CreateWith_RejectsInvalid(t *testing.T) {
	sm := newTestSessionManager(time.Minute, 0, 10)

	listener, _, cleanup := pipeChans(t)
	defer cleanup()
	defer listener.Close()

	cases := []struct {
		name    string
		token   []byte
		wantErr error
	}{
		{"empty", nil, relayconn.ErrTokenTooShort},
		{"short", make([]byte, 15), relayconn.ErrTokenTooShort},
		{"long", make([]byte, 17), relayconn.ErrTokenTooShort},
		{"all-zeros-32", make([]byte, 32), relayconn.ErrTokenInsufficientEntropy},
		{"constant-byte", bytes.Repeat([]byte{0xAA}, 32), relayconn.ErrTokenInsufficientEntropy},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			err := sm.CreateWith(listener, tc.token)
			a.ErrorIs(err, tc.wantErr)
		})
	}
}

func TestSessionManager_Create_RandomStillWorks(t *testing.T) {
	a := require.New(t)
	// Regression: Create (random mode) must be unaffected by the
	// CreateWith additions.
	sm := newTestSessionManager(time.Minute, 0, 10)

	listener, _, cleanup := pipeChans(t)
	defer cleanup()
	defer listener.Close()

	token, err := sm.Create(listener)
	a.NoError(err, "Create")
	a.Len(token, 16)
	a.Equal(1, sm.Len())
}
