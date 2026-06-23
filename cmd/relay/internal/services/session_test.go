package services

import (
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/kamune-org/kamune/pkg/exchange"
	"google.golang.org/protobuf/proto"

	"github.com/kamune-org/kamune/pkg/relayconn/pb"
)

// pipeChans returns a pair of *exchange.Channel values backed by an
// in-memory net.Pipe. One end Initiates, the other Accepts. Either can be
// closed independently to simulate a peer disconnect. The returned cleanup
// function closes the underlying pipes.
func pipeChans(t *testing.T) (a, b *exchange.Channel, cleanup func()) {
	t.Helper()

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
	if err != nil {
		t.Fatalf("exchange.Initiate: %v", err)
	}
	if err := <-acceptCh; err != nil {
		t.Fatalf("exchange.Accept: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if chB == nil {
		t.Fatal("accept did not complete")
	}

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
	b, err := proto.Marshal(f)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := ch.WriteBytes(b); err != nil {
		t.Fatalf("write: %v", err)
	}
}

// readFrame reads a single Frame from the channel.
func readFrame(t *testing.T, ch *exchange.Channel) *pb.Frame {
	t.Helper()
	b, err := ch.ReadBytes()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var f pb.Frame
	if err := proto.Unmarshal(b, &f); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return &f
}

func newTestSessionManager(tokenTTL, sessionTTL time.Duration, maxConns int) *SessionManager {
	return NewSessionManager(tokenTTL, maxConns, sessionTTL)
}

// --- SessionManager tests ------------------------------------------------

func TestSessionManager_Create_Roundtrip(t *testing.T) {
	sm := newTestSessionManager(time.Minute, 0, 10)
	defer sm.Remove(nil) // no-op, just to ensure no panic

	listener, _, cleanup := pipeChans(t)
	defer cleanup()
	defer listener.Close()

	token, err := sm.Create(listener)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if len(token) != 16 {
		t.Errorf("token length = %d, want 16", len(token))
	}
	if sm.Len() != 1 {
		t.Errorf("Len = %d, want 1", sm.Len())
	}
}

func TestSessionManager_Create_RespectsMaxConns(t *testing.T) {
	sm := newTestSessionManager(time.Minute, 0, 2)
	for i := 0; i < 2; i++ {
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
	if _, err := sm.Create(l1); err != nil {
		t.Fatalf("Create 1: %v", err)
	}

	l2, _, c2 := pipeChans(t)
	defer c2()
	defer l2.Close()
	if _, err := sm.Create(l2); err != nil {
		t.Fatalf("Create 2: %v", err)
	}

	// Third should fail.
	l3, _, c3 := pipeChans(t)
	defer c3()
	defer l3.Close()
	if _, err := sm.Create(l3); err != ErrSessionFull {
		t.Errorf("err = %v, want ErrSessionFull", err)
	}
}

func TestSessionManager_Join_RejectsUnknownToken(t *testing.T) {
	sm := newTestSessionManager(time.Minute, 0, 10)

	dialer, _, cleanup := pipeChans(t)
	defer cleanup()
	defer dialer.Close()

	err := sm.Join([]byte("doesnt-exist"), dialer)
	if err != ErrTokenNotFound {
		t.Errorf("err = %v, want ErrTokenNotFound", err)
	}
}

func TestSessionManager_Join_RejectsConsumed(t *testing.T) {
	sm := newTestSessionManager(time.Minute, 0, 10)

	listener, _, cleanup := pipeChans(t)
	defer cleanup()
	defer listener.Close()

	token, err := sm.Create(listener)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	dialer1, dialerRemote1, cleanup1 := pipeChans(t)
	defer cleanup1()
	if err := sm.Join(token, dialer1); err != nil {
		t.Fatalf("first Join: %v", err)
	}
	_ = dialerRemote1

	// Second join with the same token must fail.
	dialer2, _, cleanup2 := pipeChans(t)
	defer cleanup2()
	defer dialer2.Close()
	if err := sm.Join(token, dialer2); err != ErrTokenConsumed {
		t.Errorf("err = %v, want ErrTokenConsumed", err)
	}
}

func TestSessionManager_Join_RejectsExpired(t *testing.T) {
	sm := newTestSessionManager(10*time.Millisecond, 0, 10)

	listener, _, cleanup := pipeChans(t)
	defer cleanup()
	defer listener.Close()

	token, err := sm.Create(listener)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	time.Sleep(20 * time.Millisecond)

	dialer, _, cleanup2 := pipeChans(t)
	defer cleanup2()
	defer dialer.Close()
	if err := sm.Join(token, dialer); err != ErrSessionExpired {
		t.Errorf("err = %v, want ErrSessionExpired", err)
	}
}

func TestSessionManager_Recipient_DirectionAware(t *testing.T) {
	sm := newTestSessionManager(time.Minute, 0, 10)

	listener, _, cleanup := pipeChans(t)
	defer cleanup()
	defer listener.Close()
	dialer, _, cleanup2 := pipeChans(t)
	defer cleanup2()
	defer dialer.Close()

	token, err := sm.Create(listener)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := sm.Join(token, dialer); err != nil {
		t.Fatalf("Join: %v", err)
	}

	// From listener's perspective, recipient is the dialer.
	got, err := sm.Recipient(token, listener)
	if err != nil {
		t.Fatalf("Recipient(listener): %v", err)
	}
	if got != dialer {
		t.Errorf("Recipient(listener) returned wrong peer")
	}

	// From dialer's perspective, recipient is the listener.
	got, err = sm.Recipient(token, dialer)
	if err != nil {
		t.Fatalf("Recipient(dialer): %v", err)
	}
	if got != listener {
		t.Errorf("Recipient(dialer) returned wrong peer")
	}

	// From a stranger, returns error.
	stranger, _, cleanup3 := pipeChans(t)
	defer cleanup3()
	defer stranger.Close()
	if _, err := sm.Recipient(token, stranger); err != ErrPeerNotFound {
		t.Errorf("Recipient(stranger) = %v, want ErrPeerNotFound", err)
	}
}

func TestSessionManager_Recipient_ListenerOnlyHasNoPeer(t *testing.T) {
	sm := newTestSessionManager(time.Minute, 0, 10)

	listener, _, cleanup := pipeChans(t)
	defer cleanup()
	defer listener.Close()

	token, err := sm.Create(listener)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if _, err := sm.Recipient(token, listener); err != ErrPeerNotFound {
		t.Errorf("Recipient(listener, no peer) = %v, want ErrPeerNotFound", err)
	}
}

func TestSessionManager_ClosePeerChannel_ClosesPeer(t *testing.T) {
	sm := newTestSessionManager(time.Minute, 0, 10)

	listener, dialerRemote, cleanup := pipeChans(t)
	defer cleanup()
	dialer, dialerRemote2, cleanup2 := pipeChans(t)
	defer cleanup2()

	token, err := sm.Create(listener)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := sm.Join(token, dialer); err != nil {
		t.Fatalf("Join: %v", err)
	}
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
		if err == nil {
			t.Error("dialer ReadBytes returned nil after peer close")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("dialer ReadBytes did not return after peer close")
	}
}

func TestSessionManager_Remove_Idempotent(t *testing.T) {
	sm := newTestSessionManager(time.Minute, 0, 10)

	listener, _, cleanup := pipeChans(t)
	defer cleanup()
	defer listener.Close()

	token, err := sm.Create(listener)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	sm.Remove(token)
	if sm.Len() != 0 {
		t.Errorf("Len = %d, want 0", sm.Len())
	}

	// Remove again — must not panic.
	sm.Remove(token)
	sm.Remove([]byte("never-existed"))
}

func TestSessionManager_PurgeExpired_UnpairedSession(t *testing.T) {
	sm := newTestSessionManager(20*time.Millisecond, 0, 10)

	listener, _, cleanup := pipeChans(t)
	defer cleanup()

	// drain the remote end so listener.Close() during purge doesn't block
	drainRead(t, listener)

	token, err := sm.Create(listener)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Wait past the token TTL.
	time.Sleep(40 * time.Millisecond)

	// Purge manually.
	sm.purgeExpired()

	// Session is gone.
	if sm.Len() != 0 {
		t.Errorf("Len = %d, want 0", sm.Len())
	}

	_ = token
}

func TestSessionManager_PurgeExpired_PairedSession(t *testing.T) {
	sm := newTestSessionManager(time.Minute, 30*time.Millisecond, 10)

	listener, listenerRemote, cleanup := pipeChans(t)
	defer cleanup()
	dialer, dialerRemote, cleanup2 := pipeChans(t)
	defer cleanup2()

	drainRead(t, listenerRemote)
	drainRead(t, dialerRemote)

	token, err := sm.Create(listener)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := sm.Join(token, dialer); err != nil {
		t.Fatalf("Join: %v", err)
	}

	// Session should still be alive before expiry.
	if sm.Len() != 1 {
		t.Errorf("Len = %d, want 1", sm.Len())
	}

	time.Sleep(60 * time.Millisecond)
	sm.purgeExpired()

	if sm.Len() != 0 {
		t.Errorf("Len = %d, want 0 after expiry", sm.Len())
	}
}

func TestSessionManager_PurgeExpired_NeverExpiresWhenSessionTTLZero(t *testing.T) {
	sm := newTestSessionManager(10*time.Millisecond, 0, 10)

	listener, listenerRemote, cleanup := pipeChans(t)
	defer cleanup()
	dialer, dialerRemote, cleanup2 := pipeChans(t)
	defer cleanup2()

	drainRead(t, listenerRemote)
	drainRead(t, dialerRemote)

	token, err := sm.Create(listener)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := sm.Join(token, dialer); err != nil {
		t.Fatalf("Join: %v", err)
	}

	time.Sleep(30 * time.Millisecond)
	sm.purgeExpired()

	// sessionTTL=0 → paired sessions should not be purged.
	if sm.Len() != 1 {
		t.Errorf("Len = %d, want 1 (sessionTTL=0 should disable)", sm.Len())
	}
}

func TestSessionManager_TTL_And_SessionTTL(t *testing.T) {
	sm := NewSessionManager(5*time.Minute, 10, 30*time.Minute)
	if got := sm.TTL(); got != 5*time.Minute {
		t.Errorf("TTL = %v, want 5m", got)
	}
	if got := sm.SessionTTL(); got != 30*time.Minute {
		t.Errorf("SessionTTL = %v, want 30m", got)
	}
}
