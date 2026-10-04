package relayconn

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// waitClosed fails the test unless spy is closed within two seconds.
func waitClosed(t *testing.T, spy *closeSpy, msg string) {
	t.Helper()
	select {
	case <-spy.closed:
	case <-time.After(2 * time.Second):
		require.New(t).Fail(msg)
	}
}

func TestListenerStop_IdleReleasesRelaySession(t *testing.T) {
	a := require.New(t)
	listener, _, spy := setupListenerSpy(t)

	acceptErr := make(chan error, 1)
	go func() {
		_, err := listener.Accept()
		acceptErr <- err
	}()
	time.Sleep(50 * time.Millisecond)

	listener.Stop()

	select {
	case err := <-acceptErr:
		a.ErrorIs(err, net.ErrClosed)
	case <-time.After(2 * time.Second):
		a.Fail("blocked Accept did not return after Stop")
	}
	waitClosed(t, spy, "Stop on an idle listener kept the relay socket")
	a.Error(listener.ctx.Err())
}

func TestListenerStop_PendingConnReleasesRelaySession(t *testing.T) {
	a := require.New(t)
	listener, serverCh, spy := setupListenerSpy(t)

	a.NoError(serverCh.WriteBytes(msgFrame([]byte("hello"))))
	a.Eventually(func() bool {
		return len(listener.accept) == 1
	}, 2*time.Second, 5*time.Millisecond)

	listener.Stop()

	waitClosed(t, spy, "Stop with an unaccepted conn kept the relay socket")
	_, err := listener.Accept()
	a.ErrorIs(err, net.ErrClosed)
}

func TestListenerStop_ActiveConnReleasesOnClose(t *testing.T) {
	a := require.New(t)
	listener, serverCh, spy := setupListenerSpy(t)

	a.NoError(serverCh.WriteBytes(msgFrame([]byte("hello"))))
	conn, err := listener.Accept()
	a.NoError(err)

	listener.Stop()
	select {
	case <-spy.closed:
		a.Fail("Stop closed the relay socket of an active conn")
	case <-time.After(50 * time.Millisecond):
	}

	a.NoError(conn.Close())
	waitClosed(t, spy, "closing the active conn kept the relay socket")
}

func TestListenerReadPumpExitReleasesRelaySession(t *testing.T) {
	a := require.New(t)
	listener, serverCh, spy := setupListenerSpy(t)

	acceptErr := make(chan error, 1)
	go func() {
		_, err := listener.Accept()
		acceptErr <- err
	}()

	// The relay goes away: the listener's readPump fails.
	a.NoError(serverCh.Close())

	waitClosed(t, spy, "readPump exit kept the relay socket")
	select {
	case err := <-acceptErr:
		a.ErrorIs(err, net.ErrClosed)
	case <-time.After(2 * time.Second):
		a.Fail("Accept did not return after the relay went away")
	}
}

// TestListenerSingleConnection closes the listener's connection, as the
// kamune server does after rejecting a peer, and checks that the relay
// session ends: the peer's next frame starts no new connection, Accept
// reports net.ErrClosed and the closed connection cannot write.
func TestListenerSingleConnection(t *testing.T) {
	a := require.New(t)
	listener, serverCh, spy := setupListenerSpy(t)

	// Everything the listener writes reaches the relay here.
	relayGot := make(chan []byte, 16)
	go func() {
		for {
			data, err := serverCh.ReadBytes()
			if err != nil {
				return
			}
			relayGot <- data
		}
	}()

	a.NoError(serverCh.WriteBytes(msgFrame([]byte("a"))))
	c1, err := listener.Accept()
	a.NoError(err)

	blocked := make(chan error, 1)
	go func() {
		_, err := listener.Accept()
		blocked <- err
	}()

	a.NoError(c1.Close())
	waitClosed(t, spy, "closing the only conn kept the relay socket")

	// A frame the relay already queued must not become a new session.
	_ = serverCh.WriteBytes(msgFrame([]byte("b")))
	select {
	case err := <-blocked:
		a.ErrorIs(err, net.ErrClosed)
	case <-time.After(2 * time.Second):
		a.Fail("blocked Accept did not return after the conn closed")
	}
	_, err = listener.Accept()
	a.ErrorIs(err, net.ErrClosed)

	// A late close hook of the old conn is harmless.
	c1.(*RelayConn).closeFn()
	a.ErrorIs(c1.WriteBytes([]byte("stale")), net.ErrClosed)
	select {
	case data := <-relayGot:
		a.Failf("closed conn wrote to the relay", "frame %x", data)
	case <-time.After(50 * time.Millisecond):
	}
}

func TestRelayConnWriteAfterClose(t *testing.T) {
	a := require.New(t)
	clientCh, _ := channelPair(t)

	var mu sync.Mutex
	rc := newRelayConn(t.Context(), clientCh, &mu)
	rc.closeFn = func() { clientCh.Close() }
	a.NoError(rc.Close())
	a.NoError(rc.Close())

	a.ErrorIs(rc.WriteBytes([]byte("late")), net.ErrClosed)
}
