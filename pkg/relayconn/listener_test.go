package relayconn

import (
	"net"
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
