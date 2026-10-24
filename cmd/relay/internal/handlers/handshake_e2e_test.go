package handlers

import (
	"bytes"
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/kamune-org/kamune"
	"github.com/kamune-org/kamune/pkg/storage"
)

// frameLog records every kamune frame the hub forwards in Message.Data.
type frameLog struct {
	mu     sync.Mutex
	frames [][]byte
}

func (l *frameLog) add(frame []byte) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.frames = append(l.frames, bytes.Clone(frame))
}

func (l *frameLog) snapshot() [][]byte {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([][]byte, len(l.frames))
	copy(out, l.frames)
	return out
}

// recordingConn wraps a kamune.Conn and records every frame it reads or
// writes, which are the bytes the relay hub forwards.
type recordingConn struct {
	kamune.Conn
	log *frameLog
}

func (c *recordingConn) ReadBytes() ([]byte, error) {
	b, err := c.Conn.ReadBytes()
	if err == nil {
		c.log.add(b)
	}
	return b, err
}

func (c *recordingConn) WriteBytes(data []byte) error {
	c.log.add(data)
	return c.Conn.WriteBytes(data)
}

func (c *recordingConn) MaxFrameSize() int {
	if fl, ok := c.Conn.(interface{ MaxFrameSize() int }); ok {
		return fl.MaxFrameSize()
	}
	return 0
}

type recordingListener struct {
	inner kamune.Listener
	log   *frameLog
}

func (l *recordingListener) Accept() (kamune.Conn, error) {
	c, err := l.inner.Accept()
	if err != nil {
		return nil, err
	}
	return &recordingConn{Conn: c, log: l.log}, nil
}

func (l *recordingListener) Close() error { return l.inner.Close() }

func acceptAll(
	_ context.Context, s *storage.Storage, req kamune.VerifyRequest,
) error {
	return s.StorePeer(req.Peer)
}

func echoOnce(tr *kamune.Transport) error {
	msg := kamune.Bytes(nil)
	if _, err := tr.Receive(msg); err != nil {
		return err
	}
	if _, err := tr.Send(
		kamune.Bytes([]byte("ack")), kamune.RouteExchangeMessages,
	); err != nil {
		return err
	}
	_, err := tr.Receive(kamune.Bytes(nil))
	return err
}

func startNamedServer(
	t *testing.T, store *storage.Storage, l kamune.Listener,
) *kamune.Server {
	t.Helper()
	a := require.New(t)
	srv, err := kamune.NewServer(
		"", echoOnce, store, acceptAll,
		kamune.ServeWithListener(l),
		kamune.ServeWithServerName("Alice"),
	)
	a.NoError(err)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = srv.ListenAndServe()
	}()
	t.Cleanup(func() {
		_ = srv.Close()
		<-done
	})
	return srv
}

func exchangeHello(t *testing.T, tr *kamune.Transport) {
	t.Helper()
	a := require.New(t)
	_, err := tr.Send(
		kamune.Bytes([]byte("hello")), kamune.RouteExchangeMessages,
	)
	a.NoError(err)
	got := kamune.Bytes(nil)
	_, err = tr.Receive(got)
	a.NoError(err)
	a.Equal([]byte("ack"), got.GetValue())
}

func assertBlind(
	t *testing.T, frames [][]byte, alicePK, bobPK []byte, sessionID string,
) {
	t.Helper()
	a := require.New(t)
	a.NotEmpty(frames)
	secrets := [][]byte{
		alicePK,
		bobPK,
		alicePK[12:],
		bobPK[12:],
		[]byte("Alice"),
		[]byte("Bob"),
		[]byte(kamune.AppVersion),
		[]byte(sessionID),
	}
	for i, frame := range frames {
		for _, secret := range secrets {
			a.False(
				bytes.Contains(frame, secret),
				"frame %d holds %q", i, secret,
			)
		}
	}
}

// TestE2E_RelayBlindHandshake runs a cold kamune session through the
// in-process relay, injects one garbage frame, resumes on a second
// listener, and checks that the hub never saw identity material.
func TestE2E_RelayBlindHandshake(t *testing.T) {
	a := require.New(t)
	ep := startTestRelay(t)["tcp"]
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	log := &frameLog{}

	aliceStore := openTestStorage(t)
	bobStore := openTestStorage(t)

	res, err := ep.listen(ctx)
	a.NoError(err)
	srv := startNamedServer(t, aliceStore, &recordingListener{
		inner: res.Listener, log: log,
	})
	alicePK := srv.PublicKey()

	var dialConn *recordingConn
	dialer, err := kamune.NewDialer(
		"", bobStore, acceptAll,
		kamune.DialWithClientName("Bob"),
		kamune.DialWithPeerKey(alicePK),
		kamune.DialWithFunc(func(string) (kamune.Conn, error) {
			rc, err := ep.dial(ctx, res.Token)
			if err != nil {
				return nil, err
			}
			dialConn = &recordingConn{Conn: rc, log: log}
			return dialConn, nil
		}),
	)
	a.NoError(err)
	bobPK := dialer.PublicKey()
	cold, err := dialer.Dial()
	a.NoError(err)
	exchangeHello(t, cold)
	a.False(cold.Resumed())
	sessionID := cold.SessionID()

	a.NoError(dialConn.WriteBytes([]byte{0x00, 0x01, 0xff}))
	_, err = cold.Receive(kamune.Bytes(nil))
	a.Error(err)
	a.NoError(cold.CloseAbort())
	_ = srv.Close()

	res2, err := ep.listen(ctx)
	a.NoError(err)
	startNamedServer(t, aliceStore, &recordingListener{
		inner: res2.Listener, log: log,
	})

	resumeDialer, err := kamune.NewDialer(
		"", bobStore, acceptAll,
		kamune.DialWithClientName("Bob"),
		kamune.DialWithPeerKey(alicePK),
		kamune.DialWithResume(sessionID),
		kamune.DialWithFunc(func(string) (kamune.Conn, error) {
			rc, err := ep.dial(ctx, res2.Token)
			if err != nil {
				return nil, err
			}
			return &recordingConn{Conn: rc, log: log}, nil
		}),
	)
	a.NoError(err)
	resumed, err := resumeDialer.Dial()
	a.NoError(err)
	a.True(resumed.Resumed())
	a.Equal(sessionID, resumed.SessionID())
	exchangeHello(t, resumed)
	a.NoError(resumed.Close())

	assertBlind(t, log.snapshot(), alicePK, bobPK, sessionID)
}

var _ kamune.Listener = (*recordingListener)(nil)
