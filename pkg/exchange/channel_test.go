package exchange

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type framedConn struct {
	net.Conn
}

func (c *framedConn) ReadBytes() ([]byte, error) {
	var size uint32
	if err := binary.Read(c.Conn, binary.BigEndian, &size); err != nil {
		return nil, err
	}
	data := make([]byte, size)
	if _, err := io.ReadFull(c.Conn, data); err != nil {
		return nil, err
	}
	return data, nil
}

func (c *framedConn) WriteBytes(data []byte) error {
	if err := binary.Write(c.Conn, binary.BigEndian, uint32(len(data))); err != nil {
		return err
	}
	_, err := c.Write(data)
	return err
}

func channelPair(t *testing.T) (*Channel, *Channel) {
	t.Helper()
	a := require.New(t)
	initiatorConn, recipientConn := net.Pipe()
	t.Cleanup(func() {
		_ = initiatorConn.Close()
		_ = recipientConn.Close()
	})

	acceptCh := make(chan struct {
		channel *Channel
		err     error
	}, 1)
	go func() {
		channel, err := Accept(&framedConn{Conn: recipientConn})
		acceptCh <- struct {
			channel *Channel
			err     error
		}{channel: channel, err: err}
	}()

	initiator, err := Initiate(&framedConn{Conn: initiatorConn})
	a.NoError(err)
	accepted := <-acceptCh
	a.NoError(accepted.err)
	return initiator, accepted.channel
}

func TestChannel_ConcurrentWrites(t *testing.T) {
	a := require.New(t)
	sender, recipient := channelPair(t)
	const messageCount = 64

	writeErrs := make(chan error, messageCount)
	var wg sync.WaitGroup
	for i := range messageCount {
		wg.Go(func() {
			writeErrs <- sender.WriteBytes([]byte(fmt.Sprintf("message-%d", i)))
		})
	}

	received := make(map[string]bool, messageCount)
	for range messageCount {
		data, err := recipient.ReadBytes()
		a.NoError(err)
		received[string(data)] = true
	}
	wg.Wait()
	close(writeErrs)

	for err := range writeErrs {
		a.NoError(err)
	}
	a.Len(received, messageCount)
}

type deadlineWriter struct {
	inner    *framedConn
	mu       sync.Mutex
	deadline time.Time
	hold     atomic.Bool
	blocked  atomic.Bool
	entered  chan struct{}
	release  chan struct{}
}

func (w *deadlineWriter) ReadBytes() ([]byte, error) {
	return w.inner.ReadBytes()
}

func (w *deadlineWriter) SetWriteDeadline(t time.Time) error {
	w.mu.Lock()
	w.deadline = t
	w.mu.Unlock()
	return nil
}

func (w *deadlineWriter) WriteBytes(data []byte) error {
	if w.hold.Load() && w.blocked.CompareAndSwap(false, true) {
		close(w.entered)
		<-w.release
		w.mu.Lock()
		dl := w.deadline
		w.mu.Unlock()
		if dl.IsZero() || time.Until(dl) < 20*time.Second {
			return fmt.Errorf("deadline cleared during write: %v", dl)
		}
	}
	return w.inner.WriteBytes(data)
}

func TestWriteBytesWithin_SlowWriteKeepsDeadline(t *testing.T) {
	a := require.New(t)
	initiatorConn, recipientConn := net.Pipe()
	t.Cleanup(func() {
		_ = initiatorConn.Close()
		_ = recipientConn.Close()
	})

	writer := &deadlineWriter{
		inner:   &framedConn{Conn: initiatorConn},
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}

	acceptCh := make(chan struct {
		channel *Channel
		err     error
	}, 1)
	go func() {
		channel, err := Accept(&framedConn{Conn: recipientConn})
		acceptCh <- struct {
			channel *Channel
			err     error
		}{channel, err}
	}()
	sender, err := Initiate(writer)
	a.NoError(err)
	accepted := <-acceptCh
	a.NoError(accepted.err)
	go func() {
		for {
			if _, err := accepted.channel.ReadBytes(); err != nil {
				return
			}
		}
	}()

	writer.hold.Store(true)
	firstDone := make(chan error, 1)
	go func() {
		firstDone <- sender.WriteBytesWithin([]byte("slow"), 30*time.Second)
	}()
	<-writer.entered

	secondDone := make(chan error, 1)
	go func() {
		secondDone <- sender.WriteBytesWithin([]byte("fast"), time.Millisecond)
	}()
	select {
	case err := <-secondDone:
		t.Fatalf("fast write returned while slow write held the lock: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	close(writer.release)
	a.NoError(<-firstDone)
	a.NoError(<-secondDone)
}

// limitedConn is a framedConn that rejects frames above limit, can be told
// to fail its next write, and records Close. When closeGate is set, Close
// signals closing and then blocks until closeGate is closed.
type limitedConn struct {
	*framedConn
	closeGate chan struct{}
	closing   chan struct{}
	limit     int
	failNext  atomic.Bool
	closed    atomic.Bool
}

func (c *limitedConn) MaxFrameSize() int { return c.limit }

func (c *limitedConn) WriteBytes(data []byte) error {
	if c.failNext.CompareAndSwap(true, false) {
		return errors.New("transient write failure")
	}
	if len(data) > c.limit {
		return fmt.Errorf("frame size %d exceeds %d", len(data), c.limit)
	}
	return c.framedConn.WriteBytes(data)
}

func (c *limitedConn) Close() error {
	c.closed.Store(true)
	if c.closeGate != nil {
		close(c.closing)
		<-c.closeGate
	}
	return c.framedConn.Close()
}

// limitedChannelPair returns a sender Channel over a limitedConn and the
// Channel that reads its frames.
func limitedChannelPair(
	t *testing.T, limit int,
) (*Channel, *Channel, *limitedConn) {
	t.Helper()
	a := require.New(t)
	initiatorConn, recipientConn := net.Pipe()
	t.Cleanup(func() {
		_ = initiatorConn.Close()
		_ = recipientConn.Close()
	})
	lc := &limitedConn{
		framedConn: &framedConn{Conn: initiatorConn},
		limit:      limit,
	}

	type result struct {
		channel *Channel
		err     error
	}
	acceptCh := make(chan result, 1)
	go func() {
		channel, err := Accept(&framedConn{Conn: recipientConn})
		acceptCh <- result{channel, err}
	}()
	sender, err := Initiate(lc)
	a.NoError(err)
	accepted := <-acceptCh
	a.NoError(accepted.err)
	return sender, accepted.channel, lc
}

func TestChannel_OversizeWriteKeepsChannelUsable(t *testing.T) {
	a := require.New(t)
	const limit = 2048
	sender, recipient, lc := limitedChannelPair(t, limit)

	received := make(chan []byte, 1)
	go func() {
		data, err := recipient.ReadBytes()
		if err != nil {
			data = []byte("read error: " + err.Error())
		}
		received <- data
	}()

	err := sender.WriteBytes(make([]byte, limit-Overhead+1))
	a.ErrorIs(err, ErrFrameTooLarge)
	a.False(lc.closed.Load())

	a.NoError(sender.WriteBytes([]byte("after oversize")))
	a.Equal([]byte("after oversize"), <-received)
}

// fixedLimitConn is a ReadWriter that reports a fixed FrameLimiter limit.
type fixedLimitConn struct {
	ReadWriter
	limit int
}

func (c fixedLimitConn) MaxFrameSize() int { return c.limit }

func TestChannel_MaxFrameSize(t *testing.T) {
	cases := []struct {
		conn ReadWriter
		name string
		want int
	}{
		{name: "no limiter", conn: &framedConn{}, want: 0},
		{name: "no limit", conn: fixedLimitConn{limit: 0}, want: 0},
		{name: "limit", conn: fixedLimitConn{limit: 2048}, want: 2032},
		{name: "tiny limit", conn: fixedLimitConn{limit: Overhead}, want: 1},
		{
			name: "nested channel",
			conn: newChannel(fixedLimitConn{limit: 2048}, nil, nil),
			want: 2048 - 2*Overhead,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			a.Equal(tc.want, newChannel(tc.conn, nil, nil).MaxFrameSize())
		})
	}
}

func TestChannel_FailedWriteBreaksChannel(t *testing.T) {
	a := require.New(t)
	sender, _, lc := limitedChannelPair(t, 2048)

	lc.failNext.Store(true)
	err := sender.WriteBytes([]byte("lost"))
	a.ErrorIs(err, ErrChannelBroken)
	a.True(lc.closed.Load())

	err = sender.WriteBytes([]byte("next"))
	a.ErrorIs(err, ErrChannelBroken)
}

// TestChannel_BreakClosesOutsideWriteLock checks that closing the ReadWriter
// after a failed write does not hold up other writers, which fail at once.
func TestChannel_BreakClosesOutsideWriteLock(t *testing.T) {
	a := require.New(t)
	sender, _, lc := limitedChannelPair(t, 2048)
	lc.closeGate = make(chan struct{})
	lc.closing = make(chan struct{})
	var release sync.Once
	releaseClose := func() { release.Do(func() { close(lc.closeGate) }) }
	t.Cleanup(releaseClose)

	lc.failNext.Store(true)
	firstDone := make(chan error, 1)
	go func() { firstDone <- sender.WriteBytes([]byte("lost")) }()
	<-lc.closing

	secondDone := make(chan error, 1)
	go func() { secondDone <- sender.WriteBytes([]byte("next")) }()
	select {
	case err := <-secondDone:
		a.ErrorIs(err, ErrChannelBroken)
	case <-time.After(10 * time.Second):
		a.FailNow("write blocked while the channel was closing")
	}

	releaseClose()
	a.ErrorIs(<-firstDone, ErrChannelBroken)
}

func TestChannel_SealOverhead(t *testing.T) {
	a := require.New(t)
	initiatorConn, recipientConn := net.Pipe()
	t.Cleanup(func() {
		_ = initiatorConn.Close()
		_ = recipientConn.Close()
	})
	go func() { _, _ = Accept(&framedConn{Conn: recipientConn}) }()
	sender, err := Initiate(&framedConn{Conn: initiatorConn})
	a.NoError(err)

	for _, n := range []int{0, 1, 1000} {
		sealed, err := sender.sender.Seal(nil, make([]byte, n))
		a.NoError(err)
		a.Len(sealed, n+Overhead)
	}
}

func FuzzParseMergedExchange(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0})
	f.Add([]byte{0, 0})
	f.Add([]byte{0, 1, 'e', 'p'})
	f.Add([]byte{0, 2, 'e'})
	f.Add([]byte{0xff, 0xff})

	f.Fuzz(func(t *testing.T, merged []byte) {
		if len(merged) > 64*1024 {
			t.Skip()
		}
		a := require.New(t)
		enc, publicKey, err := parseMergedExchange(merged)
		if len(merged) < 2 {
			a.Error(err)
			a.Nil(enc)
			a.Nil(publicKey)
			return
		}

		encLen := int(binary.BigEndian.Uint16(merged[:2]))
		if encLen > len(merged)-2 {
			a.Error(err)
			a.Nil(enc)
			a.Nil(publicKey)
			return
		}

		a.NoError(err)
		a.True(bytes.Equal(merged[2:2+encLen], enc))
		a.True(bytes.Equal(merged[2+encLen:], publicKey))
	})
}
