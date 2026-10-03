package exchange

import (
	"bytes"
	"encoding/binary"
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
