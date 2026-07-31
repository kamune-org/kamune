package exchange

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"

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
