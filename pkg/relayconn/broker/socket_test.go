package broker

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// faultyReader is a socket whose first reads fail with errs, in order.
type faultyReader struct {
	*net.UDPConn
	errs []error
}

func (r *faultyReader) ReadFromUDP(b []byte) (int, *net.UDPAddr, error) {
	if len(r.errs) > 0 {
		err := r.errs[0]
		r.errs = r.errs[1:]
		return 0, nil, err
	}
	return r.UDPConn.ReadFromUDP(b)
}

// TestReadBroker_ReadErrors injects read errors before a NOTIFY from the
// broker and checks which of them end the read.
func TestReadBroker_ReadErrors(t *testing.T) {
	dropped := &net.OpError{
		Op: "read", Net: "udp", Err: os.NewSyscallError(
			"wsarecvfrom", syscall.ECONNRESET,
		),
	}
	repeat := func(err error, n int) []error {
		errs := make([]error, n)
		for i := range errs {
			errs[i] = err
		}
		return errs
	}
	cases := []struct {
		wantErr error
		name    string
		errs    []error
	}{
		{name: "no errors"},
		{
			name: "errors below the burst are dropped",
			errs: repeat(dropped, readErrBurst-1),
		},
		{
			name:    "a burst of errors ends the read",
			errs:    repeat(dropped, readErrBurst),
			wantErr: syscall.ECONNRESET,
		},
		{
			name:    "a closed socket ends the read",
			errs:    []error{net.ErrClosed},
			wantErr: net.ErrClosed,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			tb := newTestBroker(t)
			c, err := NewClient(tb.addr.String())
			a.NoError(err)
			conn := punchSocket(t)
			_, err = tb.conn.WriteToUDP(
				sealedPeerMatched(t, c.PublicKey(), 4242),
				conn.LocalAddr().(*net.UDPAddr),
			)
			a.NoError(err)

			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
			defer cancel()
			var got *Payload
			r := &faultyReader{UDPConn: conn, errs: tc.errs}
			err = c.readBroker(ctx, r, 0, func(pkt []byte) bool {
				p, decodeErr := c.decodeNotify(pkt)
				got = p
				return decodeErr == nil
			})
			if tc.wantErr != nil {
				a.ErrorIs(err, tc.wantErr)
				a.Nil(got)
				return
			}
			a.NoError(err)
			a.NotNil(got)
			a.Equal(uint16(4242), got.Port)
			a.Empty(r.errs)
		})
	}
}

// TestReadBroker_ReadsLargeDatagram sends a datagram longer than an
// Ethernet frame from the broker's address and checks that it is read
// whole, which on Windows also means the read does not fail.
func TestReadBroker_ReadsLargeDatagram(t *testing.T) {
	a := require.New(t)
	tb := newTestBroker(t)
	c, err := NewClient(tb.addr.String())
	a.NoError(err)
	conn := punchSocket(t)
	large := bytes.Repeat([]byte{0x5a}, 4000)
	_, err = tb.conn.WriteToUDP(large, conn.LocalAddr().(*net.UDPAddr))
	a.NoError(err)

	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	var got []byte
	err = c.readBroker(ctx, conn, 0, func(pkt []byte) bool {
		got = bytes.Clone(pkt)
		return true
	})
	a.NoError(err)
	a.Equal(large, got)
}

// TestReadBroker_DeadlineStillEnds checks that the read deadline still
// ends the read when the reads before it failed.
func TestReadBroker_DeadlineStillEnds(t *testing.T) {
	a := require.New(t)
	tb := newTestBroker(t)
	c, err := NewClient(tb.addr.String())
	a.NoError(err)
	r := &faultyReader{
		UDPConn: punchSocket(t),
		errs:    []error{errors.New("dropped datagram")},
	}
	err = c.readBroker(
		t.Context(), r, 50*time.Millisecond, func([]byte) bool {
			return true
		},
	)
	a.ErrorIs(err, os.ErrDeadlineExceeded)
}
