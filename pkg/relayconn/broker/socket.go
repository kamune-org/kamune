package broker

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"time"
)

// readBufSize holds the largest IPv4 UDP payload, so no datagram is too
// long to read. With a shorter buffer Windows fails the read with
// WSAEMSGSIZE instead of truncating the datagram, and anyone who can send
// to the socket could end a read that way.
const readBufSize = 64 << 10

// readErrBurst is how many reads in a row may fail before readBroker gives
// up. A read can fail for one datagram while the socket still works, as
// when Windows reports an ICMP port unreachable for an earlier send as
// WSAECONNRESET; a run of failures points to a fault of the socket.
const readErrBurst = 16

// packetReader is the part of *net.UDPConn that readBroker uses. Tests
// wrap it to inject read errors.
type packetReader interface {
	ReadFromUDP(b []byte) (int, *net.UDPAddr, error)
	SetReadDeadline(t time.Time) error
}

// The broker records the source address of each REGISTER, sends the
// registration's NOTIFYs to it and hands it to the matched peer to punch
// to. The methods in this file therefore run on a UDP socket the caller
// owns, normally the one that will carry the peer-to-peer traffic, so
// that the address the broker hands out stays open after they return.

// EchoOn sends a STUN_ECHO from conn and returns the address the broker
// sees for conn. conn must be an unconnected UDP socket, such as one
// from net.ListenUDP.
//
// EchoOn reads conn until the broker's echo reply arrives and drops
// every other packet, NOTIFYs included, so call it before RegisterOn and
// make sure no other goroutine reads conn meanwhile. It waits until ctx
// ends, or for DefaultEchoTimeout when ctx has no deadline, and clears
// conn's read deadline before it returns.
func (c *Client) EchoOn(
	ctx context.Context, conn *net.UDPConn,
) (net.IP, uint16, error) {
	_, err := conn.WriteToUDP(buildEchoRequest(), c.relayAddr)
	if err != nil {
		return nil, 0, fmt.Errorf("write echo: %w", err)
	}
	var (
		ip   net.IP
		port uint16
	)
	err = c.readBroker(ctx, conn, DefaultEchoTimeout, func(pkt []byte) bool {
		var err error
		ip, port, err = parseEchoResponse(pkt)
		return err == nil
	})
	if err != nil {
		return nil, 0, fmt.Errorf("read echo response: %w", err)
	}
	return ip, port, nil
}

// RegisterOn sends a REGISTER from conn, so the broker records conn's
// address for the registration: it sends the registration's NOTIFYs to
// conn and gives conn's address to the matched peer. Refresh a
// registration by calling RegisterOn again from the same socket, since
// the broker takes the address of every REGISTER it receives. conn must
// be an unconnected UDP socket.
//
// In random mode, an empty token or one whose WireToken form is all
// zeros, RegisterOn reads conn until the broker's TOKEN_ASSIGNED arrives
// and returns the assigned token. It drops every other packet, waits
// until ctx ends, or for DefaultRegisterTimeout when ctx has no
// deadline, and clears conn's read deadline before it returns. In static
// mode it returns token right after the write without reading conn; the
// PEER_MATCHED for the registration arrives on conn, to be read with
// ReadNotify. The broker echoes tokens in their WireToken form, so check
// them with TokenMatches.
//
// The broker only checks that claimIP is an IPv4 address and that
// claimPort is not zero; the address it records is the REGISTER's
// source.
func (c *Client) RegisterOn(
	ctx context.Context,
	conn *net.UDPConn,
	token []byte,
	claimIP net.IP,
	claimPort uint16,
) ([]byte, error) {
	pkt := BuildRegister(token, c.pub, claimIP, claimPort)
	if _, err := conn.WriteToUDP(pkt, c.relayAddr); err != nil {
		return nil, fmt.Errorf("write register: %w", err)
	}
	if !isZero(WireToken(token)) {
		return token, nil
	}

	var assigned []byte
	err := c.readBroker(ctx, conn, DefaultRegisterTimeout, func(
		pkt []byte,
	) bool {
		p, err := c.decodeNotify(pkt)
		if err != nil || p.Type != NotifyTokenAssigned {
			return false
		}
		assigned = p.Token
		return true
	})
	if err != nil {
		return nil, fmt.Errorf("read register response: %w", err)
	}
	return assigned, nil
}

// ReadNotify reads conn until a NOTIFY arrives from the broker's address
// that decrypts with the client's key, and returns its payload. It drops
// packets from other sources and packets that do not decrypt, so no
// other goroutine may read conn meanwhile. A read that fails for a single
// datagram is dropped too; ReadNotify fails only when 16 reads in a row
// fail or conn is closed. ReadNotify waits until ctx ends and clears
// conn's read deadline before it returns.
func (c *Client) ReadNotify(
	ctx context.Context, conn *net.UDPConn,
) (Payload, error) {
	var out Payload
	err := c.readBroker(ctx, conn, 0, func(pkt []byte) bool {
		p, err := c.decodeNotify(pkt)
		if err != nil {
			return false
		}
		out = *p
		return true
	})
	if err != nil {
		return Payload{}, fmt.Errorf("read notify: %w", err)
	}
	return out, nil
}

// readBroker reads packets from conn until accept returns true for one
// that came from the broker's address. It gives up when ctx ends or,
// when ctx has no deadline and timeout is positive, once timeout has
// passed. When ctx ends it returns ctx's error. A read that fails for
// another reason than the deadline or a closed socket counts as a
// dropped packet, until readErrBurst reads in a row have failed. It
// clears conn's read deadline before it returns.
func (c *Client) readBroker(
	ctx context.Context,
	conn packetReader,
	timeout time.Duration,
	accept func(pkt []byte) bool,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	deadline, ctxDeadline := ctx.Deadline()
	if !ctxDeadline && timeout > 0 {
		deadline = time.Now().Add(timeout)
	}
	if err := conn.SetReadDeadline(deadline); err != nil {
		return fmt.Errorf("set deadline: %w", err)
	}
	fired := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		defer close(fired)
		_ = conn.SetReadDeadline(time.Now())
	})
	defer func() {
		if !stop() {
			<-fired
		}
		_ = conn.SetReadDeadline(time.Time{})
	}()

	buf := make([]byte, readBufSize)
	failed := 0
	for {
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return ctxErr
			}
			if errors.Is(err, os.ErrDeadlineExceeded) {
				// The socket can time out a moment before ctx does.
				if ctxDeadline {
					return context.DeadlineExceeded
				}
				return err
			}
			if errors.Is(err, net.ErrClosed) {
				return err
			}
			failed++
			if failed >= readErrBurst {
				return fmt.Errorf("%d reads in a row failed: %w", failed, err)
			}
			continue
		}
		failed = 0
		if c.fromBroker(src) && accept(buf[:n]) {
			return nil
		}
	}
}

// fromBroker reports whether src is the broker's address.
func (c *Client) fromBroker(src *net.UDPAddr) bool {
	return src != nil &&
		src.Port == c.relayAddr.Port &&
		src.IP.Equal(c.relayAddr.IP)
}

// isZero reports whether b holds only zero bytes. It is true for an
// empty b.
func isZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}
