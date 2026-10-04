package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/kamune-org/kamune"
	"github.com/kamune-org/kamune/pkg/exchange"
	"github.com/kamune-org/kamune/pkg/relayconn"
	"github.com/kamune-org/kamune/pkg/relayconn/pb"
	"github.com/kamune-org/kamune/pkg/storage"
)

// fakeRelay is a relay for tests that speaks the tcp scheme, or tls with
// a self-signed certificate. It pairs a listener with the dialer that
// joins its token and forwards their frames.
type fakeRelay struct {
	addr string
	// cert is the relay's certificate when it speaks tls.
	cert       *x509.Certificate
	sessionTTL time.Duration

	// closed is closed when the test ends.
	closed chan struct{}

	mu      sync.Mutex
	waiting map[string]*relaySession
}

// relaySession is a session on a fakeRelay that waits for its dialer.
type relaySession struct {
	listener *relayPeer
	joined   chan *relayPeer
}

// relayPeer is one side of a session on a fakeRelay.
type relayPeer struct {
	ch   *exchange.Channel
	conn net.Conn
	mu   sync.Mutex
}

func (p *relayPeer) write(f *pb.Frame) error {
	b, err := proto.Marshal(f)
	if err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.ch.WriteBytes(b)
}

func (p *relayPeer) read() (*pb.Frame, error) {
	b, err := p.ch.ReadBytes()
	if err != nil {
		return nil, err
	}
	var f pb.Frame
	if err := proto.Unmarshal(b, &f); err != nil {
		return nil, err
	}
	return &f, nil
}

// startFakeRelay starts a relay that serves tls when useTLS is set and tcp
// otherwise. Its paired sessions last sessionTTL.
func startFakeRelay(
	t *testing.T, useTLS bool, sessionTTL time.Duration,
) *fakeRelay {
	t.Helper()
	a := require.New(t)
	r := &fakeRelay{
		sessionTTL: sessionTTL,
		closed:     make(chan struct{}),
		waiting:    make(map[string]*relaySession),
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	a.NoError(err)
	if useTLS {
		cert := selfSignedCert(t)
		r.cert, err = x509.ParseCertificate(cert.Certificate[0])
		a.NoError(err)
		ln = tls.NewListener(ln, &tls.Config{
			Certificates: []tls.Certificate{cert},
		})
	}
	r.addr = ln.Addr().String()
	var wg sync.WaitGroup
	var conns sync.Map
	t.Cleanup(func() {
		close(r.closed)
		_ = ln.Close()
		conns.Range(func(c, _ any) bool {
			_ = c.(net.Conn).Close()
			return true
		})
		wg.Wait()
	})
	wg.Go(func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			conns.Store(c, nil)
			wg.Go(func() {
				defer conns.Delete(c)
				defer c.Close()
				r.serve(c)
			})
		}
	})
	return r
}

// serve runs the relay protocol on c.
func (r *fakeRelay) serve(c net.Conn) {
	ch, err := exchange.Accept(relayconn.NewFraming(c, 0))
	if err != nil {
		return
	}
	p := &relayPeer{ch: ch, conn: c}
	f, err := p.read()
	if err != nil {
		return
	}
	reg := f.GetRegister()
	if reg == nil {
		return
	}
	switch reg.GetMode() {
	case pb.Register_MODE_CREATE:
		token := make([]byte, 16)
		_, _ = rand.Read(token)
		sess := &relaySession{listener: p, joined: make(chan *relayPeer, 1)}
		r.mu.Lock()
		r.waiting[hex.EncodeToString(token)] = sess
		r.mu.Unlock()
		err := p.write(&pb.Frame{Kind: &pb.Frame_Registered{
			Registered: &pb.Registered{
				Token:             token,
				TtlSeconds:        600,
				SessionTtlSeconds: uint32(r.sessionTTL / time.Second),
			},
		}})
		if err != nil {
			return
		}
		select {
		case dialer := <-sess.joined:
			forward(p, dialer)
		case <-r.closed:
		}
	case pb.Register_MODE_JOIN:
		key := hex.EncodeToString(reg.GetToken())
		r.mu.Lock()
		sess, ok := r.waiting[key]
		delete(r.waiting, key)
		r.mu.Unlock()
		if !ok {
			return
		}
		err := p.write(&pb.Frame{Kind: &pb.Frame_Registered{
			Registered: &pb.Registered{
				Token:             reg.GetToken(),
				SessionTtlSeconds: uint32(r.sessionTTL / time.Second),
			},
		}})
		if err != nil {
			return
		}
		sess.joined <- p
		forward(p, sess.listener)
	}
}

// forward passes the messages that from sends on to to until from fails,
// and then closes both.
func forward(from, to *relayPeer) {
	defer func() {
		_ = from.conn.Close()
		_ = to.conn.Close()
	}()
	for {
		f, err := from.read()
		if err != nil {
			return
		}
		switch {
		case f.GetMsg() != nil:
			err = to.write(f)
		case f.GetPing() != nil:
			err = from.write(&pb.Frame{Kind: &pb.Frame_Pong{
				Pong: &pb.Pong{},
			}})
		}
		if err != nil {
			return
		}
	}
}

// selfSignedCert returns a self-signed certificate for 127.0.0.1, like
// the one a relay makes when it has no certificate configured.
func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	a := require.New(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	a.NoError(err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "relay"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(
		rand.Reader, tmpl, tmpl, &key.PublicKey, key,
	)
	a.NoError(err)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// relayResult is what a relay server or a relay dial came to.
type relayResult struct {
	t   *kamune.Transport
	ttl time.Duration
	err error
}

// relayPair runs a relay server and a relay dial to it through r with
// the given passwords, and returns the session each side got.
func relayPair(
	t *testing.T, r relayTarget, serverPass, dialPass string,
) (server, dialer relayResult) {
	t.Helper()
	accept := func(*storage.Storage, *storage.Peer) error { return nil }
	ctx := context.Background()
	delivered := make(chan relayResult, 1)
	srv, token, ttl, err := relayServe(
		ctx, r, serverPass, openTestStore(t), accept,
		func(tr *kamune.Transport, release chan struct{}) {
			delivered <- relayResult{t: tr}
			<-release
		},
		func(error) {},
	)
	if err != nil {
		return relayResult{err: err}, relayResult{}
	}
	t.Cleanup(func() { _ = srv.Close() })

	dialed := make(chan relayResult, 1)
	go func() {
		tr, ttl, err := relayDial(
			ctx, r, hex.EncodeToString(token), dialPass,
			openTestStore(t), accept,
		)
		dialed <- relayResult{t: tr, ttl: ttl, err: err}
	}()
	dialer = waitFor(t, dialed)
	if dialer.err != nil {
		return relayResult{ttl: ttl}, dialer
	}
	t.Cleanup(func() { _ = dialer.t.CloseAbort() })
	server = waitFor(t, delivered)
	server.ttl = ttl
	t.Cleanup(func() { _ = server.t.CloseAbort() })
	return server, dialer
}

func TestParseRelayAddr(t *testing.T) {
	tests := []struct {
		addr   string
		scheme string
		host   string
		ok     bool
	}{
		{"relay.example:8891", "wss", "relay.example:8891", true},
		{"relay.example", "wss", "relay.example", true},
		{" wss://relay.example:443 ", "wss", "relay.example:443", true},
		{"WSS://relay.example", "wss", "relay.example", true},
		{"tls://127.0.0.1:8890", "tls", "127.0.0.1:8890", true},
		{"ws://localhost:8888", "ws", "localhost:8888", true},
		{"tcp://[::1]:8889", "tcp", "[::1]:8889", true},
		{"tls://relay.example", "", "", false},
		{"tcp://relay.example", "", "", false},
		{"http://relay.example:80", "", "", false},
		{"wss://relay.example/ws", "", "", false},
		{"wss://user@relay.example", "", "", false},
		{"wss://", "", "", false},
		{"", "", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.addr, func(t *testing.T) {
			a := require.New(t)
			r, err := parseRelayAddr(tt.addr)
			if !tt.ok {
				a.ErrorIs(err, errRelayAddress)
				return
			}
			a.NoError(err)
			a.Equal(tt.scheme, r.scheme)
			a.Equal(tt.host, r.host)
			a.Equal(tt.scheme == "wss" || tt.scheme == "tls", r.secure())
		})
	}
}

func TestRelay_SessionOverTCP(t *testing.T) {
	a := require.New(t)
	relay := startFakeRelay(t, false, time.Hour)
	r, err := parseRelayAddr("tcp://" + relay.addr)
	a.NoError(err)

	server, dialer := relayPair(t, r, "", "")
	a.NoError(server.err)
	a.NoError(dialer.err)
	a.Equal(time.Hour, server.ttl)
	a.Equal(time.Hour, dialer.ttl)
	a.Equal(server.t.SessionID(), dialer.t.SessionID())

	received := make(chan []byte, 1)
	go func() {
		_, payload, _ := server.t.ReceivePayload()
		received <- payload
	}()
	_, err = dialer.t.Send(
		kamune.Bytes([]byte("hi")), kamune.RouteExchangeMessages,
	)
	a.NoError(err)
	b := kamune.Bytes(nil)
	a.NoError(proto.Unmarshal(waitFor(t, received), b))
	a.Equal("hi", string(b.GetValue()))
}

func TestRelay_TLSChecksTheCertificate(t *testing.T) {
	a := require.New(t)
	relay := startFakeRelay(t, true, time.Hour)
	r, err := parseRelayAddr("tls://" + relay.addr)
	a.NoError(err)

	// The relay's certificate is self-signed, so neither side trusts it.
	accept := func(*storage.Storage, *storage.Peer) error { return nil }
	_, _, _, err = relayServe(
		context.Background(), r, "", openTestStore(t), accept,
		func(*kamune.Transport, chan struct{}) {}, func(error) {},
	)
	var unknown x509.UnknownAuthorityError
	a.True(errors.As(err, &unknown), "error: %v", err)
	_, _, err = relayDial(
		context.Background(), r, "00112233445566778899aabbccddeeff", "",
		openTestStore(t), accept,
	)
	a.True(errors.As(err, &unknown), "error: %v", err)
}
