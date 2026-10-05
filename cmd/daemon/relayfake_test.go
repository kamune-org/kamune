package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/kamune-org/kamune/pkg/exchange"
	"github.com/kamune-org/kamune/pkg/relayconn"
	"github.com/kamune-org/kamune/pkg/relayconn/pb"
)

// fakeRelay is a small relay on TCP. It registers listeners, pairs a
// dialer with the waiting listener of its token and forwards messages
// between the two. A dialer whose token no listener holds has its
// connection closed.
type fakeRelay struct {
	ln net.Listener
	// scheme is the scheme of the relay's address: tcp, or tls for a
	// relay from newFakeTLSRelay.
	scheme string
	// ttl is the token TTL, in seconds, that the relay reports.
	ttl atomic.Uint32
	// sessionTTL is the session TTL, in seconds, that the relay
	// reports.
	sessionTTL atomic.Uint32
	// wrongToken makes the relay answer a listener registration that
	// asks for a token with another one.
	wrongToken atomic.Bool
	// hangUp makes the relay close a listener registration's connection
	// without an answer.
	hangUp atomic.Bool

	mu sync.Mutex
	// creates holds the hex token of every listener registration, in
	// the order they arrived.
	creates []string
	// asked holds the hex token of every listener registration that
	// asked for one, answered or not.
	asked []string
	// waiting holds the listeners that no dialer has joined yet.
	waiting map[string]*exchange.Channel
	// conns holds every connection by the hex token it registered or
	// joined.
	conns   map[string][]net.Conn
	changed chan struct{}
}

func newFakeRelay(t *testing.T) *fakeRelay {
	a := require.New(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	a.NoError(err)
	return startFakeRelay(t, ln, "tcp")
}

// newFakeTLSRelay starts a fake relay that serves TLS with a self-signed
// certificate, and returns it with the certificate in DER form.
func newFakeTLSRelay(t *testing.T) (*fakeRelay, []byte) {
	a := require.New(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	a.NoError(err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "fake relay"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	a.NoError(err)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	a.NoError(err)
	ln = tls.NewListener(ln, &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{der}, PrivateKey: key,
		}},
	})
	return startFakeRelay(t, ln, "tls"), der
}

// startFakeRelay serves a fake relay on ln, whose address has scheme.
func startFakeRelay(t *testing.T, ln net.Listener, scheme string) *fakeRelay {
	r := &fakeRelay{
		ln:      ln,
		scheme:  scheme,
		waiting: make(map[string]*exchange.Channel),
		conns:   make(map[string][]net.Conn),
		changed: make(chan struct{}, 1),
	}
	r.ttl.Store(600)
	go r.serve()
	t.Cleanup(r.close)
	return r
}

func (r *fakeRelay) addr() string {
	return r.scheme + "://" + r.ln.Addr().String()
}

func (r *fakeRelay) serve() {
	for {
		conn, err := r.ln.Accept()
		if err != nil {
			return
		}
		go r.handle(conn)
	}
}

func (r *fakeRelay) handle(conn net.Conn) {
	ch, err := exchange.Accept(relayconn.NewFraming(conn, 0))
	if err != nil {
		_ = conn.Close()
		return
	}
	data, err := ch.ReadBytes()
	if err != nil {
		_ = conn.Close()
		return
	}
	var frame pb.Frame
	if err := proto.Unmarshal(data, &frame); err != nil ||
		frame.GetRegister() == nil {
		_ = conn.Close()
		return
	}
	token := frame.GetRegister().GetToken()
	switch frame.GetRegister().GetMode() {
	case pb.Register_MODE_CREATE:
		if len(token) > 0 {
			r.mu.Lock()
			r.asked = append(r.asked, hex.EncodeToString(token))
			r.mu.Unlock()
		}
		switch {
		case r.hangUp.Load():
			_ = conn.Close()
			return
		case r.wrongToken.Load() && len(token) > 0:
			other := make([]byte, len(token))
			_, _ = rand.Read(other)
			r.reply(ch, other)
			_ = conn.Close()
			return
		}
		if len(token) == 0 {
			token = make([]byte, 16)
			_, _ = rand.Read(token)
		}
		key := hex.EncodeToString(token)
		r.mu.Lock()
		r.waiting[key] = ch
		r.conns[key] = append(r.conns[key], conn)
		r.mu.Unlock()
		r.reply(ch, token)
		// Count the registration only once the listener has its reply,
		// so that a test dropping it does not cut the registration.
		r.mu.Lock()
		r.creates = append(r.creates, key)
		r.mu.Unlock()
		r.notify()
	case pb.Register_MODE_JOIN:
		key := hex.EncodeToString(token)
		r.mu.Lock()
		listener, ok := r.waiting[key]
		delete(r.waiting, key)
		if ok {
			r.conns[key] = append(r.conns[key], conn)
		}
		r.mu.Unlock()
		if !ok {
			_ = conn.Close()
			return
		}
		r.reply(ch, token)
		go r.forward(ch, listener, key)
		go r.forward(listener, ch, key)
	default:
		_ = conn.Close()
	}
}

func (r *fakeRelay) reply(ch *exchange.Channel, token []byte) {
	b, _ := proto.Marshal(&pb.Frame{Kind: &pb.Frame_Registered{
		Registered: &pb.Registered{
			Token: token, TtlSeconds: r.ttl.Load(),
			SessionTtlSeconds: r.sessionTTL.Load(),
		},
	}})
	_ = ch.WriteBytes(b)
}

// forward copies frames from one side of a pairing to the other, and
// drops the pairing when either side fails.
func (r *fakeRelay) forward(from, to *exchange.Channel, key string) {
	for {
		data, err := from.ReadBytes()
		if err == nil {
			err = to.WriteBytes(data)
		}
		if err != nil {
			r.drop(key)
			return
		}
	}
}

func (r *fakeRelay) notify() {
	select {
	case r.changed <- struct{}{}:
	default:
	}
}

// drop closes the connections of the listener and dialer of token, as
// a relay restart or a network failure would.
func (r *fakeRelay) drop(key string) {
	r.mu.Lock()
	conns := r.conns[key]
	delete(r.conns, key)
	delete(r.waiting, key)
	r.mu.Unlock()
	for _, conn := range conns {
		_ = conn.Close()
	}
}

// created returns the hex tokens of the listener registrations so far.
func (r *fakeRelay) created() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.creates)
}

// askedFor returns the hex tokens that listener registrations asked for
// so far.
func (r *fakeRelay) askedFor() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.asked)
}

// waitCreated waits until n listeners have registered and returns their
// hex tokens.
func (r *fakeRelay) waitCreated(t *testing.T, n int) []string {
	t.Helper()
	deadline := time.After(testEventTimeout)
	for {
		if created := r.created(); len(created) >= n {
			return created
		}
		select {
		case <-r.changed:
		case <-deadline:
			t.Fatalf("relay saw %d registrations, want %d", len(r.created()), n)
		}
	}
}

func (r *fakeRelay) close() {
	_ = r.ln.Close()
	r.mu.Lock()
	var conns []net.Conn
	for _, c := range r.conns {
		conns = append(conns, c...)
	}
	r.conns = make(map[string][]net.Conn)
	r.mu.Unlock()
	for _, conn := range conns {
		_ = conn.Close()
	}
}
