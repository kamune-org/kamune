package handlers

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// soKeepAlive reports whether SO_KEEPALIVE is set on c. getsockoptInt is
// the platform's syscall.GetsockoptInt, whose descriptor type differs
// between Unix and Windows.
func soKeepAlive(c *net.TCPConn) (bool, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return false, err
	}
	var value int
	var soerr error
	err = raw.Control(func(fd uintptr) {
		value, soerr = getsockoptInt(
			fd, syscall.SOL_SOCKET, syscall.SO_KEEPALIVE,
		)
	})
	if err != nil {
		return false, err
	}
	if soerr != nil {
		return false, soerr
	}
	// Darwin returns the SO_KEEPALIVE flag bit (8), not 1.
	return value != 0, nil
}

func selfSigned(t *testing.T) tls.Certificate {
	t.Helper()
	a := require.New(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	a.NoError(err)
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	a.NoError(err)
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "kamune-relay-test"},
		NotBefore:    now,
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(
		rand.Reader, tmpl, tmpl, &key.PublicKey, key,
	)
	a.NoError(err)
	cert, err := x509.ParseCertificate(der)
	a.NoError(err)
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
		Leaf:        cert,
	}
}

func TestSetTCPKeepAlive_TLSConn(t *testing.T) {
	a := require.New(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{selfSigned(t)},
	})
	a.NoError(err)
	t.Cleanup(func() { _ = ln.Close() })

	// tls.Listener.Accept returns before the handshake. Waiting for
	// tls.Dial to finish before the server reads deadlocks both sides.
	// Production sets keepalive immediately after Accept, so this test
	// does the same and then closes the socket to unblock the client.
	clientDone := make(chan struct{})
	go func() {
		defer close(clientDone)
		conn, err := tls.Dial(
			"tcp", ln.Addr().String(),
			&tls.Config{InsecureSkipVerify: true},
		)
		if err != nil {
			return
		}
		conn.Close()
	}()

	server, err := ln.Accept()
	a.NoError(err)
	defer server.Close()

	tlsConn, ok := server.(*tls.Conn)
	a.True(ok)
	tcp, ok := tlsConn.NetConn().(*net.TCPConn)
	a.True(ok)
	// Go enables keepalive on accept. Turn it off so the helper is
	// what turns the option back on.
	a.NoError(tcp.SetKeepAlive(false))
	off, err := soKeepAlive(tcp)
	a.NoError(err)
	a.False(off)
	a.NoError(setTCPKeepAlive(server))
	on, err := soKeepAlive(tcp)
	a.NoError(err)
	a.True(on)
	a.NoError(server.Close())
	select {
	case <-clientDone:
	case <-time.After(2 * time.Second):
		t.Fatal("client dial did not return after the server closed")
	}

	plainLn, err := net.Listen("tcp", "127.0.0.1:0")
	a.NoError(err)
	t.Cleanup(func() { _ = plainLn.Close() })
	go func() {
		c, err := net.Dial("tcp", plainLn.Addr().String())
		if err == nil {
			defer c.Close()
			_, _ = io.Copy(io.Discard, c)
		}
	}()
	plain, err := plainLn.Accept()
	a.NoError(err)
	t.Cleanup(func() { _ = plain.Close() })
	plainTCP := plain.(*net.TCPConn)
	a.NoError(plainTCP.SetKeepAlive(false))
	off, err = soKeepAlive(plainTCP)
	a.NoError(err)
	a.False(off)
	a.NoError(setTCPKeepAlive(plain))
	on, err = soKeepAlive(plain.(*net.TCPConn))
	a.NoError(err)
	a.True(on)
}
