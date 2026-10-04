package relayconn

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/stretchr/testify/require"

	"github.com/kamune-org/kamune"
)

// selfSignedCert returns a self-signed certificate for 127.0.0.1, like
// the one a relay generates when it has no certificate configured.
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
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	a.NoError(err)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// echoRelayTLS serves echoRelay over TLS with cert and returns its
// address.
func echoRelayTLS(t *testing.T, cert tls.Certificate, greeting []byte) string {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
	})
	require.New(t).NoError(err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				echoRelay(newTLSAdapter(c.(*tls.Conn)), greeting)
			}()
		}
	}()
	return ln.Addr().String()
}

// echoRelayWSS serves echoRelay over WebSocket on TLS with cert and
// returns its address.
func echoRelayWSS(t *testing.T, cert tls.Certificate, greeting []byte) string {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			conn, err := websocket.Accept(w, r, nil)
			if err != nil {
				return
			}
			defer conn.CloseNow()
			echoRelay(&wsAdapter{conn: conn, ctx: r.Context()}, greeting)
		},
	))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	// Refused handshakes are expected; keep them out of the test log.
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "https://")
}

func TestParseCertFingerprint(t *testing.T) {
	der := []byte("certificate")
	sum := sha256.Sum256(der)
	hexFP := CertFingerprint(der)
	var colons []string
	for i := 0; i < len(hexFP); i += 2 {
		colons = append(colons, strings.ToUpper(hexFP[i:i+2]))
	}

	tests := []struct {
		name    string
		in      string
		wantErr bool
	}{
		{name: "hex", in: hexFP},
		{name: "openssl", in: strings.Join(colons, ":")},
		{name: "spaces", in: " " + strings.ToUpper(hexFP) + "\n"},
		{name: "empty", in: "", wantErr: true},
		{name: "short", in: hexFP[:62], wantErr: true},
		{name: "long", in: hexFP + "00", wantErr: true},
		{name: "not hex", in: "zz" + hexFP[2:], wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			fp, err := ParseCertFingerprint(tc.in)
			if tc.wantErr {
				a.ErrorIs(err, ErrInvalidCertFingerprint)
				return
			}
			a.NoError(err)
			a.Equal(sum[:], fp)
		})
	}

	_, err := PinnedTLSConfig(sum[:16])
	require.New(t).ErrorIs(err, ErrInvalidCertFingerprint)
}

// TestPinnedTLSConfig reaches relays with self-signed certificates over
// wss and tls using only a pinned fingerprint, and checks that a relay
// presenting any other certificate is refused.
func TestPinnedTLSConfig(t *testing.T) {
	cert := selfSignedCert(t)
	other := selfSignedCert(t)
	token := make([]byte, peerTokenSize)
	for i := range token {
		token[i] = byte(i + 1)
	}
	type openFunc func(
		ctx context.Context, addr string, cfg *tls.Config,
	) (kamune.Conn, error)
	dialWSS := func(
		ctx context.Context, addr string, cfg *tls.Config,
	) (kamune.Conn, error) {
		return DialRelayWSS(ctx, addr, token, cfg)
	}
	dialTLS := func(
		ctx context.Context, addr string, cfg *tls.Config,
	) (kamune.Conn, error) {
		return DialRelayTLS(ctx, addr, token, cfg)
	}
	listen := func(
		fn func(context.Context, string, *tls.Config, ...Option) (
			*ListenResult, error,
		),
	) openFunc {
		return func(
			ctx context.Context, addr string, cfg *tls.Config,
		) (kamune.Conn, error) {
			res, err := fn(ctx, addr, cfg)
			if err != nil {
				return nil, err
			}
			t.Cleanup(func() { _ = res.Listener.Close() })
			return res.Listener.Accept()
		}
	}

	tests := []struct {
		open  openFunc
		relay func(*testing.T, tls.Certificate, []byte) string
		name  string
	}{
		{name: "dial wss", relay: echoRelayWSS, open: dialWSS},
		{name: "dial tls", relay: echoRelayTLS, open: dialTLS},
		{
			name:  "listen wss",
			relay: echoRelayWSS, open: listen(ListenRelayWSS),
		},
		{
			name:  "listen tls",
			relay: echoRelayTLS, open: listen(ListenRelayTLS),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			addr := tc.relay(t, cert, []byte("hello"))
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()

			wrong, err := ParseCertFingerprint(
				CertFingerprint(other.Certificate[0]),
			)
			a.NoError(err)
			cfg, err := PinnedTLSConfig(wrong)
			a.NoError(err)
			_, err = tc.open(ctx, addr, cfg)
			a.ErrorIs(err, ErrCertPinMismatch)

			right, err := ParseCertFingerprint(
				CertFingerprint(cert.Certificate[0]),
			)
			a.NoError(err)
			cfg, err = PinnedTLSConfig(right)
			a.NoError(err)
			conn, err := tc.open(ctx, addr, cfg)
			a.NoError(err)
			defer conn.Close()
			a.NoError(conn.SetDeadline(time.Now().Add(5 * time.Second)))
			got, err := conn.ReadBytes()
			a.NoError(err)
			a.Equal("hello", string(got))
		})
	}
}
