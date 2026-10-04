package run

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/stretchr/testify/require"

	"github.com/kamune-org/kamune/cmd/relay/internal/config"
	"github.com/kamune-org/kamune/cmd/relay/internal/handlers"
	"github.com/kamune-org/kamune/cmd/relay/internal/services"
)

func TestLoadTLSConfig_InMemoryWhenPathsEmpty(t *testing.T) {
	r := require.New(t)
	cfg, err := loadTLSConfig("", "")
	r.NoError(err)
	r.NotNil(cfg)
	r.Len(cfg.Certificates, 1)

	parsed, err := x509.ParseCertificate(cfg.Certificates[0].Certificate[0])
	r.NoError(err)
	r.Contains(parsed.DNSNames, "localhost")
	hasLoopback := false
	for _, ip := range parsed.IPAddresses {
		if ip.Equal(net.IPv4(127, 0, 0, 1)) {
			hasLoopback = true
			break
		}
	}
	r.True(hasLoopback, "self-signed cert must include 127.0.0.1")
}

func TestLoadTLSConfig_LoadsExistingCert(t *testing.T) {
	r := require.New(t)
	dir := t.TempDir()
	certPath := filepath.Join(dir, "server.crt")
	keyPath := filepath.Join(dir, "server.key")

	// Pre-create a valid self-signed pair so we can test the load
	// path without depending on the in-memory generator.
	writeSelfSignedPEM(t, certPath, keyPath)

	cfg, err := loadTLSConfig(certPath, keyPath)
	r.NoError(err)
	r.NotNil(cfg)
	r.Len(cfg.Certificates, 1)
}

func TestLoadTLSConfig_HardErrorsWhenFileMissing(t *testing.T) {
	r := require.New(t)
	dir := t.TempDir()
	certPath := filepath.Join(dir, "missing.crt")
	keyPath := filepath.Join(dir, "missing.key")

	_, err := loadTLSConfig(certPath, keyPath)
	r.Error(err)
	r.Contains(err.Error(), "load tls cert")
}

func TestLoadTLSConfig_HardErrorsWhenFileInvalid(t *testing.T) {
	r := require.New(t)
	dir := t.TempDir()
	certPath := filepath.Join(dir, "server.crt")
	keyPath := filepath.Join(dir, "server.key")

	junkCert := []byte("not a real certificate")
	junkKey := []byte("not a real key")
	r.NoError(os.WriteFile(certPath, junkCert, 0644))
	r.NoError(os.WriteFile(keyPath, junkKey, 0600))

	_, err := loadTLSConfig(certPath, keyPath)
	r.Error(err)
	r.Contains(err.Error(), "load tls cert")

	gotCert, err := os.ReadFile(certPath)
	r.NoError(err)
	r.Equal(junkCert, gotCert, "cert file must not be overwritten")

	gotKey, err := os.ReadFile(keyPath)
	r.NoError(err)
	r.Equal(junkKey, gotKey, "key file must not be overwritten")
}

func TestLoadTLSConfig_DoesNotOverwriteOnFailure(t *testing.T) {
	r := require.New(t)
	dir := t.TempDir()
	certPath := filepath.Join(dir, "server.crt")
	keyPath := filepath.Join(dir, "server.key")

	writeSelfSignedPEM(t, certPath, keyPath)
	originalKey, err := os.ReadFile(keyPath)
	r.NoError(err)

	// Corrupt the cert; the load should fail and neither file
	// should be modified.
	r.NoError(os.WriteFile(certPath, []byte("corrupted"), 0644))

	_, err = loadTLSConfig(certPath, keyPath)
	r.Error(err)

	gotCert, err := os.ReadFile(certPath)
	r.NoError(err)
	r.Equal([]byte("corrupted"), gotCert)

	gotKey, err := os.ReadFile(keyPath)
	r.NoError(err)
	r.Equal(originalKey, gotKey, "key file must remain untouched on load failure")
}

func TestRun_PreflightFailureDoesNotStartEarlierListener(t *testing.T) {
	a := require.New(t)
	reservation, err := net.Listen("tcp", "127.0.0.1:0")
	a.NoError(err)
	address := reservation.Addr().String()
	a.NoError(reservation.Close())

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "relay.toml")
	cfg := fmt.Sprintf(`
[diagnose]
enabled = true
address = %q

[tls]
enabled = true
address = "127.0.0.1:0"
cert_file = %q
key_file = %q

[session]
token_ttl = "1m"
max_concurrent_sessions = 10

[rate_limit]
disabled = true
`, address, filepath.Join(dir, "missing.crt"), filepath.Join(dir, "missing.key"))
	a.NoError(os.WriteFile(cfgPath, []byte(cfg), 0600))

	err = Run(cfgPath)
	a.Error(err)
	a.Contains(err.Error(), "load tls config")

	time.Sleep(50 * time.Millisecond)
	listener, err := net.Listen("tcp", address)
	a.NoError(err, "diagnose listener leaked after preflight failure")
	if listener != nil {
		a.NoError(listener.Close())
	}
}

// writeSelfSignedPEM writes a self-signed cert+key pair to disk using
// the same crypto core as run.go. It exists only so the load tests can
// stage an existing valid pair without depending on the in-memory path.
func writeSelfSignedPEM(t *testing.T, certPath, keyFile string) {
	t.Helper()
	r := require.New(t)

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	r.NoError(err)

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	r.NoError(err)

	now := time.Now()
	template := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: "kamune-relay-test",
		},
		NotBefore:             now,
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(
		rand.Reader, &template, &template, &priv.PublicKey, priv,
	)
	r.NoError(err)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	})

	r.NoError(os.MkdirAll(filepath.Dir(certPath), 0755))
	r.NoError(os.WriteFile(certPath, certPEM, 0644))
	r.NoError(os.WriteFile(keyFile, keyPEM, 0600))
}

func TestNewBroker_DoesNotShareHubLimiter(t *testing.T) {
	a := require.New(t)
	cfg := config.Config{
		Session: config.Session{
			TokenTTL:              time.Minute,
			MaxConcurrentSessions: 10,
		},
		RateLimit: config.RateLimit{
			TimeWindow: time.Minute,
			Quota:      2,
			MaxEntries: 100,
		},
		Broker: config.Broker{
			Enabled:         true,
			Address:         "127.0.0.1:0",
			RegistrationTTL: time.Minute,
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	srvc, err := services.New(ctx, cfg)
	a.NoError(err)
	br, err := newBroker(cfg)
	a.NoError(err)
	go br.Run(ctx)
	t.Cleanup(func() { _ = br.Close() })

	client, err := net.ListenUDP(
		"udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)},
	)
	a.NoError(err)
	t.Cleanup(func() { _ = client.Close() })

	echo := []byte{'K', 'B', 'R', 'K', 0x01, 0x01}
	buf := make([]byte, 64)
	for range cfg.RateLimit.Quota {
		_, err := client.WriteToUDP(echo, br.Addr())
		a.NoError(err)
		a.NoError(client.SetReadDeadline(time.Now().Add(2 * time.Second)))
		_, _, err = client.ReadFromUDP(buf)
		a.NoError(err, "echo within quota must be answered")
	}
	_, err = client.WriteToUDP(echo, br.Addr())
	a.NoError(err)
	a.NoError(client.SetReadDeadline(time.Now().Add(200 * time.Millisecond)))
	_, _, err = client.ReadFromUDP(buf)
	a.Error(err, "broker limiter must drop echo over quota")

	a.True(
		srvc.Hub().RateLimiter().Allow("127.0.0.1"),
		"broker UDP traffic must not spend the TCP/WS quota",
	)
}

func TestNewBrokerLimits(t *testing.T) {
	t.Run("disabled", func(t *testing.T) {
		a := require.New(t)
		limits := newBrokerLimits(config.RateLimit{Disabled: true})
		a.Nil(limits.Echo)
		a.Nil(limits.Register)
	})
	t.Run("echo spray cannot evict register history", func(t *testing.T) {
		a := require.New(t)
		limits := newBrokerLimits(config.RateLimit{
			TimeWindow: time.Minute,
			Quota:      1,
			MaxEntries: 2,
		})
		a.NotNil(limits.Echo)
		a.NotNil(limits.Register)

		const victim = "192.0.2.1"
		a.True(limits.Register(victim))
		a.False(limits.Register(victim), "quota is one")
		// Forged sources fill the echo limiter well past max_entries.
		for i := range 10 {
			limits.Echo(fmt.Sprintf("198.51.100.%d", i))
		}
		a.False(
			limits.Register(victim),
			"spoofed echoes must not evict the register history",
		)
		a.True(limits.Echo(victim), "echo has its own budget")
	})
}

// TestNewWSServer_OneRequestPerConnection checks that a ws or wss server
// closes a connection after its first response instead of holding it open
// for further requests, and that wss does not negotiate HTTP/2.
func TestNewWSServer_OneRequestPerConnection(t *testing.T) {
	for _, useTLS := range []bool{false, true} {
		name := "ws"
		if useTLS {
			name = "wss"
		}
		t.Run(name, func(t *testing.T) {
			a := require.New(t)
			var tlsCfg *tls.Config
			if useTLS {
				var err error
				tlsCfg, err = loadTLSConfig("", "")
				a.NoError(err)
			}
			srv := newWSServer("127.0.0.1:0", http.NewServeMux(), tlsCfg)
			a.NotNil(srv.ErrorLog)
			a.Equal(
				handlers.HTTPErrorLog().Writer(), srv.ErrorLog.Writer(),
				"TLS handshake errors must go to slog at debug",
			)
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			a.NoError(err)
			done := make(chan struct{})
			go func() {
				defer close(done)
				if useTLS {
					_ = srv.ServeTLS(ln, "", "")
				} else {
					_ = srv.Serve(ln)
				}
			}()
			t.Cleanup(func() {
				_ = srv.Close()
				<-done
			})

			var conn net.Conn
			if useTLS {
				tc, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
					InsecureSkipVerify: true,
					NextProtos:         []string{"h2", "http/1.1"},
				})
				a.NoError(err)
				a.Equal(
					"http/1.1", tc.ConnectionState().NegotiatedProtocol,
				)
				conn = tc
			} else {
				conn, err = net.Dial("tcp", ln.Addr().String())
				a.NoError(err)
			}
			defer conn.Close()

			_, err = io.WriteString(
				conn, "GET / HTTP/1.1\r\nHost: relay\r\n\r\n",
			)
			a.NoError(err)
			a.NoError(conn.SetReadDeadline(time.Now().Add(10 * time.Second)))
			br := bufio.NewReader(conn)
			resp, err := http.ReadResponse(br, nil)
			a.NoError(err)
			a.Equal(http.StatusNotFound, resp.StatusCode)
			a.True(resp.Close, "response must announce the close")
			_, err = io.Copy(io.Discard, resp.Body)
			a.NoError(err)
			a.NoError(resp.Body.Close())

			_, err = br.ReadByte()
			a.Error(err)
			var ne net.Error
			a.False(
				errors.As(err, &ne) && ne.Timeout(),
				"server must close the connection, not leave it idle",
			)
		})
	}
}

// TestNewWSServer_Upgrades checks that /ws still upgrades on a ws and a wss
// server with keep-alives off: the 101 response must keep its
// Connection: Upgrade header.
func TestNewWSServer_Upgrades(t *testing.T) {
	for _, useTLS := range []bool{false, true} {
		name := "ws"
		if useTLS {
			name = "wss"
		}
		t.Run(name, func(t *testing.T) {
			a := require.New(t)
			cfg := config.Config{
				WS: config.WS{Enabled: true, Address: "127.0.0.1:0"},
				Session: config.Session{
					TokenTTL:              time.Minute,
					MaxConcurrentSessions: 10,
					HandshakeTimeout:      time.Minute,
				},
				RateLimit: config.RateLimit{Disabled: true},
			}
			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)
			srvc, err := services.New(ctx, cfg)
			a.NoError(err)
			mux := http.NewServeMux()
			mux.HandleFunc("/ws", handlers.New(srvc, cfg).WebSocketHandler)

			var tlsCfg *tls.Config
			if useTLS {
				tlsCfg, err = loadTLSConfig("", "")
				a.NoError(err)
			}
			srv := newWSServer("127.0.0.1:0", mux, tlsCfg)
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			a.NoError(err)
			done := make(chan struct{})
			go func() {
				defer close(done)
				_ = serveWS(srv, ln, handlers.New(srvc, cfg))
			}()
			t.Cleanup(func() {
				_ = srv.Close()
				<-done
			})

			scheme := "ws"
			opts := &websocket.DialOptions{}
			if useTLS {
				scheme = "wss"
				opts.HTTPClient = &http.Client{Transport: &http.Transport{
					TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
				}}
			}
			dialCtx, dialCancel := context.WithTimeout(
				context.Background(), 10*time.Second,
			)
			defer dialCancel()
			conn, resp, err := websocket.Dial(
				dialCtx, scheme+"://"+ln.Addr().String()+"/ws", opts,
			)
			a.NoError(err)
			a.Equal(http.StatusSwitchingProtocols, resp.StatusCode)
			a.NoError(conn.Close(websocket.StatusNormalClosure, ""))
		})
	}
}

// TestServeWS_RateLimitsBeforeTLS checks that a wss peer over its quota is
// refused at accept, before the relay signs a TLS handshake for it.
func TestServeWS_RateLimitsBeforeTLS(t *testing.T) {
	a := require.New(t)
	cfg := config.Config{
		WSS: config.WSS{Enabled: true, Address: "127.0.0.1:0"},
		Session: config.Session{
			TokenTTL:              time.Minute,
			MaxConcurrentSessions: 10,
		},
		RateLimit: config.RateLimit{
			TimeWindow: time.Minute,
			Quota:      1,
			MaxEntries: 100,
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	srvc, err := services.New(ctx, cfg)
	a.NoError(err)
	tlsCfg, err := loadTLSConfig("", "")
	a.NoError(err)
	srv := newWSServer("127.0.0.1:0", http.NewServeMux(), tlsCfg)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	a.NoError(err)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = serveWS(srv, ln, handlers.New(srvc, cfg))
	}()
	t.Cleanup(func() {
		_ = srv.Close()
		<-done
	})

	clientCfg := &tls.Config{InsecureSkipVerify: true}
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	first, err := tls.DialWithDialer(
		dialer, "tcp", ln.Addr().String(), clientCfg,
	)
	a.NoError(err, "first connection is within quota")
	defer first.Close()

	second, err := tls.DialWithDialer(
		dialer, "tcp", ln.Addr().String(), clientCfg,
	)
	if err == nil {
		second.Close()
	}
	a.Error(err, "a peer over quota must not get a TLS handshake")
}

func TestSharedRateLimitListeners(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*config.Config)
		wantFor []string
	}{
		{
			name: "loopback ws behind a tunnel",
			mutate: func(c *config.Config) {
				c.WS = config.WS{Enabled: true, Address: "127.0.0.1:8080"}
			},
			wantFor: []string{"ws"},
		},
		{
			name: "localhost ws",
			mutate: func(c *config.Config) {
				c.WS = config.WS{Enabled: true, Address: "localhost:8080"}
			},
			wantFor: []string{"ws"},
		},
		{
			name: "private wss and ipv6 loopback ws",
			mutate: func(c *config.Config) {
				c.WS = config.WS{Enabled: true, Address: "[::1]:8080"}
				c.WSS = config.WSS{Enabled: true, Address: "10.1.2.3:443"}
			},
			wantFor: []string{"ws", "wss"},
		},
		{
			name: "public bind",
			mutate: func(c *config.Config) {
				c.WS = config.WS{Enabled: true, Address: "0.0.0.0:8888"}
				c.WSS = config.WSS{Enabled: true, Address: ":8891"}
			},
		},
		{
			name: "disabled listener",
			mutate: func(c *config.Config) {
				c.WS = config.WS{Enabled: false, Address: "127.0.0.1:8080"}
			},
		},
		{
			name: "trusted proxies set",
			mutate: func(c *config.Config) {
				c.WS = config.WS{Enabled: true, Address: "127.0.0.1:8080"}
				c.Server.TrustedProxies = []string{"127.0.0.1/32"}
			},
		},
		{
			name: "rate limit off",
			mutate: func(c *config.Config) {
				c.WS = config.WS{Enabled: true, Address: "127.0.0.1:8080"}
				c.RateLimit.Disabled = true
			},
		},
		{
			name: "hostname bind",
			mutate: func(c *config.Config) {
				c.WS = config.WS{Enabled: true, Address: "relay.example:80"}
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			cfg := config.Config{
				TCP: config.TCP{Enabled: true, Address: "127.0.0.1:8889"},
			}
			tc.mutate(&cfg)
			var got []string
			for _, l := range sharedRateLimitListeners(cfg) {
				got = append(got, l.name)
			}
			a.Equal(tc.wantFor, got)
		})
	}
}
