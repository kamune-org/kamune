package run

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/kamune-org/kamune/cmd/relay/internal/config"
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
