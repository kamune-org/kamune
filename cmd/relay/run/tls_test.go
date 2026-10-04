package run

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/kamune-org/kamune/pkg/relayconn"
)

// testTLSConfig returns a server TLS config with a new self-signed
// certificate kept in a temporary data directory.
func testTLSConfig(t *testing.T) *tls.Config {
	t.Helper()
	store := &certStore{dataDir: t.TempDir()}
	cfg, err := store.serverConfig("test", "", "")
	require.New(t).NoError(err)
	return cfg
}

func leafDER(t *testing.T, cfg *tls.Config) []byte {
	t.Helper()
	a := require.New(t)
	a.NotNil(cfg)
	a.Len(cfg.Certificates, 1)
	a.NotEmpty(cfg.Certificates[0].Certificate)
	return cfg.Certificates[0].Certificate[0]
}

// TestCertStore_SelfSignedPersists checks that a listener without
// cert_file and key_file gets a self-signed certificate that is saved in
// the data directory, shared by tls and wss, and loaded again by the next
// process, so a client can pin its fingerprint.
func TestCertStore_SelfSignedPersists(t *testing.T) {
	a := require.New(t)
	dir := filepath.Join(t.TempDir(), "state", "relay")

	store := &certStore{dataDir: dir}
	tlsCfg, err := store.serverConfig("tls", "", "")
	a.NoError(err)
	wssCfg, err := store.serverConfig("wss", "", "")
	a.NoError(err)
	first := leafDER(t, tlsCfg)
	a.Equal(first, leafDER(t, wssCfg), "tls and wss must share one cert")

	parsed, err := x509.ParseCertificate(first)
	a.NoError(err)
	a.Contains(parsed.DNSNames, "localhost")
	hasLoopback := false
	for _, ip := range parsed.IPAddresses {
		if ip.Equal(net.IPv4(127, 0, 0, 1)) {
			hasLoopback = true
			break
		}
	}
	a.True(hasLoopback, "self-signed cert must include 127.0.0.1")

	certPath := filepath.Join(dir, selfSignedCertName)
	keyPath := filepath.Join(dir, selfSignedKeyName)
	a.FileExists(certPath)
	a.FileExists(keyPath)
	if runtime.GOOS != "windows" {
		info, err := os.Stat(keyPath)
		a.NoError(err)
		a.Equal(os.FileMode(0o600), info.Mode().Perm())
		info, err = os.Stat(dir)
		a.NoError(err)
		a.Equal(os.FileMode(0o700), info.Mode().Perm())
	}

	// A restart loads the same certificate instead of making a new one.
	restarted := &certStore{dataDir: dir}
	again, err := restarted.serverConfig("tls", "", "")
	a.NoError(err)
	a.Equal(first, leafDER(t, again), "cert must survive a restart")
}

// TestLoadOrCreateSelfSigned_KeepsExistingFiles checks that a data
// directory holding only one of the two files, or files that do not load,
// is an error and is left as it is: a new certificate would silently
// break clients that pinned the old one.
func TestLoadOrCreateSelfSigned_KeepsExistingFiles(t *testing.T) {
	tests := []struct {
		name  string
		files map[string][]byte
		want  string
	}{
		{
			name:  "cert only",
			files: map[string][]byte{selfSignedCertName: []byte("cert")},
			want:  "incomplete",
		},
		{
			name:  "key only",
			files: map[string][]byte{selfSignedKeyName: []byte("key")},
			want:  "incomplete",
		},
		{
			name: "corrupt pair",
			files: map[string][]byte{
				selfSignedCertName: []byte("not a certificate"),
				selfSignedKeyName:  []byte("not a key"),
			},
			want: "load self-signed certificate",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			dir := t.TempDir()
			for name, data := range tc.files {
				a.NoError(os.WriteFile(filepath.Join(dir, name), data, 0o600))
			}

			_, err := loadOrCreateSelfSigned(dir)
			a.Error(err)
			a.Contains(err.Error(), tc.want)

			entries, err := os.ReadDir(dir)
			a.NoError(err)
			a.Len(entries, len(tc.files), "no file may be added")
			for name, data := range tc.files {
				got, err := os.ReadFile(filepath.Join(dir, name))
				a.NoError(err)
				a.Equal(data, got, "%s must not be overwritten", name)
			}
		})
	}
}

func TestCertStore_LoadsConfiguredCert(t *testing.T) {
	a := require.New(t)
	dir := t.TempDir()
	certPath := filepath.Join(dir, "server.crt")
	keyPath := filepath.Join(dir, "server.key")
	writeSelfSignedPEM(t, certPath, keyPath)

	dataDir := filepath.Join(dir, "data")
	store := &certStore{dataDir: dataDir}
	cfg, err := store.serverConfig("tls", certPath, keyPath)
	a.NoError(err)
	pair, err := tls.LoadX509KeyPair(certPath, keyPath)
	a.NoError(err)
	a.Equal(pair.Certificate[0], leafDER(t, cfg))
	a.NoDirExists(dataDir, "configured certs must not create the data dir")
}

func TestCertStore_ConfiguredCertErrors(t *testing.T) {
	tests := []struct {
		name  string
		setup func(t *testing.T, certPath, keyPath string)
	}{
		{
			name:  "missing",
			setup: func(*testing.T, string, string) {},
		},
		{
			name: "invalid",
			setup: func(t *testing.T, certPath, keyPath string) {
				a := require.New(t)
				a.NoError(os.WriteFile(certPath, []byte("not a cert"), 0o644))
				a.NoError(os.WriteFile(keyPath, []byte("not a key"), 0o600))
			},
		},
		{
			name: "corrupt cert",
			setup: func(t *testing.T, certPath, keyPath string) {
				writeSelfSignedPEM(t, certPath, keyPath)
				require.New(t).NoError(
					os.WriteFile(certPath, []byte("corrupted"), 0o644),
				)
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			dir := t.TempDir()
			certPath := filepath.Join(dir, "server.crt")
			keyPath := filepath.Join(dir, "server.key")
			tc.setup(t, certPath, keyPath)
			before := readIfExists(t, certPath, keyPath)

			store := &certStore{dataDir: filepath.Join(dir, "data")}
			_, err := store.serverConfig("tls", certPath, keyPath)
			a.Error(err)
			a.Contains(err.Error(), "load tls cert")
			a.Equal(
				before, readIfExists(t, certPath, keyPath),
				"configured files must not be touched",
			)
			a.NoDirExists(filepath.Join(dir, "data"))
		})
	}
}

func readIfExists(t *testing.T, paths ...string) map[string][]byte {
	t.Helper()
	out := make(map[string][]byte)
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err == nil {
			out[p] = data
		}
	}
	return out
}

// lockedBuffer is a bytes.Buffer that a slog handler can share with
// goroutines left over from other tests.
type lockedBuffer struct {
	buf bytes.Buffer
	mu  sync.Mutex
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// TestCertStore_LogsFingerprint checks that serverConfig logs the SHA-256
// fingerprint of the certificate it serves, as the lowercase hex digest
// that openssl prints without colons, and that relayconn parses it back
// to the digest a client pins.
func TestCertStore_LogsFingerprint(t *testing.T) {
	a := require.New(t)
	out := &lockedBuffer{}
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(out, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	cfg := testTLSConfig(t)
	sum := sha256.Sum256(leafDER(t, cfg))

	var logged string
	for line := range strings.Lines(out.String()) {
		var rec struct {
			Msg      string `json:"msg"`
			Listener string `json:"listener"`
			SHA256   string `json:"sha256"`
		}
		a.NoError(json.Unmarshal([]byte(line), &rec))
		if rec.Msg == "tls certificate" && rec.Listener == "test" {
			logged = rec.SHA256
		}
	}
	a.Equal(hex.EncodeToString(sum[:]), logged)
	pin, err := relayconn.ParseCertFingerprint(logged)
	a.NoError(err)
	a.Equal(sum[:], pin)
}

// writeSelfSignedPEM writes a self-signed cert+key pair to disk, so that
// tests can stage a configured pair without going through the relay's
// own generator.
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

// TestCreateSelfSignedCert_GenericSubject checks that the self-signed
// certificate, which any client or probe can fetch, does not name the
// relay or kamune.
func TestCreateSelfSignedCert_GenericSubject(t *testing.T) {
	a := require.New(t)
	certPEM, _, err := createSelfSignedCert()
	a.NoError(err)
	block, _ := pem.Decode(certPEM)
	a.NotNil(block)
	cert, err := x509.ParseCertificate(block.Bytes)
	a.NoError(err)

	a.Equal("CN=localhost", cert.Subject.String())
	a.Equal(cert.Subject.String(), cert.Issuer.String())
	for _, s := range append(
		[]string{cert.Subject.String(), cert.Issuer.String()},
		cert.DNSNames...,
	) {
		a.NotContains(strings.ToLower(s), "kamune")
		a.NotContains(strings.ToLower(s), "relay")
	}
}

// TestServerTLSConfig_RequiresTLS13 checks that the tls and wss listeners
// refuse TLS 1.2, which would send the certificate in the clear.
func TestServerTLSConfig_RequiresTLS13(t *testing.T) {
	tests := []struct {
		name       string
		maxVersion uint16
		wantErr    bool
	}{
		{name: "tls 1.2", maxVersion: tls.VersionTLS12, wantErr: true},
		{name: "tls 1.3", maxVersion: tls.VersionTLS13},
	}
	serverCfg := testTLSConfig(t)
	require.New(t).Equal(uint16(tls.VersionTLS13), serverCfg.MinVersion)
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			ln, err := tls.Listen("tcp", "127.0.0.1:0", serverCfg)
			a.NoError(err)
			t.Cleanup(func() { _ = ln.Close() })
			go func() {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				_ = conn.(*tls.Conn).Handshake()
				_ = conn.Close()
			}()

			dialer := &net.Dialer{Timeout: 10 * time.Second}
			conn, err := tls.DialWithDialer(
				dialer, "tcp", ln.Addr().String(), &tls.Config{
					InsecureSkipVerify: true,
					MaxVersion:         tc.maxVersion,
				},
			)
			if tc.wantErr {
				a.Error(err)
				return
			}
			a.NoError(err)
			defer conn.Close()
			a.Equal(
				uint16(tls.VersionTLS13), conn.ConnectionState().Version,
			)
		})
	}
}
