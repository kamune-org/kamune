package run

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/kamune-org/kamune/cmd/relay/internal/config"
	"github.com/kamune-org/kamune/pkg/relayconn"
)

// Names of the files in the data directory that hold the self-signed
// certificate and its key.
const (
	selfSignedCertName = "relay-cert.pem"
	selfSignedKeyName  = "relay-key.pem"
)

// certStore hands out the certificates of the [tls] and [wss] listeners.
// A listener with no cert_file and key_file gets the self-signed
// certificate kept in the data directory, which is created there on first
// use. Every such listener shares it, so clients pin one fingerprint for
// the relay, and it stays the same across restarts.
type certStore struct {
	// dataDir is server.data_dir. Empty means config.DefaultDataDir.
	dataDir string
	// self is the self-signed certificate, once loaded.
	self *tls.Certificate
}

// serverConfig returns the TLS config of the listener called name, which
// uses certFile and keyFile, or the self-signed certificate when both are
// empty. It logs the certificate's SHA-256 fingerprint, the value clients
// pin.
func (s *certStore) serverConfig(
	name, certFile, keyFile string,
) (*tls.Config, error) {
	var (
		cert tls.Certificate
		err  error
	)
	if certFile == "" && keyFile == "" {
		cert, err = s.selfSigned()
	} else {
		cert, err = loadCert(certFile, keyFile)
	}
	if err != nil {
		return nil, err
	}
	// Both loaders fail on a pair without a certificate, so the leaf,
	// the certificate the relay sends, is always there.
	fingerprint := relayconn.CertFingerprint(cert.Certificate[0])
	slog.Info(
		"tls certificate",
		slog.String("listener", name),
		slog.String("sha256", fingerprint),
	)
	return newServerTLSConfig(cert), nil
}

// selfSigned returns the self-signed certificate, loading or creating it
// on the first call.
func (s *certStore) selfSigned() (tls.Certificate, error) {
	if s.self != nil {
		return *s.self, nil
	}
	dir := s.dataDir
	if dir == "" {
		var err error
		if dir, err = config.DefaultDataDir(); err != nil {
			return tls.Certificate{}, err
		}
	}
	cert, err := loadOrCreateSelfSigned(dir)
	if err != nil {
		return tls.Certificate{}, err
	}
	s.self = &cert
	return cert, nil
}

// newServerTLSConfig returns the server TLS config for cert. It accepts
// TLS 1.3 only: an older handshake sends the certificate in the clear, so
// anyone on the path could read it, and every kamune client speaks 1.3.
func newServerTLSConfig(cert tls.Certificate) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}
}

// loadCert loads the certificate and key an operator configured.
func loadCert(certFile, keyFile string) (tls.Certificate, error) {
	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf(
			"load tls cert from %q and %q: %w "+
				"(generate one with `openssl req -x509 ...`)",
			certFile, keyFile, err,
		)
	}
	return pair, nil
}

// loadOrCreateSelfSigned returns the self-signed certificate kept in dir.
// When neither of its files is there, it creates dir and a new
// certificate. It never replaces a file that is there: a new certificate
// would break every client that pinned the old one, so a file that does
// not load, or one without the other, is an error for the operator to
// resolve.
func loadOrCreateSelfSigned(dir string) (tls.Certificate, error) {
	certPath := filepath.Join(dir, selfSignedCertName)
	keyPath := filepath.Join(dir, selfSignedKeyName)
	certFound, err := fileExists(certPath)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyFound, err := fileExists(keyPath)
	if err != nil {
		return tls.Certificate{}, err
	}

	switch {
	case certFound && keyFound:
		cert, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return tls.Certificate{}, fmt.Errorf(
				"load self-signed certificate from %q: %w", dir, err,
			)
		}
		return cert, nil
	case certFound || keyFound:
		return tls.Certificate{}, fmt.Errorf(
			"self-signed certificate in %q is incomplete: %s and %s "+
				"must both exist; restore the missing one, or remove "+
				"both to create a new certificate (clients that pinned "+
				"the old one must then pin the new one)",
			dir, selfSignedCertName, selfSignedKeyName,
		)
	}

	certPEM, keyPEM, err := createSelfSignedCert()
	if err != nil {
		return tls.Certificate{}, fmt.Errorf(
			"generate self-signed cert: %w", err,
		)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf(
			"parse self-signed cert: %w", err,
		)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return tls.Certificate{}, fmt.Errorf("create data dir: %w", err)
	}
	if err := writeNewFile(keyPath, keyPEM, 0o600); err != nil {
		return tls.Certificate{}, fmt.Errorf(
			"save self-signed key: %w", err,
		)
	}
	if err := writeNewFile(certPath, certPEM, 0o644); err != nil {
		_ = os.Remove(keyPath)
		return tls.Certificate{}, fmt.Errorf(
			"save self-signed cert: %w", err,
		)
	}
	slog.Info(
		"created self-signed certificate",
		slog.String("cert_file", certPath),
		slog.String("key_file", keyPath),
	)
	return cert, nil
}

// fileExists reports whether path exists.
func fileExists(path string) (bool, error) {
	_, err := os.Stat(path)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, fs.ErrNotExist):
		return false, nil
	default:
		return false, err
	}
}

// writeNewFile writes data to path, which must not exist yet, with perm.
// It removes what it wrote if it fails part-way.
func writeNewFile(path string, data []byte, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if cErr := f.Close(); err == nil {
		err = cErr
	}
	if err != nil {
		_ = os.Remove(path)
	}
	return err
}

func createSelfSignedCert() (certPEM, keyPEM []byte, err error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("generate key: %w", err)
	}

	// 128-bit cryptographically random serial, as recommended by
	// RFC 5280 §4.1.2.2. Avoids collisions when the same process
	// generates multiple certs within the same nanosecond.
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, nil, fmt.Errorf("generate serial: %w", err)
	}

	// The subject and names are those of any certificate made for a
	// local test server. Nothing in it names the relay or kamune, so a
	// probe that fetches it learns no more than that it is self-signed.
	template := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: "localhost",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageKeyEncipherment |
			x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses: []net.IP{
			net.IPv4(127, 0, 0, 1),
			net.IPv6loopback,
		},
	}

	der, err := x509.CreateCertificate(
		rand.Reader, &template, &template, &priv.PublicKey, priv,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("create cert: %w", err)
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	privBytes := x509.MarshalPKCS1PrivateKey(priv)
	keyPEM = pem.EncodeToMemory(&pem.Block{
		Type: "RSA PRIVATE KEY", Bytes: privBytes},
	)
	return certPEM, keyPEM, nil
}
