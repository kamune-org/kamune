package run

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadTLSConfig_InMemoryWhenPathsEmpty(t *testing.T) {
	r := require.New(t)
	cfg, err := loadTLSConfig("", "")
	r.NoError(err)
	r.NotNil(cfg)
	assert.Len(t, cfg.Certificates, 1)
}

func TestLoadTLSConfig_LoadsExistingCert(t *testing.T) {
	r := require.New(t)
	a := assert.New(t)
	dir := t.TempDir()
	certPath := filepath.Join(dir, "server.crt")
	keyPath := filepath.Join(dir, "server.key")

	// Pre-create a valid self-signed pair so we can test the load
	// path without depending on the in-memory generator.
	writeSelfSignedPEM(t, certPath, keyPath)

	cfg, err := loadTLSConfig(certPath, keyPath)
	r.NoError(err)
	r.NotNil(cfg)
	a.Len(cfg.Certificates, 1)
}

func TestLoadTLSConfig_HardErrorsWhenFileMissing(t *testing.T) {
	r := require.New(t)
	a := assert.New(t)
	dir := t.TempDir()
	certPath := filepath.Join(dir, "missing.crt")
	keyPath := filepath.Join(dir, "missing.key")

	_, err := loadTLSConfig(certPath, keyPath)
	r.Error(err)
	a.Contains(err.Error(), "load tls cert")
}

func TestLoadTLSConfig_HardErrorsWhenFileInvalid(t *testing.T) {
	r := require.New(t)
	a := assert.New(t)
	dir := t.TempDir()
	certPath := filepath.Join(dir, "server.crt")
	keyPath := filepath.Join(dir, "server.key")

	junkCert := []byte("not a real certificate")
	junkKey := []byte("not a real key")
	r.NoError(os.WriteFile(certPath, junkCert, 0644))
	r.NoError(os.WriteFile(keyPath, junkKey, 0600))

	_, err := loadTLSConfig(certPath, keyPath)
	r.Error(err)
	a.Contains(err.Error(), "load tls cert")

	gotCert, err := os.ReadFile(certPath)
	r.NoError(err)
	assert.Equal(t, junkCert, gotCert, "cert file must not be overwritten")

	gotKey, err := os.ReadFile(keyPath)
	r.NoError(err)
	assert.Equal(t, junkKey, gotKey, "key file must not be overwritten")
}

func TestLoadTLSConfig_DoesNotOverwriteOnFailure(t *testing.T) {
	r := require.New(t)
	a := assert.New(t)
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
	a.Equal([]byte("corrupted"), gotCert)

	gotKey, err := os.ReadFile(keyPath)
	r.NoError(err)
	a.Equal(originalKey, gotKey, "key file must remain untouched on load failure")
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
