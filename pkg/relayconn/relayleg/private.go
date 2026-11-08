package relayleg

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/hpke"
	"crypto/rand"
	"crypto/sha512"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const (
	// pemType is the PEM block type of a relay static key file.
	pemType = "KAMUNE RELAY STATIC KEY"

	// brokerDomain is the prefix ExtractShared allows.
	brokerDomain = "kamune broker v2"
)

// PrivateKey is a relay static X25519 private key.
//
// Outside this package the only use is ExtractShared. The scalar,
// the ecdh private key, and the raw DH output are not accessible.
// The key never signs.
type PrivateKey struct {
	// hpke is the DHKEM(X25519, HKDF-SHA256) key the handshake uses.
	hpke hpke.PrivateKey
	// x25519 is the scalar. ExtractShared and the key file use it.
	x25519 *ecdh.PrivateKey
}

// GenerateKey returns a new relay static key.
func GenerateKey() (*PrivateKey, error) {
	sk, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate relay key: %w", err)
	}
	return newPrivateKey(sk)
}

func newPrivateKey(sk *ecdh.PrivateKey) (*PrivateKey, error) {
	kem, err := hpke.NewDHKEMPrivateKey(sk)
	if err != nil {
		return nil, fmt.Errorf("hpke private key: %w", err)
	}
	k := &PrivateKey{hpke: kem, x25519: sk}
	// Both halves are the same X25519 key. Section 11.5 allows
	// no second scalar.
	if !bytes.Equal(k.hpke.PublicKey().Bytes(), sk.PublicKey().Bytes()) {
		return nil, errors.New(
			"hpke public key does not match the x25519 key",
		)
	}
	return k, nil
}

// PublicKey returns the public half of k.
func (k *PrivateKey) PublicKey() PublicKey {
	var pk PublicKey
	copy(pk[:], k.x25519.PublicKey().Bytes())
	return pk
}

// ExtractShared returns HKDF-Extract with SHA-512. The ikm is
// X25519(sk, peer) and the salt is domain followed by the public key.
// domain must start with "kamune broker v2".
func (k *PrivateKey) ExtractShared(
	domain string, peer []byte,
) ([]byte, error) {
	if !strings.HasPrefix(domain, brokerDomain) {
		return nil, fmt.Errorf("%w: domain %q", ErrKeyUsage, domain)
	}
	pub, err := ecdh.X25519().NewPublicKey(peer)
	if err != nil {
		return nil, fmt.Errorf("extract shared: %w", err)
	}
	dh, err := k.x25519.ECDH(pub)
	if err != nil {
		return nil, fmt.Errorf("extract shared: %w", err)
	}
	pk := k.PublicKey()
	salt := make([]byte, 0, len(domain)+len(pk))
	salt = append(salt, domain...)
	salt = append(salt, pk[:]...)
	// crypto/hkdf.Extract takes (hash, secret, salt). The secret
	// is the ikm and the salt is domain || pk.
	out, err := hkdf.Extract(sha512.New, dh, salt)
	if err != nil {
		return nil, fmt.Errorf("extract shared: %w", err)
	}
	return out, nil
}

// CreatePrivateKeyFile generates a key and writes it to path.
// The file is created with O_EXCL and mode 0600, then the file and
// its directory are fsynced. An existing file is left unchanged.
func CreatePrivateKeyFile(path string) (*PrivateKey, error) {
	k, err := GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("create relay key: %w", err)
	}
	block := &pem.Block{
		Type:  pemType,
		Bytes: k.x25519.Bytes(),
	}
	err = writeNewFile(path, pem.EncodeToMemory(block))
	if err != nil {
		return nil, fmt.Errorf("create relay key %s: %w", path, err)
	}
	return k, nil
}

// LoadPrivateKeyFile reads a key written by CreatePrivateKeyFile.
// The file must hold one PEM block of type KAMUNE RELAY STATIC KEY,
// with no headers and a 32-byte body. Errors name path.
func LoadPrivateKeyFile(path string) (*PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("load relay key %s: %w", path, err)
	}
	const marker = "-----BEGIN "
	idx := bytes.Index(data, []byte(marker))
	if idx < 0 {
		return nil, fmt.Errorf(
			"load relay key %s: no PEM block", path,
		)
	}
	if len(bytes.TrimSpace(data[:idx])) != 0 {
		return nil, fmt.Errorf(
			"load relay key %s: data before the PEM block", path,
		)
	}
	block, rest := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf(
			"load relay key %s: no PEM block", path,
		)
	}
	if block.Type != pemType {
		return nil, fmt.Errorf(
			"load relay key %s: PEM type %q", path, block.Type,
		)
	}
	if len(block.Headers) != 0 {
		return nil, fmt.Errorf(
			"load relay key %s: PEM headers", path,
		)
	}
	if next, _ := pem.Decode(rest); next != nil {
		return nil, fmt.Errorf(
			"load relay key %s: extra PEM block", path,
		)
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf(
			"load relay key %s: trailing data", path,
		)
	}
	if len(block.Bytes) != rawKeyLen {
		return nil, fmt.Errorf(
			"load relay key %s: body is %d bytes",
			path, len(block.Bytes),
		)
	}
	sk, err := ecdh.X25519().NewPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("load relay key %s: %w", path, err)
	}
	k, err := newPrivateKey(sk)
	if err != nil {
		return nil, fmt.Errorf("load relay key %s: %w", path, err)
	}
	return k, nil
}

// writeNewFile writes data to path, which must not exist yet.
// On any error after the file is created, it removes the file.
func writeNewFile(path string, data []byte) error {
	f, err := os.OpenFile(
		path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600,
	)
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
		return err
	}
	if err := syncDir(filepath.Dir(path)); err != nil {
		_ = os.Remove(path)
		return err
	}
	return nil
}

// syncDir fsyncs the directory at path so the new directory entry
// reaches stable storage. On Windows it does nothing: a directory
// opened with os.Open is read-only, FlushFileBuffers needs write
// access, and NTFS makes the entry durable with its own journal.
func syncDir(path string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	d, err := os.Open(path)
	if err != nil {
		return err
	}
	err = d.Sync()
	if cErr := d.Close(); err == nil {
		err = cErr
	}
	return err
}
