package relayconn

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

var (
	// ErrInvalidCertFingerprint is returned by ParseCertFingerprint,
	// VerifyCertFingerprint and PinnedTLSConfig for a fingerprint that is
	// not a SHA-256 digest.
	ErrInvalidCertFingerprint = errors.New(
		"certificate fingerprint must be a SHA-256 digest",
	)

	// ErrCertPinMismatch is returned by a TLS handshake that checks the
	// relay's certificate with VerifyCertFingerprint, or uses a config from
	// PinnedTLSConfig, when the certificate has a different fingerprint.
	ErrCertPinMismatch = errors.New(
		"relay certificate does not match the pinned fingerprint",
	)
)

// CertFingerprint returns the SHA-256 fingerprint of a DER-encoded
// certificate, such as tls.Certificate.Certificate[0] or
// x509.Certificate.Raw, as 64 lowercase hex digits. It is the digest that
// "openssl x509 -noout -fingerprint -sha256" prints, without the colons.
func CertFingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

// ParseCertFingerprint parses a SHA-256 certificate fingerprint written
// as 64 hex digits in either case, optionally separated by colons as
// openssl prints them. Surrounding spaces are ignored.
func ParseCertFingerprint(s string) ([]byte, error) {
	s = strings.ReplaceAll(strings.TrimSpace(s), ":", "")
	fp, err := hex.DecodeString(s)
	if err != nil || len(fp) != sha256.Size {
		return nil, ErrInvalidCertFingerprint
	}
	return fp, nil
}

// VerifyCertFingerprint returns a function for tls.Config.VerifyConnection
// that accepts only a server whose leaf certificate has the given SHA-256
// fingerprint, the raw digest that ParseCertFingerprint returns. A
// mismatch fails the handshake with an error wrapping ErrCertPinMismatch
// that names the certificate's fingerprint.
//
// The pin does not replace chain verification unless the config also
// sets InsecureSkipVerify; PinnedTLSConfig does both for a relay with a
// self-signed certificate.
func VerifyCertFingerprint(
	fingerprint []byte,
) (func(tls.ConnectionState) error, error) {
	if len(fingerprint) != sha256.Size {
		return nil, ErrInvalidCertFingerprint
	}
	want := bytes.Clone(fingerprint)
	return func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return fmt.Errorf("%w: no certificate", ErrCertPinMismatch)
		}
		got := sha256.Sum256(cs.PeerCertificates[0].Raw)
		if !bytes.Equal(got[:], want) {
			return fmt.Errorf("%w: got %x", ErrCertPinMismatch, got)
		}
		return nil
	}, nil
}

// PinnedTLSConfig returns a TLS client config for the wss and tls relay
// helpers that trusts exactly the relay certificate with the given
// SHA-256 fingerprint, the raw digest that ParseCertFingerprint returns.
// It is the way to reach a relay with a self-signed certificate without
// turning off server authentication: the pin takes the place of chain and
// host name verification, which such a certificate cannot pass, and is
// checked on every handshake, resumed ones included. A handshake with any
// other certificate fails with an error wrapping ErrCertPinMismatch.
//
// The pin covers the certificate, not just its key, so it has to be
// updated whenever the relay's certificate changes.
func PinnedTLSConfig(fingerprint []byte) (*tls.Config, error) {
	verify, err := VerifyCertFingerprint(fingerprint)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		// Chain and host name checks are off; VerifyConnection checks
		// the pin instead.
		InsecureSkipVerify: true,
		VerifyConnection:   verify,
		MinVersion:         tls.VersionTLS12,
	}, nil
}
