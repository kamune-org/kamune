// kamune/pkg/ratchet/ratchet_test.go
package ratchet

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/kamune-org/kamune/pkg/exchange"
)

func randomBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

func TestRoundTripEncryption(t *testing.T) {
	a := assert.New(t)

	// Initial root secret shared by both parties
	rootSecret := randomBytes(32)
	sessionID := string(randomBytes(20))

	// Alice creates a ratchet from the root secret
	alice, err := NewFromSecret(rootSecret)
	a.NoError(err, "Alice init")

	// Bob creates a ratchet from the same root secret
	bob, err := NewFromSecret(rootSecret)
	a.NoError(err, "Bob init")

	// Exchange public keys
	alicePub := alice.OurPublic()
	bobPub := bob.OurPublic()

	// Each side sets the other's public key
	err = alice.SetTheirPublic(bobPub, sessionID)
	a.NoError(err, "Alice set peer")
	err = bob.SetTheirPublic(alicePub, sessionID)
	a.NoError(err, "Bob set peer")

	// Alice encrypts a message
	plaintext := []byte("Hello, Bob! This is Alice.")
	ciphertext, err := alice.Encrypt(plaintext)
	a.NoError(err, "Alice encrypt")

	// Bob decrypts the message
	decrypted, err := bob.Decrypt(ciphertext)
	a.NoError(err, "Bob decrypt")

	a.Equal(plaintext, decrypted, "decrypted text mismatch")

	// Counters should reflect one message sent/received
	a.Equal(uint64(1), alice.Send(), "Alice send counter")
	a.Equal(uint64(1), bob.Received(), "Bob recv counter")
}

func TestInitiateRatchet(t *testing.T) {
	a := assert.New(t)
	rootSecret := randomBytes(32)
	sessionID := string(randomBytes(20))

	// Initiator (Alice)
	alice, err := NewFromSecret(rootSecret)
	a.NoError(err, "Alice init")

	// Responder (Bob) with fresh root
	bob, err := NewFromSecret(rootSecret)
	a.NoError(err, "Bob init")

	// Alice and Bob exchange initial public keys
	alicePub := alice.OurPublic()
	bobPub := bob.OurPublic()

	err = alice.SetTheirPublic(bobPub, sessionID)
	a.NoError(err, "Alice set peer")
	err = bob.SetTheirPublic(alicePub, sessionID)
	a.NoError(err, "Bob set peer")

	// Alice initiates a new ratchet step
	newAlicePub, err := alice.InitiateRatchet(sessionID)
	a.NoError(err, "Alice initiate ratchet")

	// Bob receives Alice's new public key and sets it
	err = bob.SetTheirPublic(newAlicePub, sessionID)
	a.NoError(err, "Bob set new peer")

	// Now Alice and Bob should be able to communicate
	msg := []byte("Message after ratchet step.")
	ct, err := alice.Encrypt(msg)
	a.NoError(err, "Alice encrypt after ratchet")

	pt, err := bob.Decrypt(ct)
	a.NoError(err, "Bob decrypt after ratchet")

	a.Equal(msg, pt, "message mismatch after ratchet")

	a.Equal(uint64(1), alice.Send(), "Alice send counter after ratchet")
	a.Equal(uint64(1), bob.Received(), "Bob recv counter after ratchet")
}

// Helper to compare two ECDH public keys for equality
func equalPublicKeys(a, b []byte) bool {
	return bytes.Equal(a, b)
}

// Test that the DH key exchange between two parties produces matching shared secrets
func TestDHExchange(t *testing.T) {
	a := assert.New(t)
	// Generate key pairs for Alice and Bob
	aliceKey, err := exchange.NewECDH()
	a.NoError(err, "alice key gen")
	bobKey, err := exchange.NewECDH()
	a.NoError(err, "bob key gen")

	alicePub := aliceKey.MarshalPublicKey()
	bobPub := bobKey.MarshalPublicKey()

	// Each party computes shared secret
	aliceShared, err := aliceKey.Exchange(bobPub)
	a.NoError(err, "alice exchange")
	bobShared, err := bobKey.Exchange(alicePub)
	a.NoError(err, "bob exchange")

	a.Equal(aliceShared, bobShared, "shared secrets differ")
}

// Test that the kdfChain produces deterministic next chain key and message key
func TestKDFChainDeterministic(t *testing.T) {
	a := assert.New(t)
	ck := randomBytes(32)
	next1, msg1, err := kdfChain(ck)
	a.NoError(err, "kdfChain first")
	next2, msg2, err := kdfChain(ck)
	a.NoError(err, "kdfChain second")
	a.Equal(next1, next2, "kdfChain nextCK deterministic")
	a.Equal(msg1, msg2, "kdfChain msgKey deterministic")
}

// Test that kdfRoot produces different root and chain keys for initiator vs responder
func TestKDFRootRoles(t *testing.T) {
	a := assert.New(t)
	root := randomBytes(32)
	sessionID := randomBytes(20)
	dh := randomBytes(32)

	rk1, ckA1, ckB1, err := kdfRoot(root, dh, sessionID, true)
	a.NoError(err, "kdfRoot initiator")
	rk2, ckA2, ckB2, err := kdfRoot(root, dh, sessionID, false)
	a.NoError(err, "kdfRoot responder")

	a.Equal(rk1, rk2, "root keys equal")
	a.NotEqual(ckA1, ckA2, "chain keys swapped")
	a.NotEqual(ckB1, ckB2, "chain keys swapped")
}

// Test that attempting to encrypt without initializing the send chain fails
func TestEncryptWithoutChain(t *testing.T) {
	a := assert.New(t)
	r, err := NewFromSecret(randomBytes(32))
	a.NoError(err, "init ratchet")
	_, err = r.Encrypt([]byte("test"))
	a.Error(err, "expected error when encrypting without chain")
}

// Test that attempting to decrypt without initializing the recv chain fails
func TestDecryptWithoutChain(t *testing.T) {
	a := assert.New(t)
	r, err := NewFromSecret(randomBytes(32))
	a.NoError(err, "init ratchet")
	_, err = r.Decrypt([]byte{0x00})
	a.Error(err, "expected error when decrypting without chain")
}
