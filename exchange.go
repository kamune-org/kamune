package kamune

import (
	"crypto/hpke"
	"fmt"
)

// HPKE ciphersuite components used for key establishment.
// MLKEM768-X25519 provides hybrid post-quantum + classical security.
// HKDF-SHA512 is the KDF and ChaCha20Poly1305 is the AEAD (used only
// within the HPKE key schedule; actual transport encryption uses the
// exported keys with XChaCha20-Poly1305 via enigma).
var (
	hpkeKEM  = hpke.MLKEM768X25519
	hpkeKDF  = hpke.HKDFSHA512
	hpkeAEAD = hpke.ChaCha20Poly1305
)

func initiateExchange(c Conn) (*encryptedConn, error) {
	kem := hpkeKEM()
	kdf := hpkeKDF()
	aead := hpkeAEAD()

	privateKey, err := kem.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("generating kem key: %w", err)
	}
	if err := c.WriteBytes(privateKey.PublicKey().Bytes()); err != nil {
		return nil, fmt.Errorf("writing hpke public key: %w", err)
	}
	remoteEnc, err := c.ReadBytes()
	if err != nil {
		return nil, fmt.Errorf("reading remote ciphertext: %w", err)
	}
	recipient, err := hpke.NewRecipient(remoteEnc, privateKey, kdf, aead, nil)
	if err != nil {
		return nil, fmt.Errorf("creating recipient: %w", err)
	}

	remotePublicBytes, err := c.ReadBytes()
	if err != nil {
		return nil, fmt.Errorf("reading remote public key: %w", err)
	}
	remotePublic, err := kem.NewPublicKey(remotePublicBytes)
	if err != nil {
		return nil, fmt.Errorf("parsing remote public key: %w", err)
	}
	enc, sender, err := hpke.NewSender(remotePublic, kdf, aead, nil)
	if err != nil {
		return nil, fmt.Errorf("creating sender: %w", err)
	}
	if err := c.WriteBytes(enc); err != nil {
		return nil, fmt.Errorf("writing ciphertext: %w", err)
	}

	return newEncryptedConn(c, sender, recipient), nil
}

func acceptExchange(c Conn) (*encryptedConn, error) {
	kem := hpkeKEM()
	kdf := hpkeKDF()
	aead := hpkeAEAD()

	remotePubBytes, err := c.ReadBytes()
	if err != nil {
		return nil, fmt.Errorf("reading remote public key: %w", err)
	}
	remotePub, err := kem.NewPublicKey(remotePubBytes)
	if err != nil {
		return nil, fmt.Errorf("parsing remote public key: %w", err)
	}
	enc, sender, err := hpke.NewSender(remotePub, kdf, aead, nil)
	if err != nil {
		return nil, fmt.Errorf("creating sender: %w", err)
	}
	if err := c.WriteBytes(enc); err != nil {
		return nil, fmt.Errorf("writing ciphertext: %w", err)
	}

	privateKey, err := kem.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("generating kem key: %w", err)
	}
	if err := c.WriteBytes(privateKey.PublicKey().Bytes()); err != nil {
		return nil, fmt.Errorf("writing hpke public key: %w", err)
	}
	remoteEnc, err := c.ReadBytes()
	if err != nil {
		return nil, fmt.Errorf("reading remote ciphertext: %w", err)
	}
	recipient, err := hpke.NewRecipient(remoteEnc, privateKey, kdf, aead, nil)
	if err != nil {
		return nil, fmt.Errorf("creating recipient: %w", err)
	}

	return newEncryptedConn(c, sender, recipient), nil
}
