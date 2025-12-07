package ratchet

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"

	"github.com/kamune-org/kamune/internal/enigma"
	"github.com/kamune-org/kamune/pkg/exchange"
)

// This is a compact Double Ratchet implementation. It intentionally omits
// skipped-message caches and persistent storage.

const (
	// sizes and HKDF labels
	keySize = 32

	infoRoot  = "DR:root"
	infoChain = "DR:chain"
	infoMsg   = "DR:msg"
)

// Ratchet represents the local state.
type Ratchet struct {
	rootKey []byte // RK
	sendCK  []byte // send chain key
	recvCK  []byte // recv chain key

	// DH keys
	ourDH    *exchange.ECDH
	theirPub []byte

	// counters
	sendCount uint64
	recvCount uint64
}

// NewFromSecret creates a Ratchet from an initial root secret and an initial
// local DH keypair.
func NewFromSecret(rootSecret []byte) (*Ratchet, error) {
	r := &Ratchet{
		rootKey: make([]byte, len(rootSecret)),
	}
	copy(r.rootKey, rootSecret)

	// generate DH keypair
	dh, err := exchange.NewECDH()
	if err != nil {
		return nil, fmt.Errorf("generating dh keypair: %w", err)
	}

	r.ourDH = dh
	return r, nil
}

// InitiateRatchet generates a fresh DH keypair, mixes it with the peer's
// stored public key to produce a new root and chain keys, updates local DH
// state to the new keypair, and returns the new public key.
func (r *Ratchet) InitiateRatchet(sessionID string) ([]byte, error) {
	if len(r.theirPub) == 0 {
		panic(fmt.Errorf("peer public key is not set"))
	}

	// create a fresh DH keypair
	newDH, err := exchange.NewECDH()
	if err != nil {
		return nil, fmt.Errorf("creating new dh: %w", err)
	}

	// compute shared = X25519(newPriv, theirPub)
	shared, err := newDH.Exchange(r.theirPub)
	if err != nil {
		return nil, fmt.Errorf("exchanging with their pub: %w", err)
	}

	// derive new root and chain keys
	// Determine initiator deterministically so this side's choice is opposite
	// of the peer's (the peer will compare their own pub to this new public).
	initiator := bytes.Compare(newDH.MarshalPublicKey(), r.theirPub) < 0
	newRoot, sendCK, recvCK, err := kdfRoot(
		r.rootKey, shared, []byte(sessionID), initiator,
	)
	if err != nil {
		return nil, fmt.Errorf("kdfRoot: %w", err)
	}

	// commit the new state: our DH becomes newDH, root & chains updated
	r.rootKey = newRoot
	r.ourDH = newDH
	r.sendCK = sendCK
	r.recvCK = recvCK
	r.sendCount = 0
	r.recvCount = 0

	return r.ourDH.MarshalPublicKey(), nil
}

// OurPublic returns the X25519 public key to send to peer.
func (r *Ratchet) OurPublic() []byte {
	return r.ourDH.MarshalPublicKey()
}

/*
SetTheirPublic installs the peer's public key and performs the initial DH
ratchet step (updates rootKey and initializes send/recv chain keys).

The initiator role is chosen deterministically here so both peers arrive at
opposite roles without an out-of-band flag. We pick the side whose public key
is lexicographically smaller as the initiator.
*/
func (r *Ratchet) SetTheirPublic(their []byte, sessionID string) error {
	// store a copy of the peer public key
	r.theirPub = make([]byte, len(their))
	copy(r.theirPub, their)

	// perform DH: shared = X25519(ourPriv, theirPub)
	shared, err := r.ourDH.Exchange(their)
	if err != nil {
		return fmt.Errorf("exchanging: %w", err)
	}

	// Determine initiator deterministically so both sides pick opposite roles:
	// the side with the lexicographically smaller public key is the initiator.
	initiator := bytes.Compare(r.ourDH.MarshalPublicKey(), their) < 0

	// KDF: RK', CKs = HKDF(RK || shared, infoRoot)
	newRoot, sendCK, recvCK, err := kdfRoot(
		r.rootKey, shared, []byte(sessionID), initiator,
	)
	if err != nil {
		return err
	}
	r.rootKey = newRoot
	r.sendCK = sendCK
	r.recvCK = recvCK
	r.sendCount = 0
	r.recvCount = 0
	return nil
}

// Encrypt derives the next message key from send chain, increments send counter,
// uses enigma.NewEnigma with the message key to encrypt plaintext, and returns
// the ciphertext along with our ephemeral public (if needed).
func (r *Ratchet) Encrypt(plaintext []byte) ([]byte, error) {
	if r.sendCK == nil {
		return nil, fmt.Errorf("send chain not initialized")
	}
	// Derive next chain key and message key
	nextCK, msgKey, err := kdfChain(r.sendCK)
	if err != nil {
		return nil, err
	}
	r.sendCK = nextCK
	r.sendCount++

	enc, err := enigma.NewEnigma(msgKey, nil, []byte(infoMsg))
	if err != nil {
		return nil, fmt.Errorf("create enigma: %w", err)
	}
	ct := enc.Encrypt(plaintext)
	return ct, nil
}

// Decrypt derives message key(s) from recv chain and attempts to decrypt the
// ciphertext. This is a simplified version that assumes messages arrive in order.
func (r *Ratchet) Decrypt(ciphertext []byte) ([]byte, error) {
	if r.recvCK == nil {
		return nil, fmt.Errorf("recv chain not initialized")
	}
	nextCK, msgKey, err := kdfChain(r.recvCK)
	if err != nil {
		return nil, err
	}
	r.recvCK = nextCK
	r.recvCount++

	enc, err := enigma.NewEnigma(msgKey, nil, []byte(infoMsg))
	if err != nil {
		return nil, fmt.Errorf("create enigma: %w", err)
	}
	pt, err := enc.Decrypt(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decrypt msg: %w", err)
	}
	return pt, nil
}

func (r *Ratchet) Send() uint64     { return r.sendCount }
func (r *Ratchet) Received() uint64 { return r.recvCount }

// kdfRoot mixes the previous root and a DH shared secret to produce a new root
// and two chain keys (used as send/recv).
func kdfRoot(
	root, dh, info []byte, initiator bool,
) (newRoot, sender, receiver []byte, err error) {
	// Use HKDF to expand root||dh into new root and two chain keys.
	seed := make([]byte, len(root)+len(dh))
	copy(seed, root)
	copy(seed[len(root):], dh)

	h := hkdf.New(sha256.New, seed, nil, info)
	newRoot = make([]byte, keySize)
	if _, err = io.ReadFull(h, newRoot); err != nil {
		return
	}
	ck1 := make([]byte, keySize)
	if _, err = io.ReadFull(h, ck1); err != nil {
		return
	}
	ck2 := make([]byte, keySize)
	if _, err = io.ReadFull(h, ck2); err != nil {
		return
	}
	if initiator {
		return newRoot, ck1, ck2, nil
	}
	return newRoot, ck2, ck1, nil
}

// kdfChain derives next chain key and a message key from a chain key.
func kdfChain(ck []byte) (nextCK, msgKey []byte, err error) {
	h := hkdf.New(sha256.New, ck, nil, []byte(infoChain))
	nextCK = make([]byte, keySize)
	if _, err = io.ReadFull(h, nextCK); err != nil {
		return
	}
	msgKey = make([]byte, keySize)
	if _, err = io.ReadFull(h, msgKey); err != nil {
		return
	}
	return
}
