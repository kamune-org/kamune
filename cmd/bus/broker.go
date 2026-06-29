package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
	"sync"

	relaybroker "github.com/kamune-org/kamune/pkg/relayconn/broker"
)

// BrokerClient wraps the kamune broker client with a stable X25519 identity
// that survives across broker-address changes. The X25519 key is created
// eagerly (in NewBrokerClient) so the broker sees the same identity for every
// registration, which is required for its self-match rule. The underlying
// relaybroker.Client is created lazily on first use, since the broker address
// is only known once the user configures a server.
type BrokerClient struct {
	key *ecdh.PrivateKey
	pub []byte

	mu         sync.Mutex
	client     *relaybroker.Client
	brokerAddr string
}

// NewBrokerClient returns a BrokerClient with a freshly-generated X25519
// identity but no underlying network client. The network client is created
// on first call to Client.
func NewBrokerClient() (*BrokerClient, error) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate x25519 key: %w", err)
	}
	return &BrokerClient{key: k, pub: k.PublicKey().Bytes()}, nil
}

// PublicKey returns the 32-byte X25519 public key.
func (b *BrokerClient) PublicKey() []byte {
	out := make([]byte, len(b.pub))
	copy(out, b.pub)
	return out
}

// Client returns the underlying broker client, creating it on first call
// (or when the broker address changes). The client is bound to the stable
// X25519 key so re-registrations keep the same identity.
func (b *BrokerClient) Client(brokerAddr string) (*relaybroker.Client, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.client != nil && b.brokerAddr == brokerAddr {
		return b.client, nil
	}
	c, err := relaybroker.NewClientWithKey(brokerAddr, b.key)
	if err != nil {
		return nil, err
	}
	b.client = c
	b.brokerAddr = brokerAddr
	return c, nil
}
