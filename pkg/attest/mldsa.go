package attest

import (
	"crypto/rand"
	"fmt"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

type mlDSA struct {
	publicKey  *mldsa65.PublicKey
	privateKey *mldsa65.PrivateKey
}

func newMLDSA() (*mlDSA, error) {
	public, private, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	return &mlDSA{publicKey: public, privateKey: private}, nil
}

func (m *mlDSA) PublicKey() PublicKey {
	return &mldsaPublicKey{m.publicKey}
}

func (m *mlDSA) Sign(msg []byte) ([]byte, error) {
	sig := make([]byte, mldsa65.SignatureSize)
	err := mldsa65.SignTo(m.privateKey, msg, nil, true, sig)
	return sig, err
}

func (m *mlDSA) Save() ([]byte, error) {
	return m.privateKey.MarshalBinary()
}

type mldsaPublicKey struct {
	key *mldsa65.PublicKey
}

func (m *mldsaPublicKey) Marshal() []byte {
	b, err := m.key.MarshalBinary()
	if err != nil {
		panic(fmt.Errorf("marshalling mlDSA public key: %v", err))
	}
	return b
}

func (m *mldsaPublicKey) Equal(key PublicKey) bool {
	return m.key.Equal(key)
}

func loadMLDSA(data []byte) (*mlDSA, error) {
	key, err := mldsa65.Scheme().UnmarshalBinaryPrivateKey(data)
	if err != nil {
		return nil, fmt.Errorf("unmarshal private key: %w", err)
	}
	private, ok := key.(*mldsa65.PrivateKey)
	if !ok {
		return nil, ErrInvalidKey
	}
	return &mlDSA{
		privateKey: private,
		publicKey:  private.Public().(*mldsa65.PublicKey),
	}, nil
}
