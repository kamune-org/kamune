package attest

import (
	"crypto/rand"
	"encoding/base64"
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

func (m *mlDSA) Save(path string) error {
	private, err := m.privateKey.MarshalBinary()
	if err != nil {
		return fmt.Errorf("marshalling private key: %w", err)
	}
	public, err := m.publicKey.MarshalBinary()
	if err != nil {
		return fmt.Errorf("marshalling public key: %w", err)
	}
	return save(private, public, path)
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

func (m *mldsaPublicKey) Base64Encoding() string {
	return base64.RawStdEncoding.EncodeToString(m.Marshal())
}

func (m *mldsaPublicKey) Equal(key PublicKey) bool {
	return m.key.Equal(key)
}

func loadMLDSA(path string) (*mlDSA, error) {
	data, err := loadFromDisk(path)
	if err != nil {
		return nil, fmt.Errorf("load from disk: %w", err)
	}
	mlPrivate, err := mldsa65.Scheme().UnmarshalBinaryPrivateKey(data)
	if err != nil {
		return nil, fmt.Errorf("unmarshal private key: %w", err)
	}
	return &mlDSA{
		privateKey: mlPrivate.(*mldsa65.PrivateKey),
		publicKey:  mlPrivate.Public().(*mldsa65.PublicKey),
	}, nil
}
