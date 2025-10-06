package attest

import (
	"crypto/rand"
	"fmt"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

type MLDSA struct {
	publicKey  *mldsa65.PublicKey
	privateKey *mldsa65.PrivateKey
}

func (m MLDSA) PublicKey() PublicKey {
	return &MLDSAPublicKey{m.publicKey}
}

func (m MLDSA) Sign(msg []byte) ([]byte, error) {
	sig := make([]byte, mldsa65.SignatureSize)
	err := mldsa65.SignTo(m.privateKey, msg, nil, true, sig)
	return sig, err
}

func (m MLDSA) Save() ([]byte, error) {
	return m.privateKey.MarshalBinary()
}

func (MLDSA) Verify(remote PublicKey, msg, sig []byte) bool {
	p, ok := remote.(*MLDSAPublicKey)
	if !ok {
		return false
	}
	return mldsa65.Verify(p.key, msg, nil, sig)
}

func (MLDSA) ParsePublicKey(key []byte) (PublicKey, error) {
	mlPub, err := mldsa65.Scheme().UnmarshalBinaryPublicKey(key)
	if err != nil {
		return nil, err
	}
	return &MLDSAPublicKey{mlPub.(*mldsa65.PublicKey)}, nil
}

func (MLDSA) String() string {
	return "mldsa"
}

type MLDSAPublicKey struct {
	key *mldsa65.PublicKey
}

func (m MLDSAPublicKey) Marshal() []byte {
	b, err := m.key.MarshalBinary()
	if err != nil {
		panic(fmt.Errorf("marshalling mlDSA public key: %v", err))
	}
	return b
}

func (m MLDSAPublicKey) Equal(key PublicKey) bool {
	return m.key.Equal(key)
}

func newMLDSA() (*MLDSA, error) {
	public, private, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	return &MLDSA{publicKey: public, privateKey: private}, nil
}

func loadMLDSA(data []byte) (*MLDSA, error) {
	key, err := mldsa65.Scheme().UnmarshalBinaryPrivateKey(data)
	if err != nil {
		return nil, fmt.Errorf("unmarshal private key: %w", err)
	}
	private, ok := key.(*mldsa65.PrivateKey)
	if !ok {
		return nil, ErrInvalidKey
	}
	return &MLDSA{
		privateKey: private,
		publicKey:  private.Public().(*mldsa65.PublicKey),
	}, nil
}
