package exchange

import (
	"crypto/mlkem"
)

// MLKEM wraps an ML-KEM-768 key pair for post-quantum key encapsulation.
// The encapsulation key is exported; the decapsulation key is kept internal.
type MLKEM struct {
	PublicKey  *mlkem.EncapsulationKey768
	privateKey *mlkem.DecapsulationKey768
}

func (m *MLKEM) MarshalPublicKey() []byte {
	return m.PublicKey.Bytes()
}

func (m *MLKEM) Decapsulate(ct []byte) ([]byte, error) {
	return m.privateKey.Decapsulate(ct)
}

// NewMLKEM generates a new ML-KEM-768 key pair.
func NewMLKEM() (*MLKEM, error) {
	private, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, err
	}

	return &MLKEM{
		privateKey: private,
		PublicKey:  private.EncapsulationKey(),
	}, nil
}

// EncapsulateMLKEM creates a shared secret and ciphertext from a remote
// ML-KEM-768 encapsulation key. The ciphertext is sent to the remote party
// who decapsulates it to obtain the same shared secret.
func EncapsulateMLKEM(remote []byte) (ss, ct []byte, err error) {
	public, err := mlkem.NewEncapsulationKey768(remote)
	if err != nil {
		return nil, nil, err
	}
	secret, cipher := public.Encapsulate()

	return secret, cipher, nil
}
