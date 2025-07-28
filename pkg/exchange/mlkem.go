package exchange

import (
	"crypto/mlkem"
)

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

func NewMLKEM() (*MLKEM, error) {
	private, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, err
	}

	return &MLKEM{privateKey: private, PublicKey: private.EncapsulationKey()}, nil
}

func EncapsulateMLKEM(remote []byte) (ss, ct []byte, err error) {
	public, err := mlkem.NewEncapsulationKey768(remote)
	if err != nil {
		return nil, nil, err
	}
	secret, cipher := public.Encapsulate()

	return secret, cipher, nil
}
