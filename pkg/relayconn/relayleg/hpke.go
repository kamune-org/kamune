package relayleg

import (
	"crypto/ecdh"
	"crypto/hpke"
)

// sealStatic encapsulates to the relay static key.
// enc is 32 bytes. ss is the 32-byte exporter output ss_s.
func sealStatic(pk PublicKey) ([]byte, []byte, error) {
	pub, err := hpke.DHKEM(ecdh.X25519()).NewPublicKey(pk[:])
	if err != nil {
		return nil, nil, err
	}
	enc, sender, err := hpke.NewSender(
		pub, hpke.HKDFSHA512(), hpke.ExportOnly(),
		[]byte(infoStatic),
	)
	if err != nil {
		return nil, nil, err
	}
	ss, err := sender.Export(exportContext, ssLen)
	if err != nil {
		return nil, nil, err
	}
	return enc, ss, nil
}

// openStatic decapsulates enc with the relay static key and
// exports ss_s.
func openStatic(k *PrivateKey, enc []byte) ([]byte, error) {
	r, err := hpke.NewRecipient(
		enc, k.hpke, hpke.HKDFSHA512(), hpke.ExportOnly(),
		[]byte(infoStatic),
	)
	if err != nil {
		return nil, err
	}
	return r.Export(exportContext, ssLen)
}

// newEphemeral generates the client's X-Wing key pair.
// The public key is eph_pk_c.
func newEphemeral() (hpke.PrivateKey, []byte, error) {
	sk, err := hpke.MLKEM768X25519().GenerateKey()
	if err != nil {
		return nil, nil, err
	}
	return sk, sk.PublicKey().Bytes(), nil
}

// sealEphemeral encapsulates to eph_pk_c.
// enc is enc_e. ss is the 32-byte exporter output ss_e.
func sealEphemeral(ephPK []byte) ([]byte, []byte, error) {
	pub, err := hpke.MLKEM768X25519().NewPublicKey(ephPK)
	if err != nil {
		return nil, nil, err
	}
	enc, sender, err := hpke.NewSender(
		pub, hpke.HKDFSHA512(), hpke.ExportOnly(),
		[]byte(infoEphemeral),
	)
	if err != nil {
		return nil, nil, err
	}
	ss, err := sender.Export(exportContext, ssLen)
	if err != nil {
		return nil, nil, err
	}
	return enc, ss, nil
}

// openEphemeral decapsulates enc_e with the client's ephemeral
// private key and exports ss_e.
func openEphemeral(sk hpke.PrivateKey, enc []byte) ([]byte, error) {
	r, err := hpke.NewRecipient(
		enc, sk, hpke.HKDFSHA512(), hpke.ExportOnly(),
		[]byte(infoEphemeral),
	)
	if err != nil {
		return nil, err
	}
	return r.Export(exportContext, ssLen)
}
