package broker

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBrokerOpenNotify_TamperedCiphertext(t *testing.T) {
	a := require.New(t)

	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	brokerEphPub := make([]byte, 32)
	for i := range brokerEphPub {
		brokerEphPub[i] = byte(i + 32)
	}

	plaintext := TokenAssignedPlaintext(make([]byte, 16), 60)
	nonce, sealed := SealNotify(key, brokerEphPub, plaintext)

	sealed[len(sealed)-1] ^= 0xFF

	_, err := OpenNotify(key, brokerEphPub, nonce, sealed)
	a.Error(err, "tampered ciphertext must be rejected")
}
