package services

import (
	"crypto/rand"
	"testing"

	"github.com/kamune-org/kamune/pkg/attest"
	"github.com/stretchr/testify/assert"
)

func TestQueueKey(t *testing.T) {
	a := assert.New(t)
	s, err := attest.NewAttester(attest.Ed25519Algorithm)
	a.NoError(err)
	r, err := attest.NewAttester(attest.Ed25519Algorithm)
	a.NoError(err)
	sessionID := rand.Text()

	key1, err := queueKey(s.PublicKey(), r.PublicKey(), sessionID)
	a.NoError(err)
	key2, err := queueKey(s.PublicKey(), r.PublicKey(), sessionID)
	a.NoError(err)
	a.Equal(key1, key2)

	key3, err := queueKey(r.PublicKey(), s.PublicKey(), sessionID)
	a.NoError(err)
	a.NotEqual(key1, key3)
}
