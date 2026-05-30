package services

import (
	"crypto/rand"
	"testing"

	"github.com/kamune-org/kamune/pkg/attest"
	"github.com/stretchr/testify/assert"

	"github.com/kamune-org/kamune/cmd/relay/internal/model"
)

func TestQueueKey(t *testing.T) {
	a := assert.New(t)
	s, err := attest.New()
	a.NoError(err)
	r, err := attest.New()
	a.NoError(err)
	sessionID := rand.Text()

	key1, err := queueKey(model.PublicKey(s.EncodePublicKey()), model.PublicKey(r.EncodePublicKey()), sessionID)
	a.NoError(err)
	key2, err := queueKey(model.PublicKey(s.EncodePublicKey()), model.PublicKey(r.EncodePublicKey()), sessionID)
	a.NoError(err)
	a.Equal(key1, key2)

	key3, err := queueKey(model.PublicKey(r.EncodePublicKey()), model.PublicKey(s.EncodePublicKey()), sessionID)
	a.NoError(err)
	a.NotEqual(key1, key3)
}
