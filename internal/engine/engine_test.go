package engine

import (
	"testing"

	"github.com/stretchr/testify/require"
)

var _ Namespace = nilNamespace{}

func TestNilNamespace(t *testing.T) {
	a := require.New(t)

	var ns Namespace = nilNamespace{}

	sub := ns.Sub([]byte("x"))
	a.IsType(nilNamespace{}, sub)

	_, err := ns.GetEncrypted([]byte("k"))
	a.ErrorIs(err, ErrMissingNamespace)
	a.ErrorIs(ns.PutEncrypted([]byte("k"), []byte("v")), ErrMissingNamespace)
	a.ErrorIs(ns.Delete([]byte("k")), ErrMissingNamespace)
	a.ErrorIs(ns.DeleteNamespace([]byte("x")), ErrMissingNamespace)
	a.Nil(ns.FirstKey())
	a.Nil(ns.LastKey())
	a.Equal(0, ns.KeyCount())
	a.Nil(ns.ListSubNamespaces())

	count := 0
	for range ns.IterateEncrypted() {
		count++
	}
	a.Equal(0, count)
}
