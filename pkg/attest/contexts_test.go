package attest

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestContexts_PrefixFree(t *testing.T) {
	a := require.New(t)
	got := Contexts()
	a.Len(got, 3)
	a.Equal(ContextResponderHandshake, got[0])
	a.Equal(ContextInitiatorHandshake, got[1])
	a.Equal(ContextTransportFrame, got[2])
	for i, left := range got {
		for j, right := range got {
			if i == j {
				continue
			}
			a.False(strings.HasPrefix(left, right))
			a.False(strings.HasPrefix(right, left))
		}
	}
}
