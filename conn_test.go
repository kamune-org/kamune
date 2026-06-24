package kamune

import (
	"bytes"
	"errors"
	"math"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

var (
	_ net.Conn = new(conn)
	_ Conn     = new(conn)
)

func TestConn_WriteBytes_RejectsOverflow(t *testing.T) {
	a := require.New(t)
	c1, c2 := net.Pipe()
	defer func() { _ = c1.Close() }()
	defer func() { _ = c2.Close() }()
	conn := newConn(c1)

	// math.MaxUint16 is the framing's hard upper bound; payloads that would
	// overflow the uint16 length prefix must be rejected before any bytes are
	// written to the underlying conn.
	oversize := bytes.Repeat([]byte{0xAB}, math.MaxUint16+1)
	err := conn.WriteBytes(oversize)
	a.Error(err)
	a.True(errors.Is(err, ErrMessageTooLarge))
}
