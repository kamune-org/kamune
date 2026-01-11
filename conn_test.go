package kamune

import (
	"net"
)

var (
	_ net.Conn = new(conn)
	_ Conn     = new(conn)
)
