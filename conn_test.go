package kamune

import (
	"net"
)

var (
	_ net.Conn = &conn{}
	_ Conn     = &conn{}
)
