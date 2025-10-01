package kamune

import (
	"net"
)

var _ net.Conn = &Conn{}
