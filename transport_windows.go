package kamune

import "syscall"

func init() {
	// Winsock reports a reset or aborted connection with its own error
	// codes, which do not match syscall.ECONNRESET or syscall.ECONNABORTED.
	connDropErrors = append(
		connDropErrors, syscall.WSAECONNRESET, syscall.WSAECONNABORTED,
	)
}
