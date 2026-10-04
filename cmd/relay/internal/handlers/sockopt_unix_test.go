//go:build unix

package handlers

import "syscall"

func getsockoptInt(fd uintptr, level, opt int) (int, error) {
	return syscall.GetsockoptInt(int(fd), level, opt)
}
