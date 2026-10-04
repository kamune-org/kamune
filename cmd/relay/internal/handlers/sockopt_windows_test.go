package handlers

import "syscall"

func getsockoptInt(fd uintptr, level, opt int) (int, error) {
	return syscall.GetsockoptInt(syscall.Handle(fd), level, opt)
}
