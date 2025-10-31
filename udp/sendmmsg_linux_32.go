//go:build linux && (386 || amd64p32 || arm || mips || mipsle) && !android && !e2e_testing

package udp

import (
	"unsafe"

	"golang.org/x/sys/unix"
)

type linuxMmsgHdr struct {
	Hdr unix.Msghdr
	Len uint32
}

func sendmmsg(fd int, hdrs []linuxMmsgHdr, flags int) (int, error) {
	if len(hdrs) == 0 {
		return 0, nil
	}
	n, _, errno := unix.Syscall6(unix.SYS_SENDMMSG, uintptr(fd), uintptr(unsafe.Pointer(&hdrs[0])), uintptr(len(hdrs)), uintptr(flags), 0, 0)
	if errno != 0 {
		return int(n), errno
	}
	return int(n), nil
}
