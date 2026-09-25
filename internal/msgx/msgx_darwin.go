//go:build !ios

package msgx

import (
	"sync"
	"syscall"
	"unsafe"
)

// dlsym is public libSystem API, imported the way x/sys/unix imports its libSystem stubs. The local name is
// distinct from runtime/race's dlsym import.
//
//go:cgo_import_dynamic msgx_dlsym dlsym "/usr/lib/libSystem.B.dylib"

// dlsymTrampolineAddr is the address of msgx_darwin.s's jump to dlsym.
var dlsymTrampolineAddr uintptr

// syscall6X calls the C function at fn on the system stack and returns errno when it returns a 64-bit -1.
// It is how x/sys/unix calls libSystem, and the runtime keeps it linkable for that.
//
//go:linkname syscall6X syscall.syscall6X
func syscall6X(fn, a1, a2, a3, a4, a5, a6 uintptr) (r1, r2 uintptr, err syscall.Errno)

// rtldDefault is dlfcn.h's RTLD_DEFAULT, ((void *)-2): search every image loaded in the process.
const rtldDefault = ^uintptr(1)

var (
	sendmsgXName = []byte("sendmsg_x\x00")
	recvmsgXName = []byte("recvmsg_x\x00")
)

type funcs struct {
	sendmsgX uintptr
	recvmsgX uintptr
}

var resolve = sync.OnceValue(func() funcs {
	return funcs{sendmsgX: lookup(sendmsgXName), recvmsgX: lookup(recvmsgXName)}
})

// lookup returns the address of the NUL-terminated C symbol name, or 0 when no loaded image exports it.
func lookup(name []byte) uintptr {
	p, _, _ := syscall6X(dlsymTrampolineAddr, rtldDefault, uintptr(unsafe.Pointer(&name[0])), 0, 0, 0, 0)
	return p
}

// Available reports whether libSystem exports both sendmsg_x and recvmsg_x. When it is false, Send and Recv
// return ENOSYS.
func Available() bool {
	f := resolve()
	return f.sendmsgX != 0 && f.recvmsgX != 0
}

// Send passes hdrs to sendmsg_x on fd and returns how many messages the kernel took.
func Send(fd uintptr, hdrs []Hdr, flags int) (int, syscall.Errno) {
	return call(resolve().sendmsgX, fd, hdrs, flags)
}

// Recv passes hdrs to recvmsg_x on fd and returns how many messages it filled.
func Recv(fd uintptr, hdrs []Hdr, flags int) (int, syscall.Errno) {
	return call(resolve().recvmsgX, fd, hdrs, flags)
}

func call(fn, fd uintptr, hdrs []Hdr, flags int) (int, syscall.Errno) {
	if fn == 0 {
		return 0, syscall.ENOSYS
	}
	if len(hdrs) == 0 {
		return 0, syscall.EINVAL
	}
	r, _, errno := syscall6X(fn, fd, uintptr(unsafe.Pointer(&hdrs[0])), uintptr(len(hdrs)), uintptr(flags), 0, 0)
	if errno != 0 {
		return 0, errno
	}
	return int(r), 0
}
