package msgx

import "syscall"

// Available is always false on iOS, so App Store builds never look up private symbols.
func Available() bool { return false }

// Send always returns ENOSYS on iOS.
func Send(uintptr, []Hdr, int) (int, syscall.Errno) { return 0, syscall.ENOSYS }

// Recv always returns ENOSYS on iOS.
func Recv(uintptr, []Hdr, int) (int, syscall.Errno) { return 0, syscall.ENOSYS }
