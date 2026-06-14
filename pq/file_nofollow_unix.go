//go:build unix

package pq

import (
	"os"
	"syscall"
)

// openPSKFileNoFollow opens path with O_NOFOLLOW so the kernel
// refuses the open with ELOOP if path is a symlink. This is the
// race-free way to defeat a symlink-substitution attack between
// readdir/Lstat and the subsequent file read.
func openPSKFileNoFollow(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
}
