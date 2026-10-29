//go:build illumos || solaris

package localapi

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// applyAccess sets the group and the mode of the socket at path, like the BSD side: the
// node is checked to be a socket owned by the daemon, then changed with fchownat under
// AT_SYMLINK_NOFOLLOW. fchmodat with AT_SYMLINK_NOFOLLOW is not supported everywhere on
// illumos, so if the kernel refuses that flag the mode is set without it; the node was
// just checked to be a socket, not a symlink, which leaves the same check-then-change
// window the BSD side documents.
func applyAccess(path string, acc Access) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if err := checkOwnSocket(path, fi); err != nil {
		return err
	}

	gid, err := gidFor(acc)
	if err != nil {
		return err
	}
	if err := unix.Fchownat(unix.AT_FDCWD, path, -1, gid, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return &os.PathError{Op: "chown", Path: path, Err: err}
	}

	mode := uint32(acc.mode.Perm())
	err = unix.Fchmodat(unix.AT_FDCWD, path, mode, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.EINVAL) || errors.Is(err, unix.EOPNOTSUPP) {
		err = unix.Fchmodat(unix.AT_FDCWD, path, mode, 0)
	}
	if err != nil {
		return &os.PathError{Op: "chmod", Path: path, Err: err}
	}
	return nil
}
