//go:build darwin || freebsd || netbsd || openbsd

package localapi

import (
	"os"

	"golang.org/x/sys/unix"
)

// applyAccess sets the group and the mode of the socket at path. It checks that the node
// there is a socket owned by the daemon, then changes it with fchownat and fchmodat under
// AT_SYMLINK_NOFOLLOW, so a symlink placed at path is changed itself rather than followed.
// There is no O_PATH on these kernels to pin the inode between the check and the changes,
// as the linux side does, so a hard link to another file swapped in at path during that
// window would be the node changed.
func applyAccess(path string, acc Access) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if err := checkOwnSocket(path, fi); err != nil {
		return err
	}

	// With no group configured the socket is handed back to the daemon's own group, so a
	// reload that drops the key takes the access away; see the linux side.
	gid, err := gidFor(acc)
	if err != nil {
		return err
	}
	if err := unix.Fchownat(unix.AT_FDCWD, path, -1, gid, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return &os.PathError{Op: "chown", Path: path, Err: err}
	}

	if err := unix.Fchmodat(unix.AT_FDCWD, path, uint32(acc.mode.Perm()), unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return &os.PathError{Op: "chmod", Path: path, Err: err}
	}

	return nil
}
