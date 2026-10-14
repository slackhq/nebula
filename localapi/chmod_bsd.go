//go:build darwin || freebsd || netbsd || openbsd

package localapi

import (
	"os"

	"golang.org/x/sys/unix"
)

// applyAccess sets the owning group and the mode of the socket node at path, and of
// nothing a link at path names. The node is looked at without following links and must
// be a socket of ours; the chown and the chmod are fchownat and fchmodat with
// AT_SYMLINK_NOFOLLOW, which these kernels honour, so a symlink put at path in the one
// syscall between the look and either call gets its own group or mode changed, which
// means nothing, and not its target's. A socket cannot be opened, and there is no O_PATH
// here to hold the inode across the calls the way the linux side does, so a hard link
// to a file of somebody's choosing swapped in during that one syscall would be changed;
// that needs the file on the socket's filesystem and the right to link to it, which
// darwin and the BSDs grant to any user by default.
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

	if err := unix.Fchmodat(unix.AT_FDCWD, path, uint32(acc.Mode.Perm()), unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return &os.PathError{Op: "chmod", Path: path, Err: err}
	}

	return nil
}
