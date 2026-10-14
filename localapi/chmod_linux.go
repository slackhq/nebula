//go:build linux

package localapi

import (
	"fmt"
	"os"
	"strconv"

	"golang.org/x/sys/unix"
)

// applyAccess sets the owning group and the mode of the socket node at path, and of
// nothing else. The node is opened O_PATH, which takes a reference to the inode without
// opening the socket itself (a socket cannot be opened, and O_PATH does not try), and
// O_NOFOLLOW, so a symlink at path is a refusal rather than a target. What the
// descriptor holds is checked to be a socket of ours, and the chown and the chmod are
// then made through /proc/self/fd, which names that inode whatever is at path by then:
// a node swapped between the look and the change, for a link or for a hard link to a
// file of somebody's choosing, is not what gets the group or the mode. This is how
// glibc implements fchmodat(AT_SYMLINK_NOFOLLOW) too.
//
// Without /proc the change falls back to fchownat and fchmodat2, which do not follow a
// link but are by path again, so a swap in the one syscall between the check and each
// would be changed. Older than kernel 6.6 with no /proc, the mode is not set and the
// socket is not served.
func applyAccess(path string, acc Access) error {
	// The look is for the message: a link or a plain file is named as what it is, which
	// the O_PATH open's ELOOP or the fstat below would say less well.
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if err := checkOwnSocket(path, fi); err != nil {
		return err
	}

	fd, err := unix.Open(path, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return &os.PathError{Op: "open", Path: path, Err: err}
	}
	defer unix.Close(fd)

	// What the descriptor holds is what the changes land on; the Lstat above looked at
	// the path, which may have changed since.
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return &os.PathError{Op: "fstat", Path: path, Err: err}
	}
	if st.Mode&unix.S_IFMT != unix.S_IFSOCK || st.Uid != currentUID() {
		return fmt.Errorf("%s was replaced while its access was being set, refusing to change it", path)
	}

	// The /proc name of the inode the descriptor holds. ENOENT from it means no /proc.
	held := "/proc/self/fd/" + strconv.Itoa(fd)

	// The group first: a chown by root clears the setgid bit, which a socket never has,
	// but the mode is pinned afterwards either way. With no group configured the socket
	// is handed back to the daemon's own, so taking the key out of the config on a reload
	// takes the access away as surely as a restart would.
	gid, err := gidFor(acc)
	if err != nil {
		return err
	}
	err = unix.Chown(held, -1, gid)
	if err == unix.ENOENT {
		err = unix.Fchownat(unix.AT_FDCWD, path, -1, gid, unix.AT_SYMLINK_NOFOLLOW)
	}
	if err != nil {
		return &os.PathError{Op: "chown", Path: path, Err: err}
	}

	perm := uint32(acc.Mode.Perm())
	err = unix.Chmod(held, perm)
	if err == unix.ENOENT {
		err = unix.Fchmodat(unix.AT_FDCWD, path, perm, unix.AT_SYMLINK_NOFOLLOW)
	}
	if err != nil {
		return &os.PathError{Op: "chmod", Path: path, Err: err}
	}

	return nil
}
