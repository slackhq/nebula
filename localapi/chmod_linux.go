//go:build linux

package localapi

import (
	"fmt"
	"os"
	"strconv"

	"golang.org/x/sys/unix"
)

// applyAccess sets the group and the mode of the socket at path. It opens the node with
// O_PATH, which takes a handle on the inode without opening the socket, and O_NOFOLLOW,
// which refuses a symlink. It then checks through that handle that the node is a socket
// owned by the daemon and makes the chown and chmod on /proc/self/fd/N, so the changes
// land on the inode that was checked even if path has since been pointed at something
// else. Without /proc it falls back to fchownat and fchmodat with AT_SYMLINK_NOFOLLOW,
// which go by path and so could change a node swapped in after the check; fchmodat with
// that flag needs kernel 6.6, and on an older kernel without /proc the chmod fails.
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

	perm := uint32(acc.mode.Perm())
	err = unix.Chmod(held, perm)
	if err == unix.ENOENT {
		err = unix.Fchmodat(unix.AT_FDCWD, path, perm, unix.AT_SYMLINK_NOFOLLOW)
	}
	if err != nil {
		return &os.PathError{Op: "chmod", Path: path, Err: err}
	}

	return nil
}
