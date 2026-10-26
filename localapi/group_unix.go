//go:build !windows

package localapi

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
)

// lookupGroupID resolves a group's name, or a numeric gid, to the gid as a string. A
// gid that the group database does not list is accepted as chown would accept it: the
// operator may be naming a group the host will learn about later, or one that only a
// directory service knows.
func lookupGroupID(name string) (string, error) {
	if g, err := user.LookupGroup(name); err == nil {
		return g.Gid, nil
	}

	if _, err := strconv.ParseUint(name, 10, 32); err == nil {
		return name, nil
	}

	return "", fmt.Errorf("group %q does not exist on this host", name)
}

// gidFor returns the gid the socket is owned by under acc: the configured group's, or
// the daemon's own effective group when none is configured.
func gidFor(acc Access) (int, error) {
	if !acc.shared() {
		return os.Getegid(), nil
	}
	gid, err := strconv.ParseUint(acc.group.id, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("group %q resolved to %q, which is not a gid", acc.group.name, acc.group.id)
	}
	return int(gid), nil
}
