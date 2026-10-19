//go:build !windows

package localapi

import (
	"fmt"
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

// gidOf returns the group's gid as the number chown takes.
func gidOf(g *Group) (int, error) {
	gid, err := strconv.ParseUint(g.ID, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("group %q resolved to %q, which is not a gid", g.Name, g.ID)
	}
	return int(gid), nil
}
