package localapi

import (
	"errors"
	"fmt"
	"os"
)

// Access is who may reach a socket beyond the account nebula runs as: the node's mode,
// and the group that shares the socket when the config names one.
//
// It is the dockerd model (-G): the operator names a group, nebula hands the socket to
// it, and who is in the group is managed outside nebula. On unix the mode is the
// socket node's and the group becomes its owning group; on windows the group is an
// entry in the pipe's security descriptor and the mode means nothing to a pipe.
//
// Only built in this package, to maintain control of validity.
type Access struct {
	mode  os.FileMode
	group Group
}

// Socket mode on unix, useless on windows.
func (a Access) Mode() os.FileMode { return a.mode }

// Group that shares API access; Group{} if there isn't one.
func (a Access) Group() Group { return a.group }

type Group struct {
	name string
	id   string
}

func (g Group) Name() string { return g.name }

// gid on unix, SID on windows.
func (g Group) ID() string { return g.id }

const (
	// ownerOnlyMode is a socket's mode when no group shares it: the account nebula runs
	// as, and nobody else.
	ownerOnlyMode os.FileMode = 0600

	// groupSocketMode is the mode a socket takes when a group shares it and the config
	// names no other: the account nebula runs as and the group, and nobody else.
	groupSocketMode os.FileMode = 0660
)

// errAccessFixed is returned by applyAccess on a platform whose access control is fixed
// when the endpoint is created and cannot be changed while it is served. A change that
// widens the access waits for a restart; one that narrows it stops the endpoint until
// then; see endpoint.rebindLocked.
var errAccessFixed = errors.New("permissions/group cannot be changed on reconfig")

// Access specifying that only the nebula user/root should be able to access the endpoint.
func OwnerOnly() Access { return Access{mode: ownerOnlyMode} }

// True if the access specifies group access.
func (a Access) shared() bool { return a.group.id != "" }

// narrowedBy reports whether acc takes away access a grants: a group a admits that acc
// does not. A group acc adds is a widening, which costs nobody served anything.
func (a Access) narrowedBy(acc Access) bool { return a.shared() && a.group != acc.group }

// String renders the access for a log line.
func (a Access) String() string {
	if !a.shared() {
		return modeString(a.mode)
	}
	return fmt.Sprintf("%s group %s (%s)", modeString(a.mode), a.group.name, a.group.id)
}

// groupFromConfig reads the group a key names, the zero Group when it names none. The
// name is resolved here, when the config is read, so a group that does not exist is a
// config error reported with the key rather than a bind that fails later.
func groupFromConfig(c interface{ GetString(string, string) string }, key string) (Group, error) {
	name := c.GetString(key, "")
	if name == "" {
		return Group{}, nil
	}

	id, err := lookupGroupID(name)
	if err != nil {
		return Group{}, fmt.Errorf("%s: %w", key, err)
	}
	return Group{name: name, id: id}, nil
}

func modeString(m os.FileMode) string {
	return fmt.Sprintf("%04o", m)
}
