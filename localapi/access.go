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
type Access struct {
	mode  os.FileMode
	group Group
}

// Group is a group named in the config, resolved to what the platform checks. The zero
// Group is none.
type Group struct {
	// name is what the config said.
	name string

	// id is the platform's identifier for it: a gid on unix, a SID on windows.
	id string
}

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

// OwnerOnly is the control socket's access when no group is configured. The mode
// itself is not configurable there; what an operator can choose is a group,
// CtlGroupKey, which makes it groupSocketMode.
func OwnerOnly() Access { return Access{mode: ownerOnlyMode} }

// shared reports whether a group shares the socket.
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
