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
	Mode  os.FileMode
	Group *Group
}

// Group is a group named in the config, resolved to what the platform checks.
type Group struct {
	// Name is what the config said.
	Name string

	// ID is the platform's identifier for it: a gid on unix, a SID on windows.
	ID string
}

// groupSocketMode is the mode a socket takes when a group shares it and the config
// names no other: the account nebula runs as and the group, and nobody else.
const groupSocketMode os.FileMode = 0660

// errReopenForAccess is returned by applyAccess on a platform whose access control is
// fixed when the endpoint is created, so a change means creating it again.
var errReopenForAccess = errors.New("access is fixed at listen time")

// ownerOnly is the control socket's access when no group is configured: the account
// nebula runs as, and nobody else.
func ownerOnly() Access { return Access{Mode: ctlSocketMode} }

// String renders the access for a log line.
func (a Access) String() string {
	if a.Group == nil {
		return modeString(a.Mode)
	}
	return fmt.Sprintf("%s group %s (%s)", modeString(a.Mode), a.Group.Name, a.Group.ID)
}

func (a Access) equal(b Access) bool {
	if a.Mode != b.Mode || (a.Group == nil) != (b.Group == nil) {
		return false
	}
	return a.Group == nil || a.Group.ID == b.Group.ID
}

// groupFromConfig reads the group a key names, or nil when it names none. The name is
// resolved here, when the config is read, so a group that does not exist is a config
// error reported with the key rather than a bind that fails later.
func groupFromConfig(c interface{ GetString(string, string) string }, key string) (*Group, error) {
	name := c.GetString(key, "")
	if name == "" {
		return nil, nil
	}

	id, err := lookupGroupID(name)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", key, err)
	}
	return &Group{Name: name, ID: id}, nil
}

func modeString(m os.FileMode) string {
	return fmt.Sprintf("%04o", m)
}
