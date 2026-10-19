package localapi

// DirName is the directory under /var/run that holds nebula's sockets by default.
const DirName = "nebula"

// CtlSocketKey is the optional config key naming the control socket. Unset, the socket
// is DefaultSocketPath, one fixed path that suits a daemon running as root, which is
// what the tun device needs anyway. A daemon run as another user, or a second daemon on
// one host, names its own. The CLI reads the same key, so when both sides see the same
// config file they agree on the socket with nothing more said.
const CtlSocketKey = "local_api.control.socket"

// CtlGroupKey is the optional config key naming a group that shares the control socket.
// Unset, the socket admits the account nebula runs as and nobody else. Set, the socket
// is handed to the group, 0660 on unix and an entry in the pipe's security descriptor on
// windows, and the kernel's check on connect is the access control, as dockerd's -G
// works; the daemon's own peer check stands aside, since on unix it could not tell a
// member of the group from anyone else.
const CtlGroupKey = "local_api.control.group"

// controlAccessFrom returns the control socket's access a config implies: the group
// CtlGroupKey names, if any, and the mode that goes with having one or not.
func controlAccessFrom(c interface{ GetString(string, string) string }) (Access, error) {
	group, err := groupFromConfig(c, CtlGroupKey)
	if err != nil {
		return Access{}, err
	}
	if group == nil {
		return ownerOnly(), nil
	}
	return Access{Mode: groupSocketMode, Group: group}, nil
}

// DefaultSocketPath is the control socket when the config names none: one fixed path per
// platform, see defaultSocketPath. Both the daemon and nebula ctl use it, which is what
// lets the endpoint work with no configuration on either side.
func DefaultSocketPath() string { return defaultSocketPath }

// SocketPathFromConfig returns the control socket path a config implies: CtlSocketKey
// when it is set, else DefaultSocketPath.
func SocketPathFromConfig(c interface{ GetString(string, string) string }) (string, error) {
	if override := c.GetString(CtlSocketKey, ""); override != "" {
		return configuredSocketPath(CtlSocketKey, override)
	}

	return DefaultSocketPath(), nil
}

// configuredSocketPath checks the value of a socket path key and returns it as given. It
// must be absolute, so that the daemon and nebula ctl, started from wherever the
// operator happens to be, name the same socket from one config, and it must be a path
// this platform can bind. key names the setting in the error.
func configuredSocketPath(key, value string) (string, error) {
	if err := checkSocketPath(key, value); err != nil {
		return "", err
	}
	return value, nil
}
