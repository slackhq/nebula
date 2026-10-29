package localapi

// DirName is the directory under /var/run that holds nebula's sockets by default.
const DirName = "nebula"

// CtlEnabledKey is the optional config key that turns the control socket off. It is on
// unless the config says false, and reloadable: a reload that turns it off removes the
// socket, and one that turns it back on brings it up again.
const CtlEnabledKey = "local_api.control.enabled"

// ControlEnabled reports whether a config leaves the control socket on. nebula ctl reads
// it too, so a client pointed at a config that turned the socket off says so rather than
// failing to dial.
func ControlEnabled(c interface{ GetBool(string, bool) bool }) bool {
	return c.GetBool(CtlEnabledKey, true)
}

// CtlSocketKey is the optional config key naming the control socket. Unset, the socket
// is DefaultSocketPath, one fixed path per platform that both the daemon and nebula ctl
// know, which is what lets the endpoint work with no configuration on either side. It
// suits a daemon running as root, which is what the tun device needs anyway. A daemon run as another user, or a second daemon on
// one host, names its own. The CLI reads the same key, so when both sides see the same
// config file they agree on the socket with nothing more said.
const CtlSocketKey = "local_api.control.socket"

// CtlGroupKey is the optional config key naming a group that shares the control socket.
// Unset, the socket admits the account nebula runs as and nobody else. Set, the socket
// is handed to the group, 0660 on unix and an entry in the pipe's security descriptor on
// windows; see Access and Server.trustSocket.
const CtlGroupKey = "local_api.control.group"

// controlAccessFrom returns the control socket's access a config implies: the group
// CtlGroupKey names, if any, and the mode that goes with having one or not.
func controlAccessFrom(c interface{ GetString(string, string) string }) (Access, error) {
	group, err := groupFromConfig(c, CtlGroupKey)
	if err != nil {
		return Access{}, err
	}
	if group.id == "" {
		return OwnerOnly(), nil
	}
	return Access{mode: groupSocketMode, group: group}, nil
}

// SocketPathFromConfig returns the control socket path a config implies: CtlSocketKey
// when it is set, else DefaultSocketPath. A configured path must be absolute, so that
// the daemon and nebula ctl, started from wherever the operator happens to be, name the
// same socket from one config, and one this platform can bind; see checkSocketPath.
func SocketPathFromConfig(c interface{ GetString(string, string) string }) (string, error) {
	override := c.GetString(CtlSocketKey, "")
	if override == "" {
		return DefaultSocketPath, nil
	}
	if err := checkSocketPath(CtlSocketKey, override); err != nil {
		return "", err
	}
	return override, nil
}
