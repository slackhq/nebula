package localapi

// DirName is the directory under /var/run that holds nebula's sockets by default.
const DirName = "nebula"

// CtlSocketKey is the optional config key naming the control socket. Unset, the socket
// is DefaultSocketPath, one fixed path that suits a daemon running as root, which is
// what the tun device needs anyway. A daemon run as another user, or a second daemon on
// one host, names its own. The CLI reads the same key, so when both sides see the same
// config file they agree on the socket with nothing more said.
const CtlSocketKey = "local_api.control.socket"

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
