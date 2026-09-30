package localapi

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// SocketExt is the suffix every socket this package creates carries, so it can be told
// apart from anything else living in the runtime dir.
const SocketExt = ".sock"

// DirName is the directory, inside the runtime dir, holding nebula's sockets.
const DirName = "nebula"

// CtlSocketKey is the optional config key naming the socket `nebula ctl` connects to.
// Nothing has to set it: the endpoint works with no configuration at all, and this
// exists for layouts the derived path cannot serve, such as a path too long for
// sun_path.
//
// The CLI reads the same key, so when both sides see the same config file they agree on
// the socket with nothing more said. It is an escape hatch rather than routine
// configuration.
const CtlSocketKey = "local_api.control.socket"

// shortHash names an endpoint after the config it belongs to, so two nebula instances
// on one host do not collide and both the daemon and the CLI can derive it.
//
// The daemon and the CLI may well reach the same file by different names, one through
// a symlink and one directly, or on windows with different letter case, so the path is
// resolved before it is hashed. A config that does not exist yet cannot be resolved and
// is hashed as given.
func shortHash(configPath string) string {
	p := configPath
	if abs, err := filepath.Abs(p); err == nil {
		p = abs
	}
	if real, err := filepath.EvalSymlinks(p); err == nil {
		p = real
	}
	if runtime.GOOS == "windows" {
		p = strings.ToLower(p)
	}

	sum := sha256.Sum256([]byte(p))
	return hex.EncodeToString(sum[:4])
}

// DefaultSocketPath derives the endpoint path for a daemon running with configPath.
//
// The daemon and the CLI both call this, which is what lets the endpoint work with no
// configuration on either side. Neither searches for the other: the path is computed,
// and when the two environments compute different answers the daemon's startup log says
// where its socket is and the operator passes it.
func DefaultSocketPath(configPath string) (string, error) {
	return defaultPathFor(shortHash(configPath))
}

// SocketPathFromConfig returns the endpoint path for a config, honouring CtlSocketKey.
//
// A relative override is resolved against the config's own directory, never the working
// directory. The daemon and the CLI are started from wherever the operator happens to be,
// and each resolving `run/ctl.sock` against its own cwd would have them compute two
// different sockets from one config file, with the daemon logging a path that only means
// something from where it was launched.
func SocketPathFromConfig(c interface{ GetString(string, string) string }, configPath string) (string, error) {
	if override := c.GetString(CtlSocketKey, ""); override != "" {
		return configuredSocketPath(CtlSocketKey, override, configPath)
	}

	return DefaultSocketPath(configPath)
}

// configuredSocketPath turns the value of a socket path key into the path to serve:
// resolved against the config's directory when relative, and refused when the platform
// cannot bind a path that long. key names the setting in the error.
func configuredSocketPath(key, value, configPath string) (string, error) {
	p := resolveOverride(value, configPath)
	if pathTooLong(p) {
		return "", fmt.Errorf("%s is %d bytes, too long for this platform: %s", key, len(p), p)
	}
	return p, nil
}

// configDir is the directory a relative CtlSocketKey resolves against: the config itself
// when nebula was pointed at a directory of config files, otherwise the file's parent.
// A config that cannot be stat'd is taken to be a file, which is what a missing path
// most plausibly was.
func configDir(configPath string) string {
	if fi, err := os.Stat(configPath); err == nil && fi.IsDir() {
		return configPath
	}
	return filepath.Dir(configPath)
}
