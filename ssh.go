package nebula

// Configuration and lifecycle for the ssh debug console. The commands it serves are not
// defined here; see commands.go, which registers them for every transport.

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"

	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/sshd"
)

func wireSSHReload(l *slog.Logger, ssh *sshd.SSHServer, c *config.C) {
	c.RegisterReloadCallback(func(c *config.C) {
		if c.GetBool("sshd.enabled", false) {
			sshRun, err := configSSH(l, ssh, c)
			if err != nil {
				l.Error("Failed to reconfigure the sshd", "error", err)
				ssh.Stop()
			}
			if sshRun != nil {
				go sshRun()
			}
		} else {
			ssh.Stop()
		}
	})
}

// configSSH reads the ssh info out of the passed-in Config and
// updates the passed-in SSHServer. On success, it returns a function
// that callers may invoke to run the configured ssh server. On
// failure, it returns nil, error.
func configSSH(l *slog.Logger, ssh *sshd.SSHServer, c *config.C) (func(), error) {
	listen := c.GetString("sshd.listen", "")
	if listen == "" {
		return nil, fmt.Errorf("sshd.listen must be provided")
	}

	_, port, err := net.SplitHostPort(listen)
	if err != nil {
		return nil, fmt.Errorf("invalid sshd.listen address: %s", err)
	}
	if port == "22" {
		return nil, fmt.Errorf("sshd.listen can not use port 22")
	}

	hostKeyPathOrKey := c.GetString("sshd.host_key", "")
	if hostKeyPathOrKey == "" {
		return nil, fmt.Errorf("sshd.host_key must be provided")
	}

	var hostKeyBytes []byte
	if strings.Contains(hostKeyPathOrKey, "-----BEGIN") {
		hostKeyBytes = []byte(hostKeyPathOrKey)
	} else {
		hostKeyBytes, err = os.ReadFile(hostKeyPathOrKey)
		if err != nil {
			return nil, fmt.Errorf("error while loading sshd.host_key file: %s", err)
		}
	}

	err = ssh.SetHostKey(hostKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("error while adding sshd.host_key: %s", err)
	}

	// Clear existing trusted CAs and authorized keys
	ssh.ClearTrustedCAs()
	ssh.ClearAuthorizedKeys()

	rawCAs := c.GetStringSlice("sshd.trusted_cas", []string{})
	for _, caAuthorizedKey := range rawCAs {
		err := ssh.AddTrustedCA(caAuthorizedKey)
		if err != nil {
			l.Warn("SSH CA had an error, ignoring", "error", err, "sshCA", caAuthorizedKey)
			continue
		}
	}

	rawKeys := c.Get("sshd.authorized_users")
	keys, ok := rawKeys.([]any)
	if ok {
		for _, rk := range keys {
			kDef, ok := rk.(map[string]any)
			if !ok {
				l.Warn("Authorized user had an error, ignoring", "sshKeyConfig", rk)
				continue
			}

			user, ok := kDef["user"].(string)
			if !ok {
				l.Warn("Authorized user is missing the user field", "sshKeyConfig", rk)
				continue
			}

			k := kDef["keys"]
			switch v := k.(type) {
			case string:
				err := ssh.AddAuthorizedKey(user, v)
				if err != nil {
					l.Warn("Failed to authorize key",
						"error", err,
						"sshKeyConfig", rk,
						"sshKey", v,
					)
					continue
				}

			case []any:
				for _, subK := range v {
					sk, ok := subK.(string)
					if !ok {
						l.Warn("Did not understand ssh key",
							"sshKeyConfig", rk,
							"sshKey", subK,
						)
						continue
					}

					err := ssh.AddAuthorizedKey(user, sk)
					if err != nil {
						l.Warn("Failed to authorize key",
							"error", err,
							"sshKeyConfig", sk,
						)
						continue
					}
				}

			default:
				l.Warn("Authorized user is missing the keys field or was not understood", "sshKeyConfig", rk)
			}
		}
	} else {
		l.Info("no ssh users to authorize")
	}

	var runner func()
	if c.GetBool("sshd.enabled", false) {
		ssh.Stop()
		runner = func() {
			if err := ssh.Run(listen); err != nil {
				l.Warn("Failed to run the SSH server", "error", err)
			}
		}
	} else {
		ssh.Stop()
	}

	return runner, nil
}
