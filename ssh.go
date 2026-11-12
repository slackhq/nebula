package nebula

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"slices"
	"strings"

	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/sshd"
)

func wireSSHReload(l *slog.Logger, ssh *sshd.SSHServer, c *config.C) {
	c.RegisterReloadCallback(func(c *config.C, r *config.Reload) {
		if c.GetBool("sshd.enabled", false) {
			// Restarting the server drops every open session, the one that asked for this reload included. Only restart
			// when it isn't running or its config changed. The host key file can change under the same config, new
			// handshakes use the new key without a restart
			if ssh.Running() && !slices.ContainsFunc(sshdServerKeys, c.HasChanged) {
				key, err := loadSSHHostKey(c)
				if err == nil {
					err = ssh.SetHostKey(key)
				}
				if err != nil {
					l.Error("Failed to reconfigure the sshd", "error", err)
					ssh.Stop()
					r.Failed()
				}
				return
			}
			sshRun, err := configSSH(l, ssh, c, r)
			if err != nil {
				l.Error("Failed to reconfigure the sshd", "error", err)
				ssh.Stop()
				r.Failed()
			}
			if sshRun != nil {
				go sshRun()
			}
		} else {
			ssh.Stop()
		}
	})
}

// sshdServerKeys are what configSSH reads
var sshdServerKeys = []string{"sshd.enabled", "sshd.listen", "sshd.host_key", "sshd.trusted_cas", "sshd.authorized_users"}

// loadSSHHostKey returns sshd.host_key, read from its file when it names one.
func loadSSHHostKey(c *config.C) ([]byte, error) {
	hostKeyPathOrKey := c.GetString("sshd.host_key", "")
	if hostKeyPathOrKey == "" {
		return nil, fmt.Errorf("sshd.host_key must be provided")
	}
	if strings.Contains(hostKeyPathOrKey, "-----BEGIN") {
		return []byte(hostKeyPathOrKey), nil
	}
	b, err := os.ReadFile(hostKeyPathOrKey)
	if err != nil {
		return nil, fmt.Errorf("error while loading sshd.host_key file: %s", err)
	}
	return b, nil
}

// configSSH reads the ssh info out of the passed-in Config and
// updates the passed-in SSHServer. On success, it returns a function
// that callers may invoke to run the configured ssh server. On
// failure, it returns nil, error.
// r is nil at startup, entries that are skipped with a warning fail it on a reload
func configSSH(l *slog.Logger, ssh *sshd.SSHServer, c *config.C, r *config.Reload) (func(), error) {
	listenAddrs := getListenAddrs(c, "sshd.listen")
	if len(listenAddrs) == 0 {
		return nil, fmt.Errorf("sshd.listen must be provided")
	}
	for _, listen := range listenAddrs {
		_, port, err := net.SplitHostPort(listen)
		if err != nil {
			return nil, fmt.Errorf("invalid sshd.listen address %q: %s", listen, err)
		}
		if port == "22" {
			return nil, fmt.Errorf("sshd.listen can not use port 22")
		}
	}

	hostKeyBytes, err := loadSSHHostKey(c)
	if err != nil {
		return nil, err
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
			r.Failed()
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
				r.Failed()
				continue
			}

			user, ok := kDef["user"].(string)
			if !ok {
				l.Warn("Authorized user is missing the user field", "sshKeyConfig", rk)
				r.Failed()
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
					r.Failed()
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
						r.Failed()
						continue
					}

					err := ssh.AddAuthorizedKey(user, sk)
					if err != nil {
						l.Warn("Failed to authorize key",
							"error", err,
							"sshKeyConfig", sk,
						)
						r.Failed()
						continue
					}
				}

			default:
				l.Warn("Authorized user is missing the keys field or was not understood", "sshKeyConfig", rk)
				r.Failed()
			}
		}
	} else {
		l.Info("no ssh users to authorize")
	}

	var runner func()
	if c.GetBool("sshd.enabled", false) {
		ssh.Stop()
		runner = func() {
			if err := ssh.Run(listenAddrs); err != nil {
				l.Warn("Failed to run the SSH server", "error", err)
			}
		}
	} else {
		ssh.Stop()
	}

	return runner, nil
}
