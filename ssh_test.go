package nebula

import (
	"context"
	"strings"
	"testing"

	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/sshd"
	"github.com/slackhq/nebula/test"
)

// TestConfigSSH_listenValidation covers sshd.listen accepting either a single
// address or a list, with per-address validation (port 22 rejected, malformed
// rejected, empty rejected).
func TestConfigSSH_listenValidation(t *testing.T) {
	l := test.NewLogger()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	attempt := func(t *testing.T, listenYAML string) error {
		c := config.NewC(l)
		if err := c.LoadString("sshd:\n  enabled: true\n  listen: " + listenYAML + "\n"); err != nil {
			t.Fatalf("LoadString: %v", err)
		}
		ssh, err := sshd.NewSSHServer(ctx, l)
		if err != nil {
			t.Fatalf("NewSSHServer: %v", err)
		}
		_, err = configSSH(l, ssh, c)
		return err
	}

	// A valid listen config passes listen validation and then fails on the
	// missing host key, which is how we know the addresses were accepted.
	t.Run("single address passes listen validation", func(t *testing.T) {
		err := attempt(t, "'127.0.0.1:2222'")
		if err == nil || !strings.Contains(err.Error(), "host_key") {
			t.Fatalf("expected host_key error, got: %v", err)
		}
	})

	t.Run("list of addresses passes listen validation", func(t *testing.T) {
		err := attempt(t, "['127.0.0.1:2222', '[::1]:2223']")
		if err == nil || !strings.Contains(err.Error(), "host_key") {
			t.Fatalf("expected host_key error, got: %v", err)
		}
	})

	t.Run("port 22 anywhere in the list is rejected", func(t *testing.T) {
		err := attempt(t, "['127.0.0.1:2222', '0.0.0.0:22']")
		if err == nil || !strings.Contains(err.Error(), "port 22") {
			t.Fatalf("expected port 22 rejection, got: %v", err)
		}
	})

	t.Run("malformed address is rejected", func(t *testing.T) {
		err := attempt(t, "'not-host-port'")
		if err == nil || !strings.Contains(err.Error(), "invalid sshd.listen") {
			t.Fatalf("expected invalid sshd.listen error, got: %v", err)
		}
	})

	t.Run("empty listen is rejected", func(t *testing.T) {
		err := attempt(t, "''")
		if err == nil || !strings.Contains(err.Error(), "must be provided") {
			t.Fatalf("expected must be provided error, got: %v", err)
		}
	})
}
