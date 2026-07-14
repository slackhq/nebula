package nebula

import (
	"context"
	"strings"
	"testing"

	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/sshd"
	"github.com/slackhq/nebula/test"
)

// TestConfigSSH_SelfTokenParseValidation pins that the "<nebula>" self-token is
// treated like any other host at config-parse time: net.SplitHostPort splits it
// cleanly, so the port-22 rejection still fires and a valid port passes through
// to the later (host_key) validation. Expansion itself happens at run time, not
// here, so no PKI is needed.
func TestConfigSSH_SelfTokenParseValidation(t *testing.T) {
	l := test.NewLogger()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	newConf := func(listen string) *config.C {
		c := config.NewC(l)
		if err := c.LoadString("sshd:\n  enabled: true\n  listen: '" + listen + "'\n"); err != nil {
			t.Fatalf("LoadString: %v", err)
		}
		return c
	}

	t.Run("token with a valid port passes listen validation", func(t *testing.T) {
		ssh, err := sshd.NewSSHServer(ctx, l)
		if err != nil {
			t.Fatalf("NewSSHServer: %v", err)
		}
		_, err = configSSH(l, ssh, newConf("<nebula>:2222"), nil)
		// It must get PAST listen validation and fail on the missing host key,
		// proving the token was accepted exactly like a normal host would be.
		if err == nil || !strings.Contains(err.Error(), "host_key") {
			t.Fatalf("expected host_key error, got: %v", err)
		}
	})

	t.Run("token with port 22 is still rejected", func(t *testing.T) {
		ssh, err := sshd.NewSSHServer(ctx, l)
		if err != nil {
			t.Fatalf("NewSSHServer: %v", err)
		}
		_, err = configSSH(l, ssh, newConf("<nebula>:22"), nil)
		if err == nil || !strings.Contains(err.Error(), "port 22") {
			t.Fatalf("expected port 22 rejection, got: %v", err)
		}
	})

	t.Run("token without a port is rejected", func(t *testing.T) {
		ssh, err := sshd.NewSSHServer(ctx, l)
		if err != nil {
			t.Fatalf("NewSSHServer: %v", err)
		}
		_, err = configSSH(l, ssh, newConf("<nebula>"), nil)
		if err == nil || !strings.Contains(err.Error(), "invalid sshd.listen") {
			t.Fatalf("expected invalid sshd.listen error, got: %v", err)
		}
	})
}
