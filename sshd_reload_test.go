package nebula

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/sshd"
	"github.com/slackhq/nebula/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

type sshdReloadHarness struct {
	c       *config.C
	server  *sshd.SSHServer
	keyFile string
	signer  ssh.Signer
	addr    string
	extra   string
}

func newSSHDReloadHarness(t *testing.T) *sshdReloadHarness {
	t.Helper()
	l := test.NewLogger()
	h := &sshdReloadHarness{keyFile: filepath.Join(t.TempDir(), "host_key")}
	h.writeHostKey(t)

	_, userKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	h.signer, err = ssh.NewSignerFromKey(userKey)
	require.NoError(t, err)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	h.addr = ln.Addr().String()
	require.NoError(t, ln.Close())

	h.c = config.NewC(l)
	require.NoError(t, h.c.LoadString(h.config()))
	h.server, err = sshd.NewSSHServer(t.Context(), l)
	require.NoError(t, err)
	wireSSHReload(l, h.server, h.c)
	run, err := configSSH(l, h.server, h.c)
	require.NoError(t, err)
	go run()
	t.Cleanup(h.server.Stop)
	require.Eventually(t, h.server.Running, 5*time.Second, 10*time.Millisecond)
	return h
}

func (h *sshdReloadHarness) writeHostKey(t *testing.T) {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	block, err := ssh.MarshalPrivateKey(key, "")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(h.keyFile, pem.EncodeToMemory(block), 0o600))
}

func (h *sshdReloadHarness) config() string {
	return fmt.Sprintf("sshd:\n  enabled: true\n  listen: %s\n  host_key: %s\n  authorized_users:\n    - user: test\n      keys: [%q]\n%s",
		h.addr, h.keyFile, string(ssh.MarshalAuthorizedKey(h.signer.PublicKey())), h.extra)
}

func (h *sshdReloadHarness) connect(t *testing.T) *ssh.Client {
	t.Helper()
	client, err := ssh.Dial("tcp", h.addr, &ssh.ClientConfig{
		User:            "test",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(h.signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })
	return client
}

// dropped is true when the server closed the client's connection within wait
func dropped(client *ssh.Client, wait time.Duration) bool {
	done := make(chan struct{})
	go func() {
		_ = client.Wait()
		close(done)
	}()
	select {
	case <-done:
		return true
	case <-time.After(wait):
		return false
	}
}

// Restarting sshd drops every open session, the one that asked for the reload included. A reload that touches nothing
// sshd reads leaves it alone
func TestSSHDReload_UnchangedKeepsSessions(t *testing.T) {
	h := newSSHDReloadHarness(t)
	client := h.connect(t)

	require.NoError(t, h.c.ReloadConfigString(h.config()+"punchy:\n  punch: true\n"))
	assert.False(t, dropped(client, 500*time.Millisecond), "an unchanged sshd was restarted")
}

func TestSSHDReload_ChangedConfigRestarts(t *testing.T) {
	h := newSSHDReloadHarness(t)
	client := h.connect(t)

	h.extra = "  trusted_cas: []\n"
	require.NoError(t, h.c.ReloadConfigString(h.config()))
	assert.True(t, dropped(client, 5*time.Second), "a changed sshd config was not applied")
	require.Eventually(t, h.server.Running, 5*time.Second, 10*time.Millisecond)
	h.connect(t)
}

// The config can stay the same while the host key file it names changes
func TestSSHDReload_ChangedHostKeyFileRestarts(t *testing.T) {
	h := newSSHDReloadHarness(t)
	client := h.connect(t)

	h.writeHostKey(t)
	require.NoError(t, h.c.ReloadConfigString(h.config()))
	assert.True(t, dropped(client, 5*time.Second), "a new host key was not applied")
	require.Eventually(t, h.server.Running, 5*time.Second, 10*time.Millisecond)
	h.connect(t)
}

// A server that isn't running, say its port was busy, is tried again on every reload as before
func TestSSHDReload_NotRunningRestarts(t *testing.T) {
	h := newSSHDReloadHarness(t)
	h.server.Stop()
	require.Eventually(t, func() bool { return !h.server.Running() }, 5*time.Second, 10*time.Millisecond)

	require.NoError(t, h.c.ReloadConfigString(h.config()))
	require.Eventually(t, h.server.Running, 5*time.Second, 10*time.Millisecond)
	h.connect(t)
}
