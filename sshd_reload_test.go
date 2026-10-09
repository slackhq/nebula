package nebula

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
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
	extra   string
}

func newSSHDReloadHarness(t *testing.T) *sshdReloadHarness {
	t.Helper()
	l := test.NewLogger()
	h := &sshdReloadHarness{keyFile: filepath.Join(t.TempDir(), "host_key")}
	h.writeHostKey(t, newEd25519Key(t))

	_, userKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	h.signer, err = ssh.NewSignerFromKey(userKey)
	require.NoError(t, err)

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

func newEd25519Key(t *testing.T) crypto.Signer {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	return key
}

// writeHostKey replaces the host key file and returns the public key a client should now see
func (h *sshdReloadHarness) writeHostKey(t *testing.T, key crypto.Signer) ssh.PublicKey {
	t.Helper()
	block, err := ssh.MarshalPrivateKey(key, "")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(h.keyFile, pem.EncodeToMemory(block), 0o600))
	pub, err := ssh.NewPublicKey(key.Public())
	require.NoError(t, err)
	return pub
}

func (h *sshdReloadHarness) config() string {
	return fmt.Sprintf("sshd:\n  enabled: true\n  listen: 127.0.0.1:0\n  host_key: %s\n  authorized_users:\n    - user: test\n      keys: [%q]\n%s",
		h.keyFile, string(ssh.MarshalAuthorizedKey(h.signer.PublicKey())), h.extra)
}

// dial connects to wherever the server listens now, a restart on :0 moves it. hostKeyAlgorithms limits which host keys
// the client accepts, none means any
func (h *sshdReloadHarness) dial(hostKeyAlgorithms ...string) (*ssh.Client, ssh.PublicKey, error) {
	addr := h.server.Addr()
	if addr == nil {
		return nil, nil, fmt.Errorf("not listening")
	}
	var hostKey ssh.PublicKey
	c, err := ssh.Dial("tcp", addr.String(), &ssh.ClientConfig{
		User: "test",
		Auth: []ssh.AuthMethod{ssh.PublicKeys(h.signer)},
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			hostKey = key
			return nil
		},
		HostKeyAlgorithms: hostKeyAlgorithms,
		Timeout:           time.Second,
	})
	return c, hostKey, err
}

func (h *sshdReloadHarness) connect(t *testing.T) (*ssh.Client, ssh.PublicKey) {
	t.Helper()
	var client *ssh.Client
	var hostKey ssh.PublicKey
	require.Eventually(t, func() bool {
		var err error
		client, hostKey, err = h.dial()
		return err == nil
	}, 5*time.Second, 20*time.Millisecond)
	t.Cleanup(func() { _ = client.Close() })
	return client, hostKey
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
	client, _ := h.connect(t)

	require.NoError(t, h.c.ReloadConfigString(h.config()+"punchy:\n  punch: true\n"))
	assert.False(t, dropped(client, 500*time.Millisecond), "an unchanged sshd was restarted")
}

func TestSSHDReload_ChangedConfigRestarts(t *testing.T) {
	h := newSSHDReloadHarness(t)
	client, _ := h.connect(t)

	h.extra = "  trusted_cas: []\n"
	require.NoError(t, h.c.ReloadConfigString(h.config()))
	assert.True(t, dropped(client, 5*time.Second), "a changed sshd config was not applied")
	require.Eventually(t, h.server.Running, 5*time.Second, 10*time.Millisecond)
	h.connect(t)
}

// The config can stay the same while the host key file it names changes. New connections get the new key, open
// sessions are left alone
func TestSSHDReload_ChangedHostKeyFile(t *testing.T) {
	h := newSSHDReloadHarness(t)
	client, _ := h.connect(t)

	want := h.writeHostKey(t, newEd25519Key(t))
	require.NoError(t, h.c.ReloadConfigString(h.config()))
	_, got := h.connect(t)
	assert.Equal(t, want.Marshal(), got.Marshal(), "a new host key was not applied")
	assert.False(t, dropped(client, 500*time.Millisecond), "a new host key restarted sshd")
}

// A host key of another algorithm replaces the old one rather than being offered next to it
func TestSSHDReload_HostKeyAlgorithmChange(t *testing.T) {
	h := newSSHDReloadHarness(t)
	h.connect(t)

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	want := h.writeHostKey(t, rsaKey)
	require.NoError(t, h.c.ReloadConfigString(h.config()))

	_, got := h.connect(t)
	assert.Equal(t, want.Marshal(), got.Marshal())
	_, _, err = h.dial(ssh.KeyAlgoED25519)
	assert.Error(t, err, "the old ed25519 host key is still offered")
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

// A host key that no longer loads stops sshd, the same as a config that doesn't
func TestSSHDReload_BadHostKeyFileStops(t *testing.T) {
	h := newSSHDReloadHarness(t)
	h.connect(t)

	require.NoError(t, os.WriteFile(h.keyFile, []byte("not a key"), 0o600))
	require.NoError(t, h.c.ReloadConfigString(h.config()))
	require.Eventually(t, func() bool { return !h.server.Running() }, 5*time.Second, 10*time.Millisecond)
}
