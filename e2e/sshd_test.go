//go:build e2e_testing
// +build e2e_testing

package e2e

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/cert_test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func TestSSHDLifecycle(t *testing.T) {
	// TestSSHDLifecycle exercises the in-process sshd through several config reloads and a Control.Stop.
	ca, _, caKey, _ := cert_test.NewTestCaCert(
		cert.Version1, cert.Curve_CURVE25519,
		time.Now(), time.Now().Add(10*time.Minute),
		nil, nil, []string{},
	)

	hostKeyPEM := generateSSHHostKey(t)
	clientSigner, clientAuthKey := generateSSHClientKey(t)
	sshdAddr := allocLoopbackPort(t)

	overrides := m{
		"sshd": m{
			"enabled":  true,
			"listen":   sshdAddr,
			"host_key": hostKeyPEM,
			"authorized_users": []m{{
				"user": "tester",
				"keys": []string{clientAuthKey},
			}},
		},
	}
	control, _, _, _ := newSimpleServer(cert.Version1, ca, caKey, "sshd-test", "10.222.0.1/24", overrides)
	control.Start()
	t.Cleanup(func() { control.Stop() })

	// sshd binds in a goroutine after Start returns; wait for it.
	require.Eventually(t, func() bool { return canDial(sshdAddr) }, 2*time.Second, 25*time.Millisecond,
		"sshd never started listening")

	for i := 1; i <= 3; i++ {
		out := sshExecReload(t, sshdAddr, clientSigner)
		assert.Contains(t, out, "Reloading config", "reload cycle %d", i)
		require.Eventually(t, func() bool { return canDial(sshdAddr) }, 2*time.Second, 25*time.Millisecond,
			"sshd not listening after reload cycle %d", i)
	}

	control.Stop()
	require.Eventually(t, func() bool { return !canDial(sshdAddr) }, 2*time.Second, 25*time.Millisecond,
		"sshd still listening after Control.Stop")
}

func canDial(addr string) bool {
	c, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

// allocLoopbackPort grabs an unused TCP port on 127.0.0.1, closes it, and returns the address. There
// is a small race between releasing the port and the sshd reclaiming it; in practice the OS keeps the
// port available long enough for the test to bind it.
func allocLoopbackPort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := l.Addr().String()
	require.NoError(t, l.Close())
	return addr
}

func generateSSHHostKey(t *testing.T) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	block, err := ssh.MarshalPrivateKey(priv, "nebula-e2e-host")
	require.NoError(t, err)
	return string(pem.EncodeToMemory(block))
}

func generateSSHClientKey(t *testing.T) (ssh.Signer, string) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromKey(priv)
	require.NoError(t, err)
	auth := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	return signer, auth
}

func sshExecReload(t *testing.T, addr string, signer ssh.Signer) string {
	t.Helper()
	cfg := &ssh.ClientConfig{
		User:            "tester",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         2 * time.Second,
	}
	client, err := ssh.Dial("tcp", addr, cfg)
	require.NoError(t, err)
	defer client.Close()

	sess, err := client.NewSession()
	require.NoError(t, err)
	defer sess.Close()

	// reload tears the channel down before sending exit-status, so Output returns an error on the
	// channel close. The output buffer still has whatever the reload callback wrote before that.
	out, _ := sess.Output("reload")
	return string(out)
}
