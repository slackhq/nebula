//go:build linux && !android && !e2e_testing

package main

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/slackhq/nebula"
	"github.com/slackhq/nebula/cert"
	cert_test "github.com/slackhq/nebula/cert_test"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/test"
	"github.com/stretchr/testify/require"
)

// TestControlStopClosesOnTimer reproduces the dnclient lifecycle: nebula runs as
// a library, and on a config update dnclient calls Stop() in-process to tear the
// old instance down before starting a new one. This boots a real nebula (real
// blocking UDP sockets, tun disabled), lets it run, then Stop()s it on a timer
// and asserts it actually closes. If the reader goroutines parked in recvmmsg
// don't wake on Close(), Wait() blocks forever and this fails with a goroutine
// dump instead of relying on a process signal to unstick them.
func TestControlStopClosesOnTimer(t *testing.T) {
	l := test.NewLogger()
	dir := t.TempDir()

	before := time.Now().Add(-time.Hour)
	after := time.Now().Add(time.Hour)
	ca, _, caKey, caPEM := cert_test.NewTestCaCert(cert.Version2, cert.Curve_CURVE25519, before, after, nil, nil, nil)
	networks := []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")}
	_, _, keyPEM, certPEM := cert_test.NewTestCert(cert.Version2, cert.Curve_CURVE25519, ca, caKey, "close-on-timer", before, after, networks, nil, nil)

	caPath := filepath.Join(dir, "ca.pem")
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	require.NoError(t, os.WriteFile(caPath, caPEM, 0o600))
	require.NoError(t, os.WriteFile(certPath, certPEM, 0o600))
	require.NoError(t, os.WriteFile(keyPath, keyPEM, 0o600))

	// tun disabled so no device/root is needed; routines: 2 so we exercise the
	// multi-socket (SO_REUSEPORT) teardown, which is where dnclient runs.
	configBody := fmt.Sprintf(`
pki:
  ca: %s
  cert: %s
  key: %s
listen:
  host: 127.0.0.1
  port: 0
tun:
  disabled: true
firewall:
  outbound:
    - port: any
      proto: any
      host: any
  inbound:
    - port: any
      proto: any
      host: any
routines: 2
`, caPath, certPath, keyPath)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "config.yml"), []byte(configBody), 0o600))

	c := config.NewC(l)
	require.NoError(t, c.Load(dir))

	ctrl, err := nebula.Main(c, false, "close-on-timer", l, nil)
	require.NoError(t, err)
	require.NoError(t, ctrl.Start())

	// Run like a live nebula, then close on a timer, exactly as dnclient does.
	<-time.NewTimer(5 * time.Second).C

	stopped := make(chan struct{})
	go func() {
		ctrl.Stop() // closes the udp sockets (shutdown(2)) and the tun
		ctrl.Wait() // blocks until every reader goroutine has returned
		close(stopped)
	}()

	select {
	case <-stopped:
		t.Log("nebula closed cleanly on timer")
	case <-time.After(10 * time.Second):
		buf := make([]byte, 1<<20)
		n := runtime.Stack(buf, true)
		t.Fatalf("nebula did NOT close within 10s of Stop(): a blocking reader never woke\n%s", buf[:n])
	}
}
