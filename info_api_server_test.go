package nebula

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/cert_test"
	"github.com/slackhq/nebula/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_parseInfoAPIListen(t *testing.T) {
	type testCase struct {
		listen  string
		addr    string
		wantErr bool
	}
	tests := []testCase{
		{listen: "", wantErr: true},
		{listen: "unix://", wantErr: true},
		{listen: "unix://relative/path.sock", wantErr: true},
		{listen: "not an address", wantErr: true},
		// tcp host:port addresses are no longer accepted
		{listen: "127.0.0.1:8085", wantErr: true},
		{listen: "[::1]:8085", wantErr: true},
		{listen: "localhost:8085", wantErr: true},
	}

	// A unix socket path must be absolute for the OS that will bind it, and filepath.IsAbs is
	// GOOS-specific. CI runs the suite separately on each OS, so assert the platform's own native
	// absolute path is accepted while the other platform's is rejected.
	posixPath := "unix:///var/run/nebula.sock"
	winPath := `unix://C:\nebula\hq.sock`
	if runtime.GOOS == "windows" {
		tests = append(tests,
			testCase{listen: winPath, addr: `C:\nebula\hq.sock`},
			testCase{listen: posixPath, wantErr: true},
		)
	} else {
		tests = append(tests,
			testCase{listen: posixPath, addr: "/var/run/nebula.sock"},
			testCase{listen: winPath, wantErr: true},
		)
	}

	for _, tt := range tests {
		addr, err := parseInfoAPIListen(tt.listen)
		if tt.wantErr {
			require.Error(t, err, "listen=%q", tt.listen)
			continue
		}
		require.NoError(t, err, "listen=%q", tt.listen)
		assert.Equal(t, tt.addr, addr, "listen=%q", tt.listen)
	}
}

func Test_loadInfoAPIConfig(t *testing.T) {
	c := config.NewC(nil)

	// the listen path must be absolute for the OS running the test (CI is per-OS)
	listen, wantAddr := "unix:///tmp/hq.sock", "/tmp/hq.sock"
	if runtime.GOOS == "windows" {
		listen, wantAddr = `unix://C:\tmp\hq.sock`, `C:\tmp\hq.sock`
	}

	// absent section means disabled, no error
	cfg, err := loadInfoAPIConfig(c)
	require.NoError(t, err)
	assert.False(t, cfg.enabled)

	// enabled without a listen address is an error
	setInfoAPIConfig(c, true, "", "")
	_, err = loadInfoAPIConfig(c)
	require.Error(t, err)

	// a unix socket gets the default mode
	setInfoAPIConfig(c, true, listen, "")
	cfg, err = loadInfoAPIConfig(c)
	require.NoError(t, err)
	assert.Equal(t, wantAddr, cfg.addr)
	assert.Equal(t, fs.FileMode(0o600), cfg.socketMode)

	setInfoAPIConfig(c, true, listen, "0660")
	cfg, err = loadInfoAPIConfig(c)
	require.NoError(t, err)
	assert.Equal(t, fs.FileMode(0o660), cfg.socketMode)

	setInfoAPIConfig(c, true, listen, "withers")
	_, err = loadInfoAPIConfig(c)
	require.Error(t, err)

	// mode bits beyond the permission bits are rejected
	setInfoAPIConfig(c, true, listen, "10600")
	_, err = loadInfoAPIConfig(c)
	require.Error(t, err)

	// tcp host:port listen addresses are no longer supported
	setInfoAPIConfig(c, true, "127.0.0.1:8085", "")
	_, err = loadInfoAPIConfig(c)
	require.Error(t, err)
}

func TestInfoAPIServer_badConfigIsNonFatal(t *testing.T) {
	// an enabled-but-invalid config must not stop construction; nebula keeps starting and the
	// feature simply stays disabled until a reload supplies a valid config
	c := config.NewC(nil)
	setInfoAPIConfig(c, true, "not-a-unix-socket", "")
	h := newInfoAPIServerFromConfig(context.Background(), slog.New(slog.DiscardHandler), nil, newHostMap(slog.New(slog.DiscardHandler)), c)
	require.NotNil(t, h)
	assert.False(t, h.enabled.Load())

	// no config was recorded, so Start has nothing to bind and is a no-op
	h.runMu.Lock()
	assert.Nil(t, h.runCfg)
	h.runMu.Unlock()
	h.Start()
	h.runMu.Lock()
	assert.Nil(t, h.run)
	h.runMu.Unlock()
}

func setInfoAPIConfig(c *config.C, enabled bool, listen, socketMode string) {
	settings := map[string]any{
		"enabled": enabled,
		"listen":  listen,
	}
	if socketMode != "" {
		settings["socket_mode"] = socketMode
	}
	c.Settings["info_api"] = settings
}

func newTestInfoAPIServer(t *testing.T) (*infoAPIServer, *config.C) {
	t.Helper()
	h := &infoAPIServer{
		l:       slog.New(slog.DiscardHandler),
		ctx:     context.Background(),
		hostMap: newHostMap(slog.New(slog.DiscardHandler)),
	}
	h.hostMap.preferredRanges.Store(&[]netip.Prefix{})
	return h, config.NewC(nil)
}

// addTestPeer creates a certificate for a peer owning each addr (as a /24 or /64) and inserts it
// into the hostmap as an established tunnel
func addTestPeer(t *testing.T, hm *HostMap, name string, addrs []netip.Addr, unsafeNetworks []netip.Prefix, groups []string) cert.Certificate {
	t.Helper()
	networks := make([]netip.Prefix, 0, len(addrs))
	for _, a := range addrs {
		bits := 24
		if a.Is6() {
			bits = 64
		}
		networks = append(networks, netip.PrefixFrom(a, bits))
	}
	ca, _, caKey, _ := cert_test.NewTestCaCert(cert.Version2, cert.Curve_CURVE25519, time.Time{}, time.Time{}, nil, nil, nil)
	crt, _, _, _ := cert_test.NewTestCert(cert.Version2, cert.Curve_CURVE25519, ca, caKey, name, time.Time{}, time.Time{}, networks, unsafeNetworks, groups)
	fp, err := crt.Fingerprint()
	require.NoError(t, err)

	hm.unlockedAddHostInfo(&HostInfo{
		ConnectionState: &ConnectionState{
			peerCert: &cert.CachedCertificate{Certificate: crt, Fingerprint: fp},
		},
		vpnAddrs: addrs,
		relayState: RelayState{
			relayForByAddr: map[netip.Addr]*Relay{},
			relayForByIdx:  map[uint32]*Relay{},
		},
	}, &Interface{})
	return crt
}

func getHost(t *testing.T, h *infoAPIServer, addrParam string) (int, map[string]any) {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/v1/host?addr="+url.QueryEscape(addrParam), nil)
	w := httptest.NewRecorder()
	h.handleHost(w, r)
	return decodeResponse(t, w)
}

func decodeResponse(t *testing.T, w *httptest.ResponseRecorder) (int, map[string]any) {
	t.Helper()
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
	var body map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	return w.Code, body
}

func TestInfoAPIServer_handleHost(t *testing.T) {
	h, _ := newTestInfoAPIServer(t)
	h.pki = newTestPKI(t, "self", []netip.Addr{netip.MustParseAddr("10.0.0.1")})

	peerV4 := netip.MustParseAddr("10.0.0.99")
	peerV6 := netip.MustParseAddr("fd00::99")
	addTestPeer(t, h.hostMap, "laptop-alice", []netip.Addr{peerV4, peerV6},
		[]netip.Prefix{netip.MustParsePrefix("192.168.50.0/24")}, []string{"eng", "ssh"})
	addTestPeer(t, h.hostMap, "groupless", []netip.Addr{netip.MustParseAddr("10.0.0.77")}, nil, nil)

	// an established peer comes back with its full identity
	code, body := getHost(t, h, "10.0.0.99")
	require.Equal(t, http.StatusOK, code)
	assert.Equal(t, "laptop-alice", body["name"])
	assert.Equal(t, []any{"10.0.0.99", "fd00::99"}, body["vpnAddrs"])
	assert.Equal(t, []any{"10.0.0.99/24", "fd00::99/64"}, body["networks"])
	assert.Equal(t, []any{"192.168.50.0/24"}, body["unsafeNetworks"])
	assert.Equal(t, []any{"eng", "ssh"}, body["groups"])
	assert.NotEmpty(t, body["fingerprint"])
	assert.Equal(t, "2", fmt.Sprintf("%v", body["certVersion"]))
	assert.NotEmpty(t, body["notBefore"])
	assert.NotEmpty(t, body["notAfter"])

	// empty cert slices marshal as [] rather than null
	code, body = getHost(t, h, "10.0.0.77")
	require.Equal(t, http.StatusOK, code)
	require.NotNil(t, body["groups"])
	assert.Empty(t, body["groups"])
	require.NotNil(t, body["unsafeNetworks"])
	assert.Empty(t, body["unsafeNetworks"])

	// a port in addr is ignored so RemoteAddr can be passed through directly, including the
	// bracketed v6 and 4in6 forms
	for _, q := range []string{"10.0.0.99:54321", "[fd00::99]:443", "::ffff:10.0.0.99"} {
		code, body = getHost(t, h, q)
		require.Equal(t, http.StatusOK, code, "addr=%q", q)
		assert.Equal(t, "laptop-alice", body["name"], "addr=%q", q)
	}

	// our own address answers from the local cert state
	code, body = getHost(t, h, "10.0.0.1")
	require.Equal(t, http.StatusOK, code)
	assert.Equal(t, "self", body["name"])

	code, body = getHost(t, h, "10.0.0.42")
	assert.Equal(t, http.StatusNotFound, code)
	assert.NotEmpty(t, body["error"])

	// a tunnel mid-teardown (no peer cert) is treated as unknown
	h.hostMap.unlockedAddHostInfo(&HostInfo{
		ConnectionState: &ConnectionState{},
		vpnAddrs:        []netip.Addr{netip.MustParseAddr("10.0.0.66")},
		relayState: RelayState{
			relayForByAddr: map[netip.Addr]*Relay{},
			relayForByIdx:  map[uint32]*Relay{},
		},
	}, &Interface{})
	code, _ = getHost(t, h, "10.0.0.66")
	assert.Equal(t, http.StatusNotFound, code)

	code, body = getHost(t, h, "not-an-address")
	assert.Equal(t, http.StatusBadRequest, code)
	assert.NotEmpty(t, body["error"])

	r := httptest.NewRequest(http.MethodGet, "/v1/host", nil)
	w := httptest.NewRecorder()
	h.handleHost(w, r)
	code, body = decodeResponse(t, w)
	assert.Equal(t, http.StatusBadRequest, code)
	assert.NotEmpty(t, body["error"])
}

func TestInfoAPIServer_handleSelf(t *testing.T) {
	h, _ := newTestInfoAPIServer(t)
	h.pki = newTestPKI(t, "lighthouse", []netip.Addr{netip.MustParseAddr("10.0.0.1")})

	r := httptest.NewRequest(http.MethodGet, "/v1/self", nil)
	w := httptest.NewRecorder()
	h.handleSelf(w, r)
	code, body := decodeResponse(t, w)
	require.Equal(t, http.StatusOK, code)
	assert.Equal(t, "lighthouse", body["name"])
	assert.Equal(t, []any{"10.0.0.1"}, body["vpnAddrs"])

	// no cert state available should be an error, not a panic
	h.pki = nil
	w = httptest.NewRecorder()
	h.handleSelf(w, r)
	code, body = decodeResponse(t, w)
	assert.Equal(t, http.StatusInternalServerError, code)
	assert.NotEmpty(t, body["error"])
}

func unixHTTPClient(path string) *http.Client {
	return &http.Client{
		Timeout: time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", path)
			},
		},
	}
}

// waitForServe polls until a GET /v1/self through client succeeds
func waitForServe(t *testing.T, client *http.Client) {
	t.Helper()
	waitFor(t, func() bool {
		resp, err := client.Get("http://hostquery/v1/self")
		if err != nil {
			return false
		}
		resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	})
}

func skipIfNoUnixSockets(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("unix socket tests are not supported on windows CI")
	}
}

func TestInfoAPIServer_unixLifecycle(t *testing.T) {
	skipIfNoUnixSockets(t)
	h, c := newTestInfoAPIServer(t)
	h.pki = newTestPKI(t, "self", []netip.Addr{netip.MustParseAddr("10.0.0.1")})

	sock := filepath.Join(t.TempDir(), "hq.sock")
	setInfoAPIConfig(c, true, "unix://"+sock, "")
	require.NoError(t, h.reload(c, true))

	done := make(chan struct{})
	go func() {
		h.Start()
		close(done)
	}()

	client := unixHTTPClient(sock)
	waitForServe(t, client)

	fi, err := os.Stat(sock)
	require.NoError(t, err)
	assert.Equal(t, fs.FileMode(0o600), fi.Mode().Perm())

	resp, err := client.Get("http://hostquery/v1/host?addr=10.0.0.1")
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	h.Stop()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Start did not return after Stop")
	}
	_, err = os.Stat(sock)
	assert.True(t, os.IsNotExist(err), "socket file should be unlinked on shutdown")
}

func TestInfoAPIServer_staleSocket(t *testing.T) {
	skipIfNoUnixSockets(t)
	h, _ := newTestInfoAPIServer(t)
	sock := filepath.Join(t.TempDir(), "hq.sock")

	// simulate an unclean exit, a leftover socket file with no listener
	stale, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
	require.NoError(t, err)
	stale.SetUnlinkOnClose(false)
	require.NoError(t, stale.Close())
	_, err = os.Stat(sock)
	require.NoError(t, err, "stale socket file should exist")

	cfg := infoAPIConfig{addr: sock, socketMode: 0o600}
	ln, err := h.listen(cfg)
	require.NoError(t, err, "a stale socket should be removed and rebound")
	require.NoError(t, ln.Close())
}

func TestInfoAPIServer_existingFileNotReplaced(t *testing.T) {
	skipIfNoUnixSockets(t)
	h, _ := newTestInfoAPIServer(t)
	path := filepath.Join(t.TempDir(), "hq.sock")
	require.NoError(t, os.WriteFile(path, []byte("precious"), 0o600))

	cfg := infoAPIConfig{addr: path, socketMode: 0o600}
	_, err := h.listen(cfg)
	require.Error(t, err, "a non-socket file at the listen path must not be replaced")

	content, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "precious", string(content))
}

func TestInfoAPIServer_reload(t *testing.T) {
	skipIfNoUnixSockets(t)
	h, c := newTestInfoAPIServer(t)
	h.pki = newTestPKI(t, "self", []netip.Addr{netip.MustParseAddr("10.0.0.1")})
	dir := t.TempDir()
	sock1 := filepath.Join(dir, "hq1.sock")
	sock2 := filepath.Join(dir, "hq2.sock")

	// initial reload only records config, Control.Start is what launches the runtime
	setInfoAPIConfig(c, false, "unix://"+sock1, "")
	require.NoError(t, h.reload(c, true))
	assert.False(t, h.enabled.Load())
	h.runMu.Lock()
	assert.Nil(t, h.run)
	h.runMu.Unlock()

	// enabling via reload spawns the listener
	setInfoAPIConfig(c, true, "unix://"+sock1, "")
	require.NoError(t, h.reload(c, false))
	waitForServe(t, unixHTTPClient(sock1))

	// changing the listen path restarts on the new address
	setInfoAPIConfig(c, true, "unix://"+sock2, "")
	require.NoError(t, h.reload(c, false))
	waitForServe(t, unixHTTPClient(sock2))
	waitFor(t, func() bool {
		_, err := os.Stat(sock1)
		return os.IsNotExist(err)
	})

	// reloading an unchanged config does not restart the runtime
	h.runMu.Lock()
	rt := h.run
	h.runMu.Unlock()
	require.NoError(t, h.reload(c, false))
	h.runMu.Lock()
	assert.Same(t, rt, h.run)
	h.runMu.Unlock()

	// disabling stops the listener
	setInfoAPIConfig(c, false, "unix://"+sock2, "")
	require.NoError(t, h.reload(c, false))
	assert.False(t, h.enabled.Load())
	waitFor(t, func() bool {
		h.runMu.Lock()
		defer h.runMu.Unlock()
		return h.run == nil
	})
}
