package nebula

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/gaissmai/bart"
	"github.com/miekg/dns"
	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/cert_test"
	"github.com/slackhq/nebula/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type stubDNSWriter struct{}

func (stubDNSWriter) LocalAddr() net.Addr { return &net.UDPAddr{} }
func (stubDNSWriter) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 5353}
}
func (stubDNSWriter) Write([]byte) (int, error) { return 0, nil }
func (stubDNSWriter) WriteMsg(*dns.Msg) error   { return nil }
func (stubDNSWriter) Close() error              { return nil }
func (stubDNSWriter) TsigStatus() error         { return nil }
func (stubDNSWriter) TsigTimersOnly(bool)       {}
func (stubDNSWriter) Hijack()                   {}

func TestParsequery(t *testing.T) {
	l := slog.New(slog.DiscardHandler)
	hostMap := &HostMap{}
	ds := &dnsServer{
		l:       l,
		dnsMap4: make(map[string]netip.Addr),
		dnsMap6: make(map[string]netip.Addr),
		hostMap: hostMap,
	}
	ds.enabled.Store(true)
	addrs := []netip.Addr{
		netip.MustParseAddr("1.2.3.4"),
		netip.MustParseAddr("1.2.3.5"),
		netip.MustParseAddr("fd01::24"),
		netip.MustParseAddr("fd01::25"),
	}
	ds.Add("test.com.com", addrs)
	ds.Add("v4only.com.com", []netip.Addr{netip.MustParseAddr("1.2.3.6")})
	ds.Add("v6only.com.com", []netip.Addr{netip.MustParseAddr("fd01::26")})

	m := &dns.Msg{}
	m.SetQuestion("test.com.com", dns.TypeA)
	ds.parseQuery(m, nil)
	assert.NotNil(t, m.Answer)
	assert.Equal(t, "1.2.3.4", m.Answer[0].(*dns.A).A.String())
	assert.Equal(t, dns.RcodeSuccess, m.Rcode)

	m = &dns.Msg{}
	m.SetQuestion("test.com.com", dns.TypeAAAA)
	ds.parseQuery(m, nil)
	assert.NotNil(t, m.Answer)
	assert.Equal(t, "fd01::24", m.Answer[0].(*dns.AAAA).AAAA.String())
	assert.Equal(t, dns.RcodeSuccess, m.Rcode)

	// A known name with no record of the requested type should return NODATA
	// (NOERROR with empty answer), not NXDOMAIN.
	m = &dns.Msg{}
	m.SetQuestion("v4only.com.com", dns.TypeAAAA)
	ds.parseQuery(m, nil)
	assert.Empty(t, m.Answer)
	assert.Equal(t, dns.RcodeSuccess, m.Rcode)

	m = &dns.Msg{}
	m.SetQuestion("v6only.com.com", dns.TypeA)
	ds.parseQuery(m, nil)
	assert.Empty(t, m.Answer)
	assert.Equal(t, dns.RcodeSuccess, m.Rcode)

	// An unknown name should still return NXDOMAIN.
	m = &dns.Msg{}
	m.SetQuestion("unknown.com.com", dns.TypeA)
	ds.parseQuery(m, nil)
	assert.Empty(t, m.Answer)
	assert.Equal(t, dns.RcodeNameError, m.Rcode)

	// short lookups should not fail
	m = &dns.Msg{}
	m.Question = []dns.Question{{Name: "", Qtype: dns.TypeTXT, Qclass: dns.ClassINET}}
	ds.parseQuery(m, stubDNSWriter{})
	assert.Empty(t, m.Answer)
	assert.Equal(t, dns.RcodeNameError, m.Rcode)

	m = &dns.Msg{}
	m.Question = []dns.Question{{Name: ".", Qtype: dns.TypeTXT, Qclass: dns.ClassINET}}
	ds.parseQuery(m, stubDNSWriter{})
	assert.Empty(t, m.Answer)
	assert.Equal(t, dns.RcodeNameError, m.Rcode)
}

func Test_getDnsServerAddrs(t *testing.T) {
	c := config.NewC(nil)

	c.Settings["lighthouse"] = map[string]any{
		"dns": map[string]any{
			"host": "0.0.0.0",
			"port": "1",
		},
	}
	assert.Equal(t, []string{"0.0.0.0:1"}, getDnsServerAddrs(c))

	c.Settings["lighthouse"] = map[string]any{
		"dns": map[string]any{
			"host": "::",
			"port": "1",
		},
	}
	assert.Equal(t, []string{"[::]:1"}, getDnsServerAddrs(c))

	c.Settings["lighthouse"] = map[string]any{
		"dns": map[string]any{
			"host": "[::]",
			"port": "1",
		},
	}
	assert.Equal(t, []string{"[::]:1"}, getDnsServerAddrs(c))

	// Make sure whitespace doesn't mess us up
	c.Settings["lighthouse"] = map[string]any{
		"dns": map[string]any{
			"host": "[::] ",
			"port": "1",
		},
	}
	assert.Equal(t, []string{"[::]:1"}, getDnsServerAddrs(c))

	// A list of hosts each gets joined with the shared port, in order.
	c.Settings["lighthouse"] = map[string]any{
		"dns": map[string]any{
			"host": []any{"0.0.0.0", "10.0.0.1", "fd00::1"},
			"port": "53",
		},
	}
	assert.Equal(t, []string{"0.0.0.0:53", "10.0.0.1:53", "[fd00::1]:53"}, getDnsServerAddrs(c))
}

func newTestDnsServer(t *testing.T) (*dnsServer, *config.C) {
	t.Helper()
	sl := slog.New(slog.DiscardHandler)
	ds := &dnsServer{
		l:       sl,
		ctx:     context.Background(),
		dnsMap4: make(map[string]netip.Addr),
		dnsMap6: make(map[string]netip.Addr),
		hostMap: &HostMap{},
	}
	ds.mux = dns.NewServeMux()
	ds.mux.HandleFunc(".", ds.handleDnsRequest)
	return ds, config.NewC(nil)
}

func setDnsConfig(c *config.C, host string, port string, amLighthouse, serveDns bool) {
	c.Settings["lighthouse"] = map[string]any{
		"am_lighthouse": amLighthouse,
		"serve_dns":     serveDns,
		"dns": map[string]any{
			"host": host,
			"port": port,
		},
	}
}

func TestDnsServer_reload_initial_disabled(t *testing.T) {
	ds, c := newTestDnsServer(t)
	setDnsConfig(c, "127.0.0.1", "0", true, false)

	require.NoError(t, ds.reload(c, true))
	assert.False(t, ds.enabled.Load())
	assert.Equal(t, []string{"127.0.0.1:0"}, ds.addrs)
	assert.Empty(t, ds.listeners)
}

func TestDnsServer_reload_initial_enabled(t *testing.T) {
	ds, c := newTestDnsServer(t)
	setDnsConfig(c, "127.0.0.1", "0", true, true)

	require.NoError(t, ds.reload(c, true))
	assert.True(t, ds.enabled.Load())
	assert.Equal(t, []string{"127.0.0.1:0"}, ds.addrs)
	// initial never starts a runner; that's Control.Start's job
	assert.Empty(t, ds.listeners)
}

func TestDnsServer_reload_initial_serveDnsWithoutLighthouse(t *testing.T) {
	ds, c := newTestDnsServer(t)
	setDnsConfig(c, "127.0.0.1", "0", false, true)

	require.NoError(t, ds.reload(c, true))
	// Wants DNS but isn't a lighthouse: gated off, no runner.
	assert.False(t, ds.enabled.Load())
}

func TestDnsServer_reload_sameAddr_noOp(t *testing.T) {
	port := freeUDPPort(t)
	ds, c := newTestDnsServer(t)
	setDnsConfig(c, "127.0.0.1", port, true, true)
	require.NoError(t, ds.reload(c, true))

	done := make(chan struct{})
	go func() {
		ds.Start()
		close(done)
	}()
	waitForBind(t, ds)

	ds.serverMu.Lock()
	before := ds.listeners
	ds.serverMu.Unlock()
	require.Len(t, before, 1)

	// Same address: reload must not tear down and rebuild the listener.
	require.NoError(t, ds.reload(c, false))
	assert.True(t, ds.enabled.Load())

	ds.serverMu.Lock()
	after := ds.listeners
	ds.serverMu.Unlock()
	require.Len(t, after, 1)
	assert.Same(t, before[0], after[0], "same-addr reload should not restart the listener")

	ds.Stop()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Start did not return after Stop")
	}
}

func TestDnsServer_StartStop_lifecycle(t *testing.T) {
	// Bind to a real (random) UDP port so we exercise the actual
	// ListenAndServe + Shutdown plumbing including the started-chan race fix.
	port := freeUDPPort(t)

	ds, c := newTestDnsServer(t)
	setDnsConfig(c, "127.0.0.1", port, true, true)
	require.NoError(t, ds.reload(c, true))

	done := make(chan struct{})
	go func() {
		ds.Start()
		close(done)
	}()

	waitForBind(t, ds)

	ds.Stop()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Start did not return after Stop")
	}
}

func TestDnsServer_Stop_beforeBind_doesNotHang(t *testing.T) {
	// Stop called immediately after Start should not deadlock even if bind
	// hasn't completed yet. This exercises the started-chan close-on-bind-fail
	// path: by binding to an obviously bad port (privileged) we get a fast
	// bind error before NotifyStartedFunc fires.
	ds, c := newTestDnsServer(t)
	// Use a port that should fail to bind (negative would be invalid, use a
	// host that won't resolve to ensure listenUDP fails quickly).
	setDnsConfig(c, "256.256.256.256", "53", true, true)
	require.NoError(t, ds.reload(c, true))

	done := make(chan struct{})
	go func() {
		ds.Start()
		close(done)
	}()

	// Give Start a moment to attempt the bind and fail.
	select {
	case <-done:
		// Bind failed and Start returned; Stop should be a no-op.
	case <-time.After(time.Second):
		t.Fatal("Start did not return after a bad bind")
	}

	stopped := make(chan struct{})
	go func() {
		ds.Stop()
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("Stop hung after a failed bind")
	}
}

// newTestPKI builds a minimal *PKI with a single v1 cert whose name and
// VPN addresses are caller-provided, suitable for exercising seedSelf and
// QueryCert self handling.
func newTestPKI(t *testing.T, name string, addrs []netip.Addr) *PKI {
	t.Helper()
	networks := make([]netip.Prefix, 0, len(addrs))
	for _, a := range addrs {
		bits := 32
		if a.Is6() {
			bits = 128
		}
		networks = append(networks, netip.PrefixFrom(a, bits))
	}
	ca, _, caKey, _ := cert_test.NewTestCaCert(cert.Version2, cert.Curve_CURVE25519, time.Time{}, time.Time{}, nil, nil, nil)
	c, _, _, _ := cert_test.NewTestCert(cert.Version2, cert.Curve_CURVE25519, ca, caKey, name, time.Time{}, time.Time{}, networks, nil, nil)

	addrsTable := new(bart.Lite)
	for _, a := range addrs {
		addrsTable.Insert(netip.PrefixFrom(a, a.BitLen()))
	}

	cs := &CertState{
		v2Cert:            c,
		initiatingVersion: cert.Version2,
		myVpnAddrs:        addrs,
		myVpnAddrsTable:   addrsTable,
	}
	pki := &PKI{}
	pki.cs.Store(cs)
	return pki
}

func TestDnsServer_seedSelf_addsOwnRecord(t *testing.T) {
	ds, c := newTestDnsServer(t)
	myV4 := netip.MustParseAddr("10.0.0.1")
	myV6 := netip.MustParseAddr("fd00::1")
	ds.pki = newTestPKI(t, "lighthouse", []netip.Addr{myV4, myV6})
	setDnsConfig(c, "127.0.0.1", "0", true, true)
	require.NoError(t, ds.reload(c, true))

	ds.seedSelf()
	got4, exists := ds.Query(dns.TypeA, "lighthouse.")
	assert.True(t, exists)
	assert.Equal(t, myV4, got4)
	got6, exists := ds.Query(dns.TypeAAAA, "lighthouse.")
	assert.True(t, exists)
	assert.Equal(t, myV6, got6)
}

func TestDnsServer_seedSelf_disabled_noOp(t *testing.T) {
	ds, c := newTestDnsServer(t)
	ds.pki = newTestPKI(t, "lighthouse", []netip.Addr{netip.MustParseAddr("10.0.0.1")})
	setDnsConfig(c, "127.0.0.1", "0", true, false)
	require.NoError(t, ds.reload(c, true))

	ds.seedSelf()
	_, exists := ds.Query(dns.TypeA, "lighthouse.")
	assert.False(t, exists)
}

func TestDnsServer_clearRecords_dropsSelfHost(t *testing.T) {
	ds, c := newTestDnsServer(t)
	ds.pki = newTestPKI(t, "lighthouse", []netip.Addr{netip.MustParseAddr("10.0.0.1")})
	setDnsConfig(c, "127.0.0.1", "0", true, true)
	require.NoError(t, ds.reload(c, true))
	ds.seedSelf()
	require.NotEmpty(t, ds.selfHost)

	ds.clearRecords()
	assert.Empty(t, ds.selfHost)
	_, exists := ds.Query(dns.TypeA, "lighthouse.")
	assert.False(t, exists)
}

func TestDnsServer_QueryCert_returnsOwnCert(t *testing.T) {
	ds, _ := newTestDnsServer(t)
	myV4 := netip.MustParseAddr("10.0.0.1")
	ds.pki = newTestPKI(t, "lighthouse", []netip.Addr{myV4})

	got := ds.QueryCert(myV4.String() + ".")
	assert.NotEmpty(t, got, "TXT lookup of our own VPN address should return our cert")

	other := netip.MustParseAddr("10.0.0.99")
	assert.Empty(t, ds.QueryCert(other.String()+"."), "unknown peer IP should return nothing")
}

func TestDnsServer_reload_disable_stopsRunningServer(t *testing.T) {
	port := freeUDPPort(t)
	ds, c := newTestDnsServer(t)
	setDnsConfig(c, "127.0.0.1", port, true, true)
	require.NoError(t, ds.reload(c, true))

	startReturned := make(chan struct{})
	go func() {
		ds.Start()
		close(startReturned)
	}()
	waitForBind(t, ds)

	// Toggle serve_dns off; reload should shut the running server down.
	setDnsConfig(c, "127.0.0.1", port, true, false)
	require.NoError(t, ds.reload(c, false))
	select {
	case <-startReturned:
	case <-time.After(5 * time.Second):
		t.Fatal("Start did not return after reload disabled DNS")
	}
	assert.False(t, ds.enabled.Load())
}

func TestDnsServer_reload_multiHost_recordsAllAddrs(t *testing.T) {
	ds, c := newTestDnsServer(t)
	c.Settings["lighthouse"] = map[string]any{
		"am_lighthouse": true,
		"serve_dns":     true,
		"dns": map[string]any{
			"host": []any{"10.0.0.1", "fd00::1"},
			"port": "53",
		},
	}
	require.NoError(t, ds.reload(c, true))
	// Each host is joined with the shared port; IPv6 is bracketed.
	assert.Equal(t, []string{"10.0.0.1:53", "[fd00::1]:53"}, ds.addrs)
}

// TestDnsServer_startListeners_multiAddr is the regression test for the
// per-listener started-chan machinery: several servers bind, each answers
// queries via the shared mux, and Stop tears all of them down without hanging.
func TestDnsServer_startListeners_multiAddr(t *testing.T) {
	ds, _ := newTestDnsServer(t)
	ds.enabled.Store(true)
	ds.Add("multi.example.", []netip.Addr{netip.MustParseAddr("10.9.8.7")})

	addrs := []string{freeUDPPortOn(t, "127.0.0.1")}
	if v6LoopbackAvailable() {
		// Exercises IPv6 bracketing end-to-end (the bind-ALL shape a token
		// with a v6 VPN address produces).
		addrs = append(addrs, freeUDPPortOn(t, "::1"))
	}

	ds.startGen++
	gen := ds.startGen
	done := make(chan struct{})
	go func() {
		ds.startListeners(addrs, gen)
		close(done)
	}()
	waitForBind(t, ds)
	require.Len(t, ds.listeners, len(addrs))

	for _, a := range addrs {
		resp := queryDNS(t, a, "multi.example.", dns.TypeA)
		require.NotEmpty(t, resp.Answer, "listener %s should answer", a)
		assert.Equal(t, "10.9.8.7", resp.Answer[0].(*dns.A).A.String())
	}

	ds.Stop()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("startListeners did not return after Stop")
	}
}

// TestDnsServer_Start_noAddrs_clearsListeners is the regression test for the
// reload-wedge: a Start that bails before binding (here, no configured listen
// address) must clear the defunct listeners a prior reload left behind,
// otherwise reload sees running==true and no-ops every subsequent same-addr
// SIGHUP, leaving DNS dead forever.
func TestDnsServer_Start_noAddrs_clearsListeners(t *testing.T) {
	ds, _ := newTestDnsServer(t)
	ds.enabled.Store(true)
	ds.addrs = nil
	// Simulate the stale state a prior reload's shutdownListeners leaves: the
	// slice still references now-defunct listeners.
	ds.listeners = []*dnsListener{{server: &dns.Server{}, started: make(chan struct{})}}

	ds.Start()

	require.Nil(t, ds.listeners, "Start with no addrs must clear stale listeners so reload retries")
}

// TestDnsServer_startListeners_allBindsFail_clearsListeners covers the other
// staleness path: when every expanded address fails to bind, startListeners
// must not leave the dead listeners installed.
func TestDnsServer_startListeners_allBindsFail_clearsListeners(t *testing.T) {
	ds, _ := newTestDnsServer(t)
	ds.enabled.Store(true)

	// Occupy a UDP port, then try to bind it so ListenAndServe fails.
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer conn.Close()
	busy := conn.LocalAddr().String()

	ds.startGen++
	gen := ds.startGen
	done := make(chan struct{})
	go func() {
		ds.startListeners([]string{busy}, gen)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("startListeners did not return after all binds failed")
	}
	require.Nil(t, ds.listeners, "all-binds-failed must clear listeners so reload retries")
}

func queryDNS(t *testing.T, addr, name string, qtype uint16) *dns.Msg {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(name, qtype)
	c := &dns.Client{Net: "udp", Timeout: 2 * time.Second}
	resp, _, err := c.Exchange(m, addr)
	require.NoError(t, err)
	return resp
}

func v6LoopbackAvailable() bool {
	conn, err := net.ListenPacket("udp", "[::1]:0")
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func freeUDPPortOn(t *testing.T, host string) string {
	t.Helper()
	conn, err := net.ListenPacket("udp", net.JoinHostPort(host, "0"))
	require.NoError(t, err)
	port := conn.LocalAddr().(*net.UDPAddr).Port
	require.NoError(t, conn.Close())
	return net.JoinHostPort(host, strconv.Itoa(port))
}

func freeUDPPort(t *testing.T) string {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	port := conn.LocalAddr().(*net.UDPAddr).Port
	require.NoError(t, conn.Close())
	return strconv.Itoa(port)
}

func waitForBind(t *testing.T, ds *dnsServer) {
	t.Helper()
	waitFor(t, func() bool {
		ds.serverMu.Lock()
		listeners := ds.listeners
		ds.serverMu.Unlock()
		if len(listeners) == 0 {
			return false
		}
		for _, ln := range listeners {
			select {
			case <-ln.started:
			default:
				return false
			}
		}
		return true
	})
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("timed out waiting for condition")
}
