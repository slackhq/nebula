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

func Test_getDnsServerAddr(t *testing.T) {
	c := config.NewC(nil)

	c.Settings["lighthouse"] = map[string]any{
		"dns": map[string]any{
			"host": "0.0.0.0",
			"port": "1",
		},
	}
	assert.Equal(t, "0.0.0.0:1", getDnsServerAddr(c))

	c.Settings["lighthouse"] = map[string]any{
		"dns": map[string]any{
			"host": "::",
			"port": "1",
		},
	}
	assert.Equal(t, "[::]:1", getDnsServerAddr(c))

	c.Settings["lighthouse"] = map[string]any{
		"dns": map[string]any{
			"host": "[::]",
			"port": "1",
		},
	}
	assert.Equal(t, "[::]:1", getDnsServerAddr(c))

	// Make sure whitespace doesn't mess us up
	c.Settings["lighthouse"] = map[string]any{
		"dns": map[string]any{
			"host": "[::] ",
			"port": "1",
		},
	}
	assert.Equal(t, "[::]:1", getDnsServerAddr(c))
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
	assert.Equal(t, "127.0.0.1:0", ds.addr)
	assert.Nil(t, ds.server)
}

func TestDnsServer_reload_initial_enabled(t *testing.T) {
	ds, c := newTestDnsServer(t)
	setDnsConfig(c, "127.0.0.1", "0", true, true)

	require.NoError(t, ds.reload(c, true))
	assert.True(t, ds.enabled.Load())
	assert.Equal(t, "127.0.0.1:0", ds.addr)
	// initial never starts a runner; that's Control.Start's job
	assert.Nil(t, ds.server)
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

	go ds.Start()
	waitForBind(t, ds)

	ds.serverMu.Lock()
	before := ds.server
	ds.serverMu.Unlock()
	require.NotNil(t, before)

	// Same address, so the running listener must be left alone rather than rebuilt under live queries
	require.NoError(t, ds.reload(c, false))
	assert.True(t, ds.enabled.Load())

	ds.serverMu.Lock()
	after := ds.server
	ds.serverMu.Unlock()
	assert.Same(t, before, after, "a same-address reload must not restart the listener")

	ds.Stop()
}

// The branch the old sameAddr test was accidentally hitting: enabled with nothing running means reload starts it.
func TestDnsServer_reload_whenNotRunning_starts(t *testing.T) {
	port := freeUDPPort(t)
	ds, c := newTestDnsServer(t)
	setDnsConfig(c, "127.0.0.1", port, true, true)

	// initial only records config, it never starts anything
	require.NoError(t, ds.reload(c, true))
	ds.serverMu.Lock()
	assert.Nil(t, ds.server, "the initial reload must not start a listener")
	ds.serverMu.Unlock()

	require.NoError(t, ds.reload(c, false))
	waitForBind(t, ds)

	ds.serverMu.Lock()
	assert.NotNil(t, ds.server, "a reload with nothing running should bring DNS up")
	ds.serverMu.Unlock()

	ds.Stop()
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

	waitFor(t, func() bool {
		ds.serverMu.Lock()
		started := ds.started
		ds.serverMu.Unlock()
		if started == nil {
			return false
		}
		select {
		case <-started:
			return true
		default:
			return false
		}
	})

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
		started := ds.started
		ds.serverMu.Unlock()
		if started == nil {
			return false
		}
		select {
		case <-started:
			return true
		default:
			return false
		}
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

// Two reloads in quick succession, or a HUP before Control.Start, can race two Starts at the same listener.
func TestDnsServer_Start_isIdempotent(t *testing.T) {
	port := freeUDPPort(t)
	ds, c := newTestDnsServer(t)
	setDnsConfig(c, "127.0.0.1", port, true, true)
	require.NoError(t, ds.reload(c, true))

	go ds.Start()
	waitForBind(t, ds)

	ds.serverMu.Lock()
	first := ds.server
	ds.serverMu.Unlock()
	require.NotNil(t, first)

	// If the second Start replaces the tracked server, Stop kills the wrong one and the port leaks
	done := make(chan struct{})
	go func() {
		ds.Start()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second * 5):
		t.Fatal("second Start never returned")
	}

	ds.serverMu.Lock()
	second := ds.server
	ds.serverMu.Unlock()
	assert.Same(t, first, second, "a second Start must not replace the running server")

	// The real proof, after Stop the port must actually be free
	ds.Stop()
	waitFor(t, func() bool {
		pc, err := net.ListenPacket("udp", "127.0.0.1:"+port)
		if err != nil {
			return false
		}
		_ = pc.Close()
		return true
	})
}

// An address change must actually end up listening on the new port. Start's guard refuses when a server is already
// installed, so reload has to clear the slot before shutting the old one down.
func TestDnsServer_reload_addrChange_restarts(t *testing.T) {
	first := freeUDPPort(t)
	second := freeUDPPort(t)

	ds, c := newTestDnsServer(t)
	setDnsConfig(c, "127.0.0.1", first, true, true)
	require.NoError(t, ds.reload(c, true))

	go ds.Start()
	waitForBind(t, ds)

	// Cycle a few times, the failure this guards against depends on which goroutine wins serverMu
	for i := range 8 {
		want := second
		if i%2 == 1 {
			want = first
		}
		setDnsConfig(c, "127.0.0.1", want, true, true)
		require.NoError(t, ds.reload(c, false))
		waitForBind(t, ds)

		ds.serverMu.Lock()
		srv := ds.server
		ds.serverMu.Unlock()
		require.NotNil(t, srv, "reload left DNS down instead of restarting it")
		require.Equal(t, "127.0.0.1:"+want, srv.Addr, "reload should be serving the new address")
	}

	// Land back on second so the port assertions below are meaningful
	setDnsConfig(c, "127.0.0.1", second, true, true)
	require.NoError(t, ds.reload(c, false))
	waitForBind(t, ds)

	// The old port must be released and the new one actually held
	waitFor(t, func() bool {
		pc, err := net.ListenPacket("udp", "127.0.0.1:"+first)
		if err != nil {
			return false
		}
		_ = pc.Close()
		return true
	})
	_, err := net.ListenPacket("udp", "127.0.0.1:"+second)
	assert.Error(t, err, "the new address should be bound by the DNS responder")

	ds.Stop()
}

// A listener that dies on its own must release the slot, or a later same-addr reload sees it as running and no-ops.
func TestDnsServer_Start_bindFailure_releasesSlot(t *testing.T) {
	port := freeUDPPort(t)
	blocker, err := net.ListenPacket("udp", "127.0.0.1:"+port)
	require.NoError(t, err)

	ds, c := newTestDnsServer(t)
	setDnsConfig(c, "127.0.0.1", port, true, true)
	require.NoError(t, ds.reload(c, true))

	ds.Start() // returns once the bind fails

	ds.serverMu.Lock()
	assert.Nil(t, ds.server, "a listener that failed to bind must not stay parked in the slot")
	ds.serverMu.Unlock()

	// With the slot released, a reload can retry once the port frees up
	require.NoError(t, blocker.Close())
	require.NoError(t, ds.reload(c, false))
	waitForBind(t, ds)

	ds.serverMu.Lock()
	assert.NotNil(t, ds.server, "a same-addr reload should retry after a failed bind")
	ds.serverMu.Unlock()

	ds.Stop()
}

// A disable that lands while Start is between its unlocked check and the guard must not leave a listener behind.
func TestDnsServer_Start_refusesWhenDisabledUnderLock(t *testing.T) {
	port := freeUDPPort(t)
	ds, c := newTestDnsServer(t)
	setDnsConfig(c, "127.0.0.1", port, true, true)
	require.NoError(t, ds.reload(c, true))
	require.True(t, ds.enabled.Load())

	// Holding serverMu parks Start on the lock, the only way to land the disable in that window on purpose
	ds.serverMu.Lock()

	done := make(chan struct{})
	go func() {
		ds.Start()
		close(done)
	}()

	select {
	case <-done:
		ds.serverMu.Unlock()
		t.Fatal("Start returned early, the test never exercised the window")
	case <-time.After(time.Millisecond * 100):
	}

	// The disable reload's critical section. It sees nothing running, so it never calls Stop.
	ds.enabled.Store(false)
	ds.serverMu.Unlock()

	select {
	case <-done:
	case <-time.After(time.Second * 5):
		t.Fatal("Start never returned")
	}

	ds.serverMu.Lock()
	assert.Nil(t, ds.server, "Start must not install a listener a disable already cancelled")
	ds.serverMu.Unlock()

	pc, err := net.ListenPacket("udp", "127.0.0.1:"+port)
	require.NoError(t, err, "an orphaned listener is still holding the port")
	_ = pc.Close()
}
