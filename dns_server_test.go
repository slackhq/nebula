package nebula

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/miekg/dns"
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
	ds, c := newTestDnsServer(t)
	setDnsConfig(c, "127.0.0.1", "0", true, true)

	require.NoError(t, ds.reload(c, true))
	// No server running yet, no addr change. Reload should not spawn anything.
	require.NoError(t, ds.reload(c, false))
	assert.True(t, ds.enabled.Load())
	assert.Nil(t, ds.server)
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
