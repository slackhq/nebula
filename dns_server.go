package nebula

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/miekg/dns"
	"github.com/slackhq/nebula/config"
)

type dnsServer struct {
	sync.RWMutex
	l       *slog.Logger
	ctx     context.Context
	dnsMap4 map[string]netip.Addr
	dnsMap6 map[string]netip.Addr
	hostMap *HostMap
	pki     *PKI

	// selfHost is the cached FQDN we last seeded for ourselves
	selfHost string

	mux *dns.ServeMux

	// enabled mirrors `lighthouse.serve_dns && lighthouse.am_lighthouse`.
	// Start, Add, and reload consult it so callers don't need to know the
	// gating rules. When it toggles off via reload, accumulated records are
	// cleared so a later re-enable starts with a fresh map populated from
	// new handshakes.
	enabled atomic.Bool

	serverMu sync.Mutex
	// listeners holds one entry per bound address. A single listen address
	// yields one entry; a "<nebula>" self-token expands to one per VPN
	// address (bind-ALL). addr keeps the RAW joined config string so reload's
	// sameAddr comparison is unaffected by expansion.
	listeners []*dnsListener
	addr      string
	// startGen tags each Start attempt so the one that stops serving (or bails
	// before binding) only clears d.listeners if a newer Start hasn't taken
	// over. Without this, a Start that fails to bind (or expands to zero VPN
	// addrs) would leave stale dead listeners in d.listeners, making reload see
	// running==true and no-op every same-addr SIGHUP, wedging DNS permanently.
	startGen uint64
}

// dnsListener pairs a dns.Server with its started channel. The channel is
// closed once the server has finished binding (or after ListenAndServe returns
// on a bind failure). Stop waits on it before calling Shutdown to avoid the
// miekg/dns "server not started" race where a Shutdown that arrives before bind
// completes is silently ignored, leaving the listener running forever. Each
// listener carries its own channel so the race fix holds per bound address.
type dnsListener struct {
	server  *dns.Server
	started chan struct{}
}

// newDnsServerFromConfig builds a dnsServer, applies the initial config, and
// registers a reload callback. The reload callback is registered before the
// initial config is applied, so a SIGHUP can later enable, fix, or disable
// DNS even if the initial application failed.
//
// The dnsServer internally gates on `lighthouse.serve_dns &&
// lighthouse.am_lighthouse`. Start and Add are safe to call unconditionally,
// they no-op when DNS isn't enabled. Each Start invocation owns a ctx-cancel
// watcher that tears the listener down on nebula shutdown. The returned
// pointer is always non-nil, even on error.
func newDnsServerFromConfig(ctx context.Context, l *slog.Logger, pki *PKI, hostMap *HostMap, c *config.C) (*dnsServer, error) {
	ds := &dnsServer{
		l:       l,
		ctx:     ctx,
		dnsMap4: make(map[string]netip.Addr),
		dnsMap6: make(map[string]netip.Addr),
		hostMap: hostMap,
		pki:     pki,
	}
	ds.mux = dns.NewServeMux()
	ds.mux.HandleFunc(".", ds.handleDnsRequest)

	c.RegisterReloadCallback(func(c *config.C) {
		if err := ds.reload(c, false); err != nil {
			ds.l.Error("Failed to reload DNS responder from config", "error", err)
		}
	})

	if err := ds.reload(c, true); err != nil {
		return ds, err
	}
	ds.seedSelf()
	return ds, nil
}

// reload applies the latest config and reconciles the running state with it:
//   - enabled toggled on  -> spawn a runner
//   - enabled toggled off -> stop the runner
//   - listen address changed (while running) -> restart on the new address
//   - everything else     -> no-op
//
// On the initial call it only records configuration; Control.Start is what
// launches the first runner via dnsStart.
func (d *dnsServer) reload(c *config.C, initial bool) error {
	wantsDns := c.GetBool("lighthouse.serve_dns", false)
	amLighthouse := c.GetBool("lighthouse.am_lighthouse", false)
	enabled := wantsDns && amLighthouse
	newAddr := getDnsServerAddr(c)

	d.serverMu.Lock()
	runningListeners := d.listeners
	running := len(runningListeners) > 0
	sameAddr := d.addr == newAddr
	d.addr = newAddr
	d.enabled.Store(enabled)
	d.serverMu.Unlock()

	if initial {
		if wantsDns && !amLighthouse {
			d.l.Warn("DNS server refusing to run because this host is not a lighthouse.")
		}
		return nil
	}

	if !enabled {
		if running {
			d.Stop()
		}
		// Drop any records that accumulated while enabled; a later re-enable
		// will repopulate from fresh handshakes and a fresh seedSelf.
		d.clearRecords()
		return nil
	}

	if !running {
		// Was disabled (or never started); bring it up now.
		go d.Start()
	} else if !sameAddr {
		d.shutdownListeners(runningListeners, "reload")
		// Old Start goroutine has now exited; bring up a fresh listener on the new address.
		go d.Start()
	}

	// Refresh the self entry every enabled reload so cert renewals that change our name or VPN addresses are picked up.
	d.seedSelf()
	return nil
}

// shutdownListeners shuts down every listener in the slice, waiting for each to
// finish binding first so Shutdown actually stops it rather than no-oping.
func (d *dnsServer) shutdownListeners(listeners []*dnsListener, reason string) {
	for _, ln := range listeners {
		d.shutdownServer(ln.server, ln.started, reason)
	}
}

// shutdownServer waits for the server to finish binding (so Shutdown actually
// stops it rather than no-oping) and then shuts it down.
func (d *dnsServer) shutdownServer(srv *dns.Server, started chan struct{}, reason string) {
	if srv == nil {
		return
	}
	if started != nil {
		<-started
	}
	if err := srv.Shutdown(); err != nil {
		d.l.Warn("Failed to shut down the DNS responder", "reason", reason, "error", err)
	}
}

// Start binds and serves the DNS responder. Blocks until Stop is called or the
// listeners error. Safe to call when DNS is disabled (returns immediately).
// This is what Control.dnsStart points at.
//
// Must be invoked after the tun device is active so that lighthouse.dns.host
// may bind to a nebula IP. That timing is also what lets the "<nebula>"
// self-token expand to this host's VPN addresses (bind-ALL): expansion happens
// here, at listener-start, reading the reload-safe cert state.
func (d *dnsServer) Start() {
	if !d.enabled.Load() {
		return
	}

	d.serverMu.Lock()
	if d.ctx.Err() != nil {
		d.serverMu.Unlock()
		return
	}
	rawAddr := d.addr
	d.startGen++
	myGen := d.startGen
	d.serverMu.Unlock()

	addrs, err := resolveSelfListenAddrs(rawAddr, d.pki.vpnAddrs())
	if err != nil {
		d.l.Warn("Failed to run the DNS responder", "error", err)
		// Drop the now-defunct listeners a prior reload shut down, so a later
		// same-addr SIGHUP retries instead of no-oping on stale state.
		d.clearListenersIfCurrent(myGen)
		return
	}
	d.startListeners(addrs, myGen)
}

// clearListenersIfCurrent nils out d.listeners, but only if no newer Start has
// superseded this one (identified by gen). This lets the Start that stopped
// serving reset the running state without clobbering a concurrent restart.
func (d *dnsServer) clearListenersIfCurrent(gen uint64) {
	d.serverMu.Lock()
	if d.startGen == gen {
		d.listeners = nil
	}
	d.serverMu.Unlock()
}

// startListeners binds and serves one dns.Server per already-expanded address,
// blocking until all of them return. Split from Start so tests can drive the
// multi-listener machinery with concrete addresses. A bind failure on one
// address is logged and the remaining listeners keep serving (log-and-continue,
// matching the single-listener behavior this refactor grew out of).
func (d *dnsServer) startListeners(addrs []string, myGen uint64) {
	listeners := make([]*dnsListener, len(addrs))
	for i, a := range addrs {
		started := make(chan struct{})
		listeners[i] = &dnsListener{
			started: started,
			server: &dns.Server{
				Addr:              a,
				Net:               "udp",
				Handler:           d.mux,
				NotifyStartedFunc: func() { close(started) },
			},
		}
	}

	d.serverMu.Lock()
	if d.ctx.Err() != nil || d.startGen != myGen {
		// Shutting down, or a newer Start has superseded us; don't install.
		d.serverMu.Unlock()
		return
	}
	d.listeners = listeners
	d.serverMu.Unlock()

	// Per-invocation ctx watcher. Exits when startListeners does, so we don't
	// leak a watcher per reload-driven restart.
	done := make(chan struct{})
	go func() {
		select {
		case <-d.ctx.Done():
			d.shutdownListeners(listeners, "shutdown")
		case <-done:
		}
	}()

	var wg sync.WaitGroup
	for _, ln := range listeners {
		wg.Add(1)
		go func(ln *dnsListener) {
			defer wg.Done()
			d.l.Info("Starting DNS responder", "dnsListener", ln.server.Addr)
			err := ln.server.ListenAndServe()

			// If the listener never bound (bind error) NotifyStartedFunc never
			// fires, so close started here to release any waiter on it.
			select {
			case <-ln.started:
			default:
				close(ln.started)
			}

			if err != nil {
				d.l.Warn("Failed to run the DNS responder", "error", err, "dnsListener", ln.server.Addr)
			}
		}(ln)
	}
	wg.Wait()
	close(done)

	// All listeners have stopped serving. Clear the running state (unless a
	// newer Start took over) so a same-addr reload re-runs Start instead of
	// treating the dead listeners as live. Matches stats' retry-on-unclean-exit.
	d.clearListenersIfCurrent(myGen)
}

// Stop shuts down all active listeners, if any. Idempotent.
func (d *dnsServer) Stop() {
	d.serverMu.Lock()
	listeners := d.listeners
	d.listeners = nil
	d.serverMu.Unlock()
	d.shutdownListeners(listeners, "stop")
}

// Query returns the address for the given name and query type. The second
// return value reports whether the name is known at all (in either A or AAAA),
// which lets callers distinguish NODATA from NXDOMAIN.
func (d *dnsServer) Query(q uint16, data string) (netip.Addr, bool) {
	data = strings.ToLower(data)
	d.RLock()
	defer d.RUnlock()
	addr4, haveV4 := d.dnsMap4[data]
	addr6, haveV6 := d.dnsMap6[data]
	nameExists := haveV4 || haveV6
	switch q {
	case dns.TypeA:
		if haveV4 {
			return addr4, nameExists
		}
	case dns.TypeAAAA:
		if haveV6 {
			return addr6, nameExists
		}
	}

	return netip.Addr{}, nameExists
}

func (d *dnsServer) QueryCert(data string) string {
	if len(data) < 2 {
		return ""
	}
	ip, err := netip.ParseAddr(data[:len(data)-1])
	if err != nil {
		return ""
	}

	// The hostmap only ever contains peers we have handshaked with, so it never carries an entry for ourselves.
	// Answer self lookups straight from the local cert state.
	if cs := d.certState(); cs != nil && cs.myVpnAddrsTable != nil && cs.myVpnAddrsTable.Contains(ip) {
		c := cs.GetDefaultCertificate()
		if c == nil {
			return ""
		}
		b, err := c.MarshalJSON()
		if err != nil {
			return ""
		}
		return string(b)
	}

	hostinfo := d.hostMap.QueryVpnAddr(ip)
	if hostinfo == nil {
		return ""
	}

	q := hostinfo.GetCert()
	if q == nil {
		return ""
	}

	b, err := q.Certificate.MarshalJSON()
	if err != nil {
		return ""
	}
	return string(b)
}

// clearRecords drops all DNS records, including the self entry.
func (d *dnsServer) clearRecords() {
	d.Lock()
	defer d.Unlock()
	clear(d.dnsMap4)
	clear(d.dnsMap6)
	d.selfHost = ""
}

// seedSelf inserts (or refreshes) a record for our own cert name pointing at our VPN addresses,
// so a single-lighthouse network can resolve the lighthouse's own hostname without the two-process workaround.
func (d *dnsServer) seedSelf() {
	if !d.enabled.Load() {
		return
	}
	cs := d.certState()
	if cs == nil {
		return
	}
	c := cs.GetDefaultCertificate()
	if c == nil {
		return
	}
	newHost := strings.ToLower(c.Name()) + "."

	d.Lock()
	defer d.Unlock()
	if d.selfHost != "" && d.selfHost != newHost {
		delete(d.dnsMap4, d.selfHost)
		delete(d.dnsMap6, d.selfHost)
	}
	d.selfHost = newHost
	delete(d.dnsMap4, newHost)
	delete(d.dnsMap6, newHost)
	haveV4, haveV6 := false, false
	for _, addr := range cs.myVpnAddrs {
		if addr.Is4() && !haveV4 {
			d.dnsMap4[newHost] = addr
			haveV4 = true
		} else if addr.Is6() && !haveV6 {
			d.dnsMap6[newHost] = addr
			haveV6 = true
		}
		if haveV4 && haveV6 {
			break
		}
	}
}

func (d *dnsServer) certState() *CertState {
	if d.pki == nil {
		return nil
	}
	return d.pki.getCertState()
}

// Add adds the first IPv4 and IPv6 address that appears in `addresses` as the record for `host`
func (d *dnsServer) Add(host string, addresses []netip.Addr) {
	if !d.enabled.Load() {
		return
	}
	host = strings.ToLower(host)
	d.Lock()
	defer d.Unlock()
	haveV4 := false
	haveV6 := false
	for _, addr := range addresses {
		if addr.Is4() && !haveV4 {
			d.dnsMap4[host] = addr
			haveV4 = true
		} else if addr.Is6() && !haveV6 {
			d.dnsMap6[host] = addr
			haveV6 = true
		}
		if haveV4 && haveV6 {
			break
		}
	}
}

func (d *dnsServer) isSelfNebulaOrLocalhost(addr string) bool {
	a, _, _ := net.SplitHostPort(addr)
	b, err := netip.ParseAddr(a)
	if err != nil {
		return false
	}

	if b.IsLoopback() {
		return true
	}

	cs := d.certState()
	if cs == nil || cs.myVpnAddrsTable == nil {
		return false
	}
	//if we found it in this table, it's good
	return cs.myVpnAddrsTable.Contains(b)
}

func (d *dnsServer) parseQuery(m *dns.Msg, w dns.ResponseWriter) {
	debugEnabled := d.l.Enabled(context.Background(), slog.LevelDebug)
	// Per RFC 2308 §2.2, a name that exists but has no record of the requested
	// type must be answered with NOERROR and an empty answer section (NODATA),
	// not NXDOMAIN (RFC 2308 §2.1), which is reserved for names that do not
	// exist at all.
	anyNameExists := false
	for _, q := range m.Question {
		switch q.Qtype {
		case dns.TypeA, dns.TypeAAAA:
			qType := dns.TypeToString[q.Qtype]
			if debugEnabled {
				d.l.Debug("DNS query", "type", qType, "name", q.Name)
			}
			ip, nameExists := d.Query(q.Qtype, q.Name)
			if nameExists {
				anyNameExists = true
			}
			if ip.IsValid() {
				rr, err := dns.NewRR(fmt.Sprintf("%s %s %s", q.Name, qType, ip))
				if err == nil {
					m.Answer = append(m.Answer, rr)
				}
			}
		case dns.TypeTXT:
			// We only answer these queries from nebula nodes or localhost
			if !d.isSelfNebulaOrLocalhost(w.RemoteAddr().String()) {
				return
			}
			if debugEnabled {
				d.l.Debug("DNS query", "type", "TXT", "name", q.Name)
			}
			ip := d.QueryCert(q.Name)
			if ip != "" {
				rr, err := dns.NewRR(fmt.Sprintf("%s TXT %s", q.Name, ip))
				if err == nil {
					m.Answer = append(m.Answer, rr)
				}
			}
		}
	}

	if len(m.Answer) == 0 && !anyNameExists {
		m.Rcode = dns.RcodeNameError
	}
}

func (d *dnsServer) handleDnsRequest(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = false

	switch r.Opcode {
	case dns.OpcodeQuery:
		d.parseQuery(m, w)
	}

	w.WriteMsg(m)
}

func getDnsServerAddr(c *config.C) string {
	dnsHost := strings.TrimSpace(c.GetString("lighthouse.dns.host", ""))
	// Old guidance was to provide the literal `[::]` in `lighthouse.dns.host` but that won't resolve.
	if dnsHost == "[::]" {
		dnsHost = "::"
	}
	return net.JoinHostPort(dnsHost, strconv.Itoa(c.GetInt("lighthouse.dns.port", 53)))
}
