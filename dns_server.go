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

	"github.com/gaissmai/bart"
	"github.com/miekg/dns"
	"github.com/slackhq/nebula/config"
)

type dnsServer struct {
	sync.RWMutex
	l               *slog.Logger
	ctx             context.Context
	dnsMap4         map[string]netip.Addr
	dnsMap6         map[string]netip.Addr
	hostMap         *HostMap
	myVpnAddrsTable *bart.Lite

	mux *dns.ServeMux

	// enabled mirrors `lighthouse.serve_dns && lighthouse.am_lighthouse`.
	// Start, Add, and reload consult it so callers don't need to know the
	// gating rules. When it toggles off via reload, accumulated records are
	// cleared so a later re-enable starts with a fresh map populated from
	// new handshakes.
	enabled atomic.Bool

	serverMu sync.Mutex
	server   *dns.Server
	// started is closed once `server` has finished binding (or after
	// ListenAndServe returns on a bind failure). Stop waits on it before
	// calling Shutdown to avoid the miekg/dns "server not started" race
	// where a Shutdown that arrives before bind completes is silently
	// ignored, leaving the listener running forever.
	started chan struct{}
	addr    string
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
func newDnsServerFromConfig(ctx context.Context, l *slog.Logger, cs *CertState, hostMap *HostMap, c *config.C) (*dnsServer, error) {
	ds := &dnsServer{
		l:               l,
		ctx:             ctx,
		dnsMap4:         make(map[string]netip.Addr),
		dnsMap6:         make(map[string]netip.Addr),
		hostMap:         hostMap,
		myVpnAddrsTable: cs.myVpnAddrsTable,
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
	running := d.server
	runningStarted := d.started
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
		if running != nil {
			d.Stop()
		}
		// Drop any records that accumulated while enabled; a later re-enable
		// will repopulate from fresh handshakes.
		d.clearRecords()
		return nil
	}

	if running == nil {
		// Was disabled (or never started); bring it up now.
		go d.Start()
		return nil
	}

	if sameAddr {
		return nil
	}

	d.shutdownServer(running, runningStarted, "reload")
	// Old Start goroutine has now exited; bring up a fresh listener on the
	// new address.
	go d.Start()
	return nil
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

// Start binds and serves the DNS responder. Blocks until Stop is called or
// the listener errors. Safe to call when DNS is disabled (returns
// immediately). This is what Control.dnsStart points at.
//
// Must be invoked after the tun device is active so that lighthouse.dns.host
// may bind to a nebula IP.
func (d *dnsServer) Start() {
	if !d.enabled.Load() {
		return
	}

	started := make(chan struct{})
	d.serverMu.Lock()
	if d.ctx.Err() != nil {
		d.serverMu.Unlock()
		return
	}
	addr := d.addr
	server := &dns.Server{
		Addr:              addr,
		Net:               "udp",
		Handler:           d.mux,
		NotifyStartedFunc: func() { close(started) },
	}
	d.server = server
	d.started = started
	d.serverMu.Unlock()

	// Per-invocation ctx watcher. Exits when Start does, so we don't leak a
	// watcher per reload-driven restart.
	done := make(chan struct{})
	go func() {
		select {
		case <-d.ctx.Done():
			d.shutdownServer(server, started, "shutdown")
		case <-done:
		}
	}()

	d.l.Info("Starting DNS responder", "dnsListener", addr)
	err := server.ListenAndServe()
	close(done)

	// If the listener never bound (bind error) NotifyStartedFunc never fires,
	// so close started here to release any Stop caller waiting on it.
	select {
	case <-started:
	default:
		close(started)
	}

	if err != nil {
		d.l.Warn("Failed to run the DNS responder", "error", err)
	}
}

// Stop shuts down the active server, if any. Idempotent.
func (d *dnsServer) Stop() {
	d.serverMu.Lock()
	srv := d.server
	started := d.started
	d.server = nil
	d.started = nil
	d.serverMu.Unlock()
	d.shutdownServer(srv, started, "stop")
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

// clearRecords drops all DNS records.
func (d *dnsServer) clearRecords() {
	d.Lock()
	defer d.Unlock()
	clear(d.dnsMap4)
	clear(d.dnsMap6)
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

	//if we found it in this table, it's good
	return d.myVpnAddrsTable.Contains(b)
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
