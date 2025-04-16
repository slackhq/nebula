package nebula

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"

	"github.com/gaissmai/bart"
	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/config"
)

// This whole thing should be rewritten to use context

var dnsR *dnsRecords
var dnsServer *dns.Server
var dnsAddr string

type dnsRecords struct {
	sync.RWMutex
	l               *logrus.Logger
	dnsMap4         map[string]netip.Addr
	dnsMap6         map[string]netip.Addr
	hostMap         *HostMap
	myVpnAddrsTable *bart.Lite
}

func newDnsRecords(l *logrus.Logger, cs *CertState, hostMap *HostMap) *dnsRecords {
	return &dnsRecords{
		l:               l,
		dnsMap4:         make(map[string]netip.Addr),
		dnsMap6:         make(map[string]netip.Addr),
		hostMap:         hostMap,
		myVpnAddrsTable: cs.myVpnAddrsTable,
	}
}

func (d *dnsRecords) Query(q uint16, data string) netip.Addr {
	data = strings.ToLower(data)
	d.RLock()
	defer d.RUnlock()
	switch q {
	case dns.TypeA:
		if r, ok := d.dnsMap4[data]; ok {
			return r
		}
	case dns.TypeAAAA:
		if r, ok := d.dnsMap6[data]; ok {
			return r
		}
	}

	return netip.Addr{}
}

func (d *dnsRecords) QueryCert(data string) string {
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

// Add adds the first IPv4 and IPv6 address that appears in `addresses` as the record for `host`
func (d *dnsRecords) Add(host string, addresses []netip.Addr) {
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

func (d *dnsRecords) isSelfNebulaOrLocalhost(addr string) bool {
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

func (d *dnsRecords) parseQuery(m *dns.Msg, w dns.ResponseWriter) {
	for _, q := range m.Question {
		switch q.Qtype {
		case dns.TypeA, dns.TypeAAAA:
			qType := dns.TypeToString[q.Qtype]
			d.l.Debugf("Query for %s %s", qType, q.Name)
			ip := d.Query(q.Qtype, q.Name)
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
			d.l.Debugf("Query for TXT %s", q.Name)
			ip := d.QueryCert(q.Name)
			if ip != "" {
				rr, err := dns.NewRR(fmt.Sprintf("%s TXT %s", q.Name, ip))
				if err == nil {
					m.Answer = append(m.Answer, rr)
				}
			}
		}
	}

	if len(m.Answer) == 0 {
		m.Rcode = dns.RcodeNameError
	}
}

func (d *dnsRecords) handleDnsRequest(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = false

	switch r.Opcode {
	case dns.OpcodeQuery:
		d.parseQuery(m, w)
	}

	w.WriteMsg(m)
}

func dnsMain(l *logrus.Logger, cs *CertState, hostMap *HostMap, c *config.C) func() {
	dnsR = newDnsRecords(l, cs, hostMap)

	// attach request handler func
	dns.HandleFunc(".", dnsR.handleDnsRequest)

	c.RegisterReloadCallback(func(c *config.C) {
		reloadDns(l, c)
	})

	return func() {
		startDns(l, c)
	}
}

func getDnsServerAddr(c *config.C) string {
	dnsHost := strings.TrimSpace(c.GetString("lighthouse.dns.host", ""))
	// Old guidance was to provide the literal `[::]` in `lighthouse.dns.host` but that won't resolve.
	if dnsHost == "[::]" {
		dnsHost = "::"
	}
	return net.JoinHostPort(dnsHost, strconv.Itoa(c.GetInt("lighthouse.dns.port", 53)))
}

func startDns(l *logrus.Logger, c *config.C) {
	dnsAddr = getDnsServerAddr(c)
	dnsServer = &dns.Server{Addr: dnsAddr, Net: "udp"}
	l.WithField("dnsListener", dnsAddr).Info("Starting DNS responder")
	err := dnsServer.ListenAndServe()
	defer dnsServer.Shutdown()
	if err != nil {
		l.Errorf("Failed to start server: %s\n ", err.Error())
	}
}

func reloadDns(l *logrus.Logger, c *config.C) {
	if dnsAddr == getDnsServerAddr(c) {
		l.Debug("No DNS server config change detected")
		return
	}

	l.Debug("Restarting DNS server")
	dnsServer.Shutdown()
	go startDns(l, c)
}
