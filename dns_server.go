package nebula

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"

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
	dnsMap  map[string]string
	hostMap *HostMap
}

func newDnsRecords(hostMap *HostMap) *dnsRecords {
	return &dnsRecords{
		dnsMap:  make(map[string]string),
		hostMap: hostMap,
	}
}

func (d *dnsRecords) Query(data string) string {
	d.RLock()
	defer d.RUnlock()
	if r, ok := d.dnsMap[strings.ToLower(data)]; ok {
		return r
	}
	return ""
}

func (d *dnsRecords) QueryCert(data string) string {
	ip, err := netip.ParseAddr(data[:len(data)-1])
	if err != nil {
		return ""
	}

	hostinfo := d.hostMap.QueryVpnIp(ip)
	if hostinfo == nil {
		return ""
	}

	q := hostinfo.GetCert()
	if q == nil {
		return ""
	}

	cert := q.Details
	c := fmt.Sprintf("\"Name: %s\" \"Ips: %s\" \"Subnets %s\" \"Groups %s\" \"NotBefore %s\" \"NotAfter %s\" \"PublicKey %x\" \"IsCA %t\" \"Issuer %s\"", cert.Name, cert.Ips, cert.Subnets, cert.Groups, cert.NotBefore, cert.NotAfter, cert.PublicKey, cert.IsCA, cert.Issuer)
	return c
}

func (d *dnsRecords) Add(host, data string) {
	d.Lock()
	defer d.Unlock()
	d.dnsMap[strings.ToLower(host)] = data
}

func parseQuery(l *logrus.Logger, m *dns.Msg, w dns.ResponseWriter) {
	for _, q := range m.Question {
		switch q.Qtype {
		case dns.TypeA:
			l.Debugf("Query for A %s", q.Name)
			ip := dnsR.Query(q.Name)
			if ip != "" {
				rr, err := dns.NewRR(fmt.Sprintf("%s A %s", q.Name, ip))
				if err == nil {
					m.Answer = append(m.Answer, rr)
				}
			}
		case dns.TypeTXT:
			a, _, _ := net.SplitHostPort(w.RemoteAddr().String())
			b, err := netip.ParseAddr(a)
			if err != nil {
				return
			}

			// We don't answer these queries from non nebula nodes or localhost
			//l.Debugf("Does %s contain %s", b, dnsR.hostMap.vpnCIDR)
			if !dnsR.hostMap.vpnCIDR.Contains(b) && a != "127.0.0.1" {
				return
			}
			l.Debugf("Query for TXT %s", q.Name)
			ip := dnsR.QueryCert(q.Name)
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

func handleDnsRequest(l *logrus.Logger, w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = false

	switch r.Opcode {
	case dns.OpcodeQuery:
		parseQuery(l, m, w)
	}

	w.WriteMsg(m)
}

func dnsMain(l *logrus.Logger, hostMap *HostMap, c *config.C) func() {
	dnsR = newDnsRecords(hostMap)

	// attach request handler func
	dns.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		handleDnsRequest(l, w, r)
	})

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
