package nebula

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/iputil"
)

// This whole thing should be rewritten to use context

var dnsR *dnsRecords
var dnsServer *dns.Server
var dnsAddr string

type dnsRecords struct {
	sync.RWMutex
	dnsMap             map[string]string
	hostMap            *HostMap
	dnsWildcardEnabled bool
	dnsWildcardLimit   int
}

func newDnsRecords(hostMap *HostMap) *dnsRecords {
	return &dnsRecords{
		dnsMap:             make(map[string]string),
		hostMap:            hostMap,
		dnsWildcardEnabled: false,
		dnsWildcardLimit:   5,
	}
}

func (d *dnsRecords) Query(data string) string {
	d.RLock()

	if d.dnsWildcardEnabled {
		hostParts := strings.SplitN(data, ".", d.dnsWildcardLimit+1)
		for i := range hostParts {
			if r, ok := d.dnsMap[strings.Join(hostParts[i:], ".")]; ok {
				d.RUnlock()
				return r
			}
		}
	} else {
		if r, ok := d.dnsMap[data]; ok {
			d.RUnlock()
			return r
		}
	}

	d.RUnlock()
	return ""
}

func (d *dnsRecords) QueryCert(data string) string {
	ip := net.ParseIP(data[:len(data)-1])
	if ip == nil {
		return ""
	}
	iip := iputil.Ip2VpnIp(ip)
	hostinfo, err := d.hostMap.QueryVpnIp(iip)
	if err != nil {
		return ""
	}
	q := hostinfo.GetCert()
	if q == nil {
		return ""
	}
	cert := q.Details
	c := fmt.Sprintf("\"Name: %s\" \"Ips: %s\" \"Subnets %s\" \"Groups %s\" \"NotBefore %s\" \"NotAFter %s\" \"PublicKey %x\" \"IsCA %t\" \"Issuer %s\"", cert.Name, cert.Ips, cert.Subnets, cert.Groups, cert.NotBefore, cert.NotAfter, cert.PublicKey, cert.IsCA, cert.Issuer)
	return c
}

func (d *dnsRecords) Add(host, data string) {
	d.Lock()
	d.dnsMap[host] = data
	d.Unlock()
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
			b := net.ParseIP(a)
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
	dnsR.dnsWildcardEnabled = c.GetBool("lighthouse.dns.wildcard", false)
	dnsR.dnsWildcardLimit = c.GetInt("lighthouse.dns.wildcard_limit", 5)

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
	return c.GetString("lighthouse.dns.host", "") + ":" + strconv.Itoa(c.GetInt("lighthouse.dns.port", 53))
}

func startDns(l *logrus.Logger, c *config.C) {
	dnsAddr = getDnsServerAddr(c)
	dnsServer = &dns.Server{Addr: dnsAddr, Net: "udp"}
	l.WithField("dnsListener", dnsAddr).Infof("Starting DNS responder")
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
