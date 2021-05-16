package nebula

import (
	"fmt"
	"net"
	"strconv"
	"sync"
	"strings"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

// This whole thing should be rewritten to use context

var dnsR *dnsRecords
var dnsServer *dns.Server
var dnsAddr string
var dnsZones []string
var dnsRespondToFiltered bool

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
	if r, ok := d.dnsMap[data]; ok {
		d.RUnlock()
		return r
	}
	d.RUnlock()
	return ""
}

func (d *dnsRecords) QueryCert(data string) string {
	ip := net.ParseIP(data[:len(data)-1])
	if ip == nil {
		return ""
	}
	iip := ip2int(ip)
	hostinfo, err := d.hostMap.QueryVpnIP(iip)
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

func zoneMatches(zones []string, qname string) string {
	zone := ""
	for _, zname := range zones {
		if dns.IsSubDomain(zname, qname) {
			if len(zname) > len(zone) {
				zone = zname
			}
		}
	}
	return zone
}

func parseQuery(l *logrus.Logger, m *dns.Msg, w dns.ResponseWriter) error {
	for _, q := range m.Question {
		zone := zoneMatches(dnsZones, q.Name)
		qtype := dns.Type(q.Qtype).String()
		entry := l.WithField("from", w.RemoteAddr().String()).WithField("name", q.Name).WithField("type", qtype)
		// Only respond to requests with name matching the correct zone
		// Exception is responding to TXT records for a nebula IP
		if len(dnsZones) > 0 && zone == "" && q.Qtype != dns.TypeTXT {
			entry.Debug("Rejected DNS query")
			return fmt.Errorf("Rejected query")
		}
		switch q.Qtype {
		case dns.TypeA:
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
				entry.Debug("Rejected DNS query")
				return fmt.Errorf("Rejected query")
			}
			ip := dnsR.QueryCert(q.Name)
			if ip != "" {
				rr, err := dns.NewRR(fmt.Sprintf("%s TXT %s", q.Name, ip))
				if err == nil {
					m.Answer = append(m.Answer, rr)
				}
			}
		}
		entry.Debug("Accepted DNS query")
	}
	return nil
}

func handleDnsRequest(l *logrus.Logger, w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = false

	switch r.Opcode {
	case dns.OpcodeQuery:
		err := parseQuery(l, m, w)
		if err != nil && !dnsRespondToFiltered {
		       return
		}
	default:
		if !dnsRespondToFiltered {
			return
		}
	}

	w.WriteMsg(m)
}

func dnsMain(l *logrus.Logger, hostMap *HostMap, c *Config) func() {
	dnsR = newDnsRecords(hostMap)

	// attach request handler func
	dns.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		handleDnsRequest(l, w, r)
	})

	c.RegisterReloadCallback(func(c *Config) {
		reloadDns(l, c)
	})

	return func() {
		startDns(l, c)
	}
}

func getDnsServerAddr(c *Config) string {
	return c.GetString("lighthouse.dns.host", "") + ":" + strconv.Itoa(c.GetInt("lighthouse.dns.port", 53))
}

func getDnsZones(c *Config) []string {
	zones := c.GetStringSlice("lighthouse.dns.zones", []string{})
	for i := range zones {
		zones[i] = strings.ToLower(dns.Fqdn(zones[i]))
	}
	return zones
}

func getDnsFilterResponse(c *Config) bool {
	return c.GetBool("lighthouse.dns.respond_to_filtered", true)
}

func startDns(l *logrus.Logger, c *Config) {
	dnsAddr = getDnsServerAddr(c)
	dnsZones = getDnsZones(c)
	dnsServer = &dns.Server{Addr: dnsAddr, Net: "udp"}
	dnsRespondToFiltered = getDnsFilterResponse(c)
	l.WithField("dnsListener", dnsAddr).Infof("Starting DNS responder")
	err := dnsServer.ListenAndServe()
	defer dnsServer.Shutdown()
	if err != nil {
		l.Errorf("Failed to start server: %s\n ", err.Error())
	}
}

func Equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}

func reloadDns(l *logrus.Logger, c *Config) {
	if dnsAddr == getDnsServerAddr(c) && Equal(dnsZones, getDnsZones(c)) && dnsRespondToFiltered == getDnsFilterResponse(c) {
		l.Debug("No DNS server config change detected")
		return
	}

	l.Debug("Restarting DNS server")
	dnsServer.Shutdown()
	go startDns(l, c)
}
