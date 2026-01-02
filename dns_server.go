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
	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/config"
)

// This whole thing should be rewritten to use context

var dnsR *dnsRecords
var dnsServer *dns.Server
var dnsAddr string
var dnsSuffix string

type dnsRecords struct {
	sync.RWMutex
	l      *logrus.Logger
	dnsMap map[dns.Question][]dns.RR
}

func newDnsRecords(l *logrus.Logger) *dnsRecords {
	return &dnsRecords{
		l:      l,
		dnsMap: make(map[dns.Question][]dns.RR),
	}
}

func (d *dnsRecords) addA(name string, addresses []netip.Addr) {
	q := dns.Question{Name: name, Qclass: dns.ClassINET, Qtype: dns.TypeA}
	d.dnsMap[q] = nil

	for _, addr := range addresses {
		if addr.Is4() {
			qType := dns.TypeToString[q.Qtype]
			rr, err := dns.NewRR(fmt.Sprintf("%s %s %s", name, qType, addr.String()))
			if err == nil {
				d.dnsMap[q] = append(d.dnsMap[q], rr)
				d.l.Debugf("DNS record added %s", rr.String())
			}
		}
	}
} 

func (d *dnsRecords) addAAAA(name string, addresses []netip.Addr) {
	q := dns.Question{Name: name, Qclass: dns.ClassINET, Qtype: dns.TypeAAAA}
	d.dnsMap[q] = nil

	for _, addr := range addresses {
		if addr.Is6() {
			qType := dns.TypeToString[q.Qtype]
			rr, err := dns.NewRR(fmt.Sprintf("%s %s %s", name, qType, addr.String()))
			if err == nil {
				d.dnsMap[q] = append(d.dnsMap[q], rr)
				d.l.Debugf("DNS record added %s", rr.String())
			}
		}
	}
} 

func (d *dnsRecords) addPTR(name string, addresses []netip.Addr) {
	for _, addr := range addresses {
		arpa, err := dns.ReverseAddr(addr.String())
		if err == nil {
			q := dns.Question{Name: arpa, Qclass: dns.ClassINET, Qtype: dns.TypePTR}
			qType := dns.TypeToString[q.Qtype]
			rr, err := dns.NewRR(fmt.Sprintf("%s %s %s", arpa, qType, name))
			if err == nil {
				d.dnsMap[q] = []dns.RR{rr}
				d.l.Debugf("DNS record added %s", rr.String())
			}
		}
	}
} 

func (d *dnsRecords) addTXT(name string, crt cert.Certificate) {
	q := dns.Question{Name: name, Qclass: dns.ClassINET, Qtype: dns.TypeTXT}
	d.dnsMap[q] = nil

	qType := dns.TypeToString[q.Qtype]
	rr, err := dns.NewRR(fmt.Sprintf("%s %s \"Name: %v\" \"Networks: %v\" \"Groups: %v\" \"UnsafeNetworks: %v\"", name, qType, crt.Name(), crt.Networks(), crt.Groups(), crt.UnsafeNetworks()))
	if err == nil {
		d.dnsMap[q] = []dns.RR{rr}
		d.l.Debugf("DNS record added %s", rr.String())
	}
} 

func (d *dnsRecords) Add(crt cert.Certificate, addresses []netip.Addr) {
	host := dns.Fqdn(strings.ToLower(crt.Name() + dnsSuffix))
	
	d.Lock()
	defer d.Unlock()

	d.addA(host, addresses)
	d.addAAAA(host, addresses)
	d.addPTR(host, addresses)
	d.addTXT(host, crt)
}

func (d *dnsRecords) parseQuery(m *dns.Msg) {
	for _, q := range m.Question {
		switch q.Qtype {
		case dns.TypeA, dns.TypeAAAA, dns.TypePTR, dns.TypeTXT:
			d.RLock()
			if rr, ok := d.dnsMap[q]; ok {
				m.Answer = append(m.Answer, rr...)
			}
			d.RUnlock()
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
		d.parseQuery(m)
	}

	w.WriteMsg(m)
}

func dnsMain(l *logrus.Logger, cs *CertState, c *config.C) func() {
	dnsR = newDnsRecords(l)
	dnsSuffix = getDnsSuffix(c)

	// Add self to dns records
	dnsR.Add(cs.GetDefaultCertificate(), cs.myVpnAddrs)

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

func getDnsSuffix(c *config.C) string {
	suffix := strings.TrimSpace(c.GetString("lighthouse.dns.suffix", ""))
	return suffix
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
