package nebula

import (
	"net"
	"net/netip"
	"testing"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/config"
	"github.com/stretchr/testify/assert"
)

func TestParsequery(t *testing.T) {
	l := logrus.New()
	hostMap := &HostMap{}
	ds := newDnsRecords(l, &CertState{}, hostMap)
	addrs := []netip.Addr{
		netip.MustParseAddr("1.2.3.4"),
		netip.MustParseAddr("1.2.3.5"),
		netip.MustParseAddr("fd01::24"),
		netip.MustParseAddr("fd01::25"),
	}
	ds.Add("test.com.com", addrs)

	m := &dns.Msg{}
	m.SetQuestion("test.com.com", dns.TypeA)
	ds.parseQuery(m, nil)
	assert.NotNil(t, m.Answer)
	assert.Equal(t, "1.2.3.4", m.Answer[0].(*dns.A).A.String())

	m = &dns.Msg{}
	m.SetQuestion("test.com.com", dns.TypeAAAA)
	ds.parseQuery(m, nil)
	assert.NotNil(t, m.Answer)
	assert.Equal(t, "fd01::24", m.Answer[0].(*dns.AAAA).AAAA.String())
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

type stubDNSWriter struct{}

func (stubDNSWriter) LocalAddr() net.Addr                { return &net.UDPAddr{} }
func (stubDNSWriter) RemoteAddr() net.Addr               { return &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 5353} }
func (stubDNSWriter) Write([]byte) (int, error)          { return 0, nil }
func (stubDNSWriter) WriteMsg(*dns.Msg) error            { return nil }
func (stubDNSWriter) Close() error                       { return nil }
func (stubDNSWriter) TsigStatus() error                  { return nil }
func (stubDNSWriter) TsigTimersOnly(bool)                {}
func (stubDNSWriter) Hijack()                            {}

func TestQueryCert_short_inputs(t *testing.T) {
	ds := newDnsRecords(logrus.New(), &CertState{}, &HostMap{})

	assert.NotPanics(t, func() { ds.QueryCert("") })
	assert.NotPanics(t, func() { ds.QueryCert(".") })
	assert.Equal(t, "", ds.QueryCert(""))
	assert.Equal(t, "", ds.QueryCert("."))
}

func TestParseQuery_TXT_empty_and_root_qname(t *testing.T) {
	ds := newDnsRecords(logrus.New(), &CertState{}, &HostMap{})

	// Root zone "." — must not panic, should return NXDOMAIN
	m := new(dns.Msg)
	m.SetQuestion(".", dns.TypeTXT)
	assert.NotPanics(t, func() { ds.parseQuery(m, stubDNSWriter{}) })
	assert.Equal(t, dns.RcodeNameError, m.Rcode)

	// Directly injected empty Name — must not panic
	m = new(dns.Msg)
	m.Question = []dns.Question{{Name: "", Qtype: dns.TypeTXT, Qclass: dns.ClassINET}}
	assert.NotPanics(t, func() { ds.parseQuery(m, stubDNSWriter{}) })
	assert.Equal(t, dns.RcodeNameError, m.Rcode)
}
