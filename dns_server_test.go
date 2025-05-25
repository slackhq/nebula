package nebula

import (
	"net/netip"
	"testing"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/config"
	"github.com/stretchr/testify/assert"
)

func TestParsequery(t *testing.T) {
	l := logrus.New()
	ds := newDnsRecords(l)
	addrs := []netip.Addr{
		netip.MustParseAddr("1.2.3.4"),
		netip.MustParseAddr("1.2.3.5"),
		netip.MustParseAddr("fd01::24"),
		netip.MustParseAddr("fd01::25"),
	}
	dnsSuffix = ".com"
	ds.Add("test.com", addrs)

	m := &dns.Msg{}
	m.SetQuestion("test.com.com.", dns.TypeA)
	ds.parseQuery(m)
	assert.NotNil(t, m.Answer)
	assert.Equal(t, "1.2.3.4", m.Answer[0].(*dns.A).A.String())

	m = &dns.Msg{}
	m.SetQuestion("test.com.com.", dns.TypeAAAA)
	ds.parseQuery(m)
	assert.NotNil(t, m.Answer)
	assert.Equal(t, "fd01::24", m.Answer[0].(*dns.AAAA).AAAA.String())

	m = &dns.Msg{}
	m.SetQuestion("4.3.2.1.in-addr.arpa.", dns.TypePTR)
	ds.parseQuery(m)
	assert.NotNil(t, m.Answer)
	assert.Equal(t, "test.com.com.", m.Answer[0].(*dns.PTR).Ptr)

	m = &dns.Msg{}
	m.SetQuestion("4.2.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.0.d.f.ip6.arpa.", dns.TypePTR)
	ds.parseQuery(m)
	assert.NotNil(t, m.Answer)
	assert.Equal(t, "test.com.com.", m.Answer[0].(*dns.PTR).Ptr)
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
