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

func Test_getDnsServerAddrPort(t *testing.T) {
	c := config.NewC(nil)

	c.Settings["lighthouse"] = map[string]any{
		"dns": map[string]any{
			"host": "0.0.0.0",
			"port": "1",
		},
	}
	assert.Equal(t, "0.0.0.0:1", getDnsServerAddrPort(c))

	c.Settings["lighthouse"] = map[string]any{
		"dns": map[string]any{
			"host": "::",
			"port": "1",
		},
	}
	assert.Equal(t, "[::]:1", getDnsServerAddrPort(c))

	c.Settings["lighthouse"] = map[string]any{
		"dns": map[string]any{
			"host": "[::]",
			"port": "1",
		},
	}
	assert.Equal(t, "[::]:1", getDnsServerAddrPort(c))

	// Make sure whitespace doesn't mess us up
	c.Settings["lighthouse"] = map[string]any{
		"dns": map[string]any{
			"host": "[::] ",
			"port": "1",
		},
	}
	assert.Equal(t, "[::]:1", getDnsServerAddrPort(c))
}

func Test_shouldServeDns(t *testing.T) {
	c := config.NewC(nil)
	notLoopback := map[interface{}]interface{}{"host": "0.0.0.0", "port": "1"}
	yesLoopbackv4 := map[interface{}]interface{}{"host": "127.0.0.2", "port": "1"}
	yesLoopbackv6 := map[interface{}]interface{}{"host": "::1", "port": "1"}

	c.Settings["lighthouse"] = map[interface{}]interface{}{
		"serve_dns": false,
	}
	serveDns, err := shouldServeDns(c)
	assert.NoError(t, err)
	assert.False(t, serveDns)

	c.Settings["lighthouse"] = map[interface{}]interface{}{
		"am_lighthouse": true,
		"serve_dns":     true,
	}
	serveDns, err = shouldServeDns(c)
	assert.Error(t, err)
	assert.False(t, serveDns)

	c.Settings["lighthouse"] = map[interface{}]interface{}{
		"am_lighthouse": true,
		"serve_dns":     true,
		"dns":           notLoopback,
	}
	serveDns, err = shouldServeDns(c)
	assert.NoError(t, err)
	assert.True(t, serveDns)

	//non-lighthouses must do DNS on loopback
	c.Settings["lighthouse"] = map[interface{}]interface{}{
		"am_lighthouse": false,
		"serve_dns":     true,
		"dns":           notLoopback,
	}
	serveDns, err = shouldServeDns(c)
	assert.Error(t, err)
	assert.False(t, serveDns)

	c.Settings["lighthouse"] = map[interface{}]interface{}{
		"am_lighthouse": false,
		"serve_dns":     true,
		"dns":           yesLoopbackv4,
	}
	serveDns, err = shouldServeDns(c)
	assert.NoError(t, err)
	assert.True(t, serveDns)

	c.Settings["lighthouse"] = map[interface{}]interface{}{
		"am_lighthouse": false,
		"serve_dns":     true,
		"dns":           yesLoopbackv6,
	}
	serveDns, err = shouldServeDns(c)
	assert.NoError(t, err)
	assert.True(t, serveDns)
}
