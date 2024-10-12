package nebula

import (
	"testing"

	"github.com/miekg/dns"
	"github.com/slackhq/nebula/config"
	"github.com/stretchr/testify/assert"
)

func TestParsequery(t *testing.T) {
	//TODO: This test is basically pointless
	hostMap := &HostMap{}
	ds := newDnsRecords(hostMap)
	ds.Add("test.com.com", "1.2.3.4")

	m := new(dns.Msg)
	m.SetQuestion("test.com.com", dns.TypeA)

	//parseQuery(m)
}

func Test_getDnsServerAddrPort(t *testing.T) {
	c := config.NewC(nil)

	c.Settings["lighthouse"] = map[interface{}]interface{}{
		"dns": map[interface{}]interface{}{
			"host": "0.0.0.0",
			"port": "1",
		},
	}
	assert.Equal(t, "0.0.0.0:1", getDnsServerAddrPort(c))

	c.Settings["lighthouse"] = map[interface{}]interface{}{
		"dns": map[interface{}]interface{}{
			"host": "::",
			"port": "1",
		},
	}
	assert.Equal(t, "[::]:1", getDnsServerAddrPort(c))

	c.Settings["lighthouse"] = map[interface{}]interface{}{
		"dns": map[interface{}]interface{}{
			"host": "[::]",
			"port": "1",
		},
	}
	assert.Equal(t, "[::]:1", getDnsServerAddrPort(c))

	// Make sure whitespace doesn't mess us up
	c.Settings["lighthouse"] = map[interface{}]interface{}{
		"dns": map[interface{}]interface{}{
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
