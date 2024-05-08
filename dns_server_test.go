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

func Test_getDnsServerAddr(t *testing.T) {
	c := config.NewC(nil)

	c.Settings["lighthouse"] = map[interface{}]interface{}{
		"dns": map[interface{}]interface{}{
			"host": "0.0.0.0",
			"port": "1",
		},
	}
	assert.Equal(t, "0.0.0.0:1", getDnsServerAddr(c))

	c.Settings["lighthouse"] = map[interface{}]interface{}{
		"dns": map[interface{}]interface{}{
			"host": "::",
			"port": "1",
		},
	}
	assert.Equal(t, "[::]:1", getDnsServerAddr(c))

	c.Settings["lighthouse"] = map[interface{}]interface{}{
		"dns": map[interface{}]interface{}{
			"host": "[::]",
			"port": "1",
		},
	}
	assert.Equal(t, "[::]:1", getDnsServerAddr(c))

	// Make sure whitespace doesn't mess us up
	c.Settings["lighthouse"] = map[interface{}]interface{}{
		"dns": map[interface{}]interface{}{
			"host": "[::] ",
			"port": "1",
		},
	}
	assert.Equal(t, "[::]:1", getDnsServerAddr(c))
}
