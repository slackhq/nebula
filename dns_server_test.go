package nebula

import (
	"testing"

	"github.com/miekg/dns"
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

func TestDnsWildcardLookup(t *testing.T) {
	hostMap := &HostMap{}
	ds := newDnsRecords(hostMap)
	ds.Add("test.com.com", "1.2.3.4")
	ds.dnsWildcardEnabled = true

	result := ds.Query("foo.test.com.com")
	assert.Equal(t, "1.2.3.4", result)
}

func TestDnsWildcardDisabled(t *testing.T) {
	hostMap := &HostMap{}
	ds := newDnsRecords(hostMap)
	ds.Add("test.com.com", "1.2.3.4")

	result := ds.Query("test.com.com")
	assert.Equal(t, "1.2.3.4", result)

	result = ds.Query("foo.test.com.com")
	assert.Equal(t, "", result)
}

func TestDnsWildcardLookupLimit(t *testing.T) {
	hostMap := &HostMap{}
	ds := newDnsRecords(hostMap)
	ds.Add("test.com.com", "1.2.3.4")
	ds.dnsWildcardEnabled = true
	ds.dnsWildcardLimit = 1

	result := ds.Query("foo.test.com.com")
	assert.Equal(t, "1.2.3.4", result)

	result = ds.Query("foo.bar.test.com.com")
	assert.Equal(t, "", result)
}
