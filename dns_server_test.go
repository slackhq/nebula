package nebula

import (
	"testing"

	"github.com/miekg/dns"
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
