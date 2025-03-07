//go:build e2e_testing
// +build e2e_testing

package router

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/slackhq/nebula"
)

type edge struct {
	from string
	to   string
	dual bool
}

func renderHostmaps(controls ...*nebula.Control) string {
	var lines []*edge
	r := "graph TB\n"
	for _, c := range controls {
		sr, se := renderHostmap(c)
		r += sr
		for _, e := range se {
			add := true

			// Collapse duplicate edges into a bi-directionally connected edge
			for _, ge := range lines {
				if e.to == ge.from && e.from == ge.to {
					add = false
					ge.dual = true
					break
				}
			}

			if add {
				lines = append(lines, e)
			}
		}
	}

	for _, line := range lines {
		if line.dual {
			r += fmt.Sprintf("\t%v <--> %v\n", line.from, line.to)
		} else {
			r += fmt.Sprintf("\t%v --> %v\n", line.from, line.to)
		}

	}

	return r
}

func renderHostmap(c *nebula.Control) (string, []*edge) {
	var lines []string
	var globalLines []*edge

	crt := c.GetCertState().GetDefaultCertificate()
	clusterName := strings.Trim(crt.Name(), " ")
	clusterVpnIp := crt.Networks()[0].Addr()
	r := fmt.Sprintf("\tsubgraph %s[\"%s (%s)\"]\n", clusterName, clusterName, clusterVpnIp)

	hm := c.GetHostmap()
	hm.RLock()
	defer hm.RUnlock()

	// Draw the vpn to index nodes
	r += fmt.Sprintf("\t\tsubgraph %s.hosts[\"Hosts (vpn ip to index)\"]\n", clusterName)
	hosts := sortedHosts(hm.Hosts)
	for _, vpnIp := range hosts {
		hi := hm.Hosts[vpnIp]
		r += fmt.Sprintf("\t\t\t%v.%v[\"%v\"]\n", clusterName, vpnIp, vpnIp)
		lines = append(lines, fmt.Sprintf("%v.%v --> %v.%v", clusterName, vpnIp, clusterName, hi.GetLocalIndex()))

		rs := hi.GetRelayState()
		for _, relayIp := range rs.CopyRelayIps() {
			lines = append(lines, fmt.Sprintf("%v.%v --> %v.%v", clusterName, vpnIp, clusterName, relayIp))
		}

		for _, relayIp := range rs.CopyRelayForIdxs() {
			lines = append(lines, fmt.Sprintf("%v.%v --> %v.%v", clusterName, vpnIp, clusterName, relayIp))
		}
	}
	r += "\t\tend\n"

	// Draw the relay hostinfos
	if len(hm.Relays) > 0 {
		r += fmt.Sprintf("\t\tsubgraph %s.relays[\"Relays (relay index to hostinfo)\"]\n", clusterName)
		for relayIndex, hi := range hm.Relays {
			r += fmt.Sprintf("\t\t\t%v.%v[\"%v\"]\n", clusterName, relayIndex, relayIndex)
			lines = append(lines, fmt.Sprintf("%v.%v --> %v.%v", clusterName, relayIndex, clusterName, hi.GetLocalIndex()))
		}
		r += "\t\tend\n"
	}

	// Draw the local index to relay or remote index nodes
	r += fmt.Sprintf("\t\tsubgraph indexes.%s[\"Indexes (index to hostinfo)\"]\n", clusterName)
	indexes := sortedIndexes(hm.Indexes)
	for _, idx := range indexes {
		hi, ok := hm.Indexes[idx]
		if ok {
			r += fmt.Sprintf("\t\t\t%v.%v[\"%v (%v)\"]\n", clusterName, idx, idx, hi.GetVpnAddrs())
			remoteClusterName := strings.Trim(hi.GetCert().Certificate.Name(), " ")
			globalLines = append(globalLines, &edge{from: fmt.Sprintf("%v.%v", clusterName, idx), to: fmt.Sprintf("%v.%v", remoteClusterName, hi.GetRemoteIndex())})
			_ = hi
		}
	}
	r += "\t\tend\n"

	// Add the edges inside this host
	for _, line := range lines {
		r += fmt.Sprintf("\t\t%v\n", line)
	}

	r += "\tend\n"
	return r, globalLines
}

func sortedHosts(hosts map[netip.Addr]*nebula.HostInfo) []netip.Addr {
	keys := make([]netip.Addr, 0, len(hosts))
	for key := range hosts {
		keys = append(keys, key)
	}

	sort.SliceStable(keys, func(i, j int) bool {
		return keys[i].Compare(keys[j]) > 0
	})

	return keys
}

func sortedIndexes(indexes map[uint32]*nebula.HostInfo) []uint32 {
	keys := make([]uint32, 0, len(indexes))
	for key := range indexes {
		keys = append(keys, key)
	}

	sort.SliceStable(keys, func(i, j int) bool {
		return keys[i] > keys[j]
	})

	return keys
}
