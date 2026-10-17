package nebula

import (
	"net/netip"
	"testing"

	"github.com/gaissmai/bart"
	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/overlay/overlaytest"
	"github.com/slackhq/nebula/routing"
	"github.com/slackhq/nebula/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestReloadFirewall_CertUnsafeNetworksChanged verifies that reloadFirewall
// rebuilds the firewall when only the certificate's UnsafeNetworks have changed,
// even if the firewall section of the YAML has not.
func TestReloadFirewall_CertUnsafeNetworksChanged(t *testing.T) {
	l := test.NewLogger()

	vpnNet := netip.MustParsePrefix("10.0.0.1/24")
	initialUnsafe := []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")}

	// dummyCert avoids dragging the real signing pipeline into a unit test.
	c1 := &dummyCert{
		version:        cert.Version2,
		networks:       []netip.Prefix{vpnNet},
		unsafeNetworks: initialUnsafe,
	}
	pki := &PKI{}
	pki.cs.Store(&CertState{v2Cert: c1, initiatingVersion: cert.Version2})

	rawYAML := `firewall:
  outbound:
    - port: any
      proto: any
      host: any
  inbound:
    - port: any
      proto: any
      host: any
`
	cfg := config.NewC(l)
	require.NoError(t, cfg.LoadString(rawYAML))

	fw, err := NewFirewallFromConfig(l, pki.getCertState(), cfg)
	require.NoError(t, err)
	require.Equal(t, initialUnsafe, fw.unsafeNetworks)

	f := &Interface{
		pki:      pki,
		firewall: fw,
		l:        l,
	}

	// Swap the cert with a different UnsafeNetworks set.
	newUnsafe := []netip.Prefix{
		netip.MustParsePrefix("198.51.100.0/24"),
		netip.MustParsePrefix("203.0.113.0/24"),
	}
	c2 := &dummyCert{
		version:        cert.Version2,
		networks:       []netip.Prefix{vpnNet},
		unsafeNetworks: newUnsafe,
	}
	pki.cs.Store(&CertState{v2Cert: c2, initiatingVersion: cert.Version2})

	// Reload with the same YAML so HasChanged("firewall") reports false.
	require.NoError(t, cfg.ReloadConfigString(rawYAML).Err)
	require.False(t, cfg.HasChanged("firewall"))

	f.reloadFirewall(cfg, nil)

	assert.NotSame(t, fw, f.firewall, "firewall pointer should have been replaced")
	assert.Equal(t, newUnsafe, f.firewall.unsafeNetworks)
	assert.True(t, f.firewall.routableNetworks.Contains(netip.MustParseAddr("203.0.113.5")))
}

// TestReloadFirewall_NoChange verifies that reloadFirewall is a no-op when
// neither the firewall config nor the cert's UnsafeNetworks have changed.
func TestReloadFirewall_NoChange(t *testing.T) {
	l := test.NewLogger()

	vpnNet := netip.MustParsePrefix("10.0.0.1/24")
	unsafe := []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")}

	c1 := &dummyCert{
		version:        cert.Version2,
		networks:       []netip.Prefix{vpnNet},
		unsafeNetworks: unsafe,
	}
	pki := &PKI{}
	pki.cs.Store(&CertState{v2Cert: c1, initiatingVersion: cert.Version2})

	rawYAML := `firewall:
  outbound:
    - port: any
      proto: any
      host: any
  inbound:
    - port: any
      proto: any
      host: any
`
	cfg := config.NewC(l)
	require.NoError(t, cfg.LoadString(rawYAML))

	fw, err := NewFirewallFromConfig(l, pki.getCertState(), cfg)
	require.NoError(t, err)

	f := &Interface{
		pki:      pki,
		firewall: fw,
		l:        l,
	}

	require.NoError(t, cfg.ReloadConfigString(rawYAML).Err)
	f.reloadFirewall(cfg, nil)

	assert.Same(t, fw, f.firewall, "firewall should not have been replaced")
}

// Rules that don't parse keep the old firewall, and the reload says it could not apply them
func TestReloadFirewall_BadRulesFailTheReload(t *testing.T) {
	l := test.NewLogger()
	pki := &PKI{}
	pki.cs.Store(&CertState{v2Cert: &dummyCert{version: cert.Version2, networks: []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")}}, initiatingVersion: cert.Version2})

	rules := func(proto string) string {
		return "firewall:\n  outbound:\n    - port: any\n      proto: any\n      host: any\n  inbound:\n    - port: any\n      proto: " + proto + "\n      host: any\n"
	}
	cfg := config.NewC(l)
	require.NoError(t, cfg.LoadString(rules("any")))
	fw, err := NewFirewallFromConfig(l, pki.getCertState(), cfg)
	require.NoError(t, err)
	f := &Interface{pki: pki, firewall: fw, l: l}
	cfg.RegisterReloadCallback(f.reloadFirewall)

	res := cfg.ReloadConfigString(rules("nope"))
	require.NoError(t, res.Err)
	assert.True(t, res.Failed)
	assert.Same(t, fw, f.firewall)
}

// routesTun is a NoopTun with a route table
type routesTun struct {
	overlaytest.NoopTun
	routes *bart.Table[routing.Gateways]
}

func (t routesTun) RoutesFor(ip netip.Addr) routing.Gateways {
	r, _ := t.routes.Lookup(ip)
	return r
}

func TestInterface_SiblingPeers(t *testing.T) {
	addr := netip.MustParseAddr
	routes := new(bart.Table[routing.Gateways])
	// a and b carry 198.51.100.0/24, the route names b by its v6 address
	routes.Insert(netip.MustParsePrefix("198.51.100.0/24"), routing.Gateways{
		routing.NewGateway(addr("192.0.2.2"), 1),
		routing.NewGateway(addr("fd00::3"), 1),
		routing.NewGateway(addr("192.0.2.5"), 1), // no tunnel to this one
	})
	routes.Insert(netip.MustParsePrefix("203.0.113.0/24"), routing.Gateways{routing.NewGateway(addr("192.0.2.2"), 1)})

	hm := newHostMap(test.NewLogger())
	a := &HostInfo{vpnAddrs: []netip.Addr{addr("192.0.2.2"), addr("fd00::2")}, localIndexId: 1}
	b := &HostInfo{vpnAddrs: []netip.Addr{addr("192.0.2.3"), addr("fd00::3")}, localIndexId: 2}
	c := &HostInfo{vpnAddrs: []netip.Addr{addr("192.0.2.4")}, localIndexId: 3}
	for _, h := range []*HostInfo{a, b, c} {
		hm.unlockedAddHostInfo(h, &Interface{})
	}
	f := &Interface{inside: routesTun{routes: routes}, hostMap: hm}

	// Siblings come back as their first vpn address, the one conntrack keys on, whichever address the route names
	assert.Equal(t, []netip.Addr{addr("192.0.2.3")}, f.siblingPeers(addr("198.51.100.5"), a, nil))
	assert.Equal(t, []netip.Addr{addr("192.0.2.2")}, f.siblingPeers(addr("198.51.100.5"), b, nil))
	assert.Empty(t, f.siblingPeers(addr("198.51.100.5"), c, nil), "not one of our gateways for the network")
	assert.Empty(t, f.siblingPeers(addr("203.0.113.5"), a, nil), "a single gateway route has no siblings")
	assert.Empty(t, f.siblingPeers(addr("192.0.2.3"), a, nil), "no route")
}
