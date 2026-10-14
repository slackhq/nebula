package nebula

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"testing"
	"time"

	"github.com/gaissmai/bart"
	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/cert_test"
	"github.com/slackhq/nebula/commands"
	"github.com/slackhq/nebula/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// identityFixture is an Interface with our own certificate loaded, one peer behind an
// established tunnel, and one that also holds an address in a network we do not, which
// is all identity reads.
func identityFixture(t *testing.T) (*Interface, cert.Certificate) {
	t.Helper()

	l := test.NewLogger()
	me := netip.MustParsePrefix("10.0.0.1/24")
	peer := netip.MustParsePrefix("10.0.0.2/24")

	ca, _, caKey, _ := cert_test.NewTestCaCert(cert.Version2, cert.Curve_CURVE25519, time.Time{}, time.Time{}, nil, nil, nil)
	peerCert, _, _, _ := cert_test.NewTestCert(cert.Version2, cert.Curve_CURVE25519, ca, caKey, "peer", time.Time{}, time.Time{},
		[]netip.Prefix{peer}, []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")}, []string{"web", "db"})

	hm := newHostMap(l)
	hm.Hosts[peer.Addr()] = &HostInfo{
		vpnAddrs:        []netip.Addr{peer.Addr()},
		ConnectionState: &ConnectionState{peerCert: &cert.CachedCertificate{Certificate: peerCert}},
	}
	// A tunnel still handshaking has no certificate yet, and must not be reported.
	hm.Hosts[netip.MustParseAddr("10.0.0.3")] = &HostInfo{
		vpnAddrs:        []netip.Addr{netip.MustParseAddr("10.0.0.3")},
		ConnectionState: &ConnectionState{},
	}
	// A peer in two networks is indexed under both addresses once one is in common, as
	// the handshake keeps them, though a packet from the one we do not hold is never
	// accepted from it.
	far := []netip.Addr{netip.MustParseAddr("10.0.0.4"), netip.MustParseAddr("9.9.9.9")}
	farCert, _, _, _ := cert_test.NewTestCert(cert.Version2, cert.Curve_CURVE25519, ca, caKey, "far", time.Time{}, time.Time{},
		[]netip.Prefix{netip.PrefixFrom(far[0], 24), netip.PrefixFrom(far[1], 24)}, nil, nil)
	farInfo := &HostInfo{
		vpnAddrs:        far,
		ConnectionState: &ConnectionState{peerCert: &cert.CachedCertificate{Certificate: farCert}},
	}
	hm.Hosts[far[0]] = farInfo
	hm.Hosts[far[1]] = farInfo

	return &Interface{pki: identityPKI(t, "me", me), hostMap: hm}, peerCert
}

// identityPKI is a *PKI holding one v2 certificate for name over network, with the
// address and network tables the identity lookups consult: an address is ours when it
// is in the first, and a peer is answered for only when its address is in the second.
func identityPKI(t *testing.T, name string, network netip.Prefix) *PKI {
	t.Helper()
	ca, _, caKey, _ := cert_test.NewTestCaCert(cert.Version2, cert.Curve_CURVE25519, time.Time{}, time.Time{}, nil, nil, nil)
	c, _, _, _ := cert_test.NewTestCert(cert.Version2, cert.Curve_CURVE25519, ca, caKey, name, time.Time{}, time.Time{}, []netip.Prefix{network}, nil, nil)

	addr := network.Addr()
	addrsTable := new(bart.Lite)
	addrsTable.Insert(netip.PrefixFrom(addr, addr.BitLen()))
	networksTable := new(bart.Lite)
	networksTable.Insert(network.Masked())

	pki := &PKI{}
	pki.cs.Store(&CertState{
		v2Cert:             c,
		initiatingVersion:  cert.Version2,
		myVpnAddrs:         []netip.Addr{addr},
		myVpnAddrsTable:    addrsTable,
		myVpnNetworksTable: networksTable,
	})
	return pki
}

// identity runs the command with -address given as address.
func identity(t *testing.T, f *Interface, address string, operands ...string) commands.Result {
	t.Helper()
	fs := &identityFlags{}
	require.NoError(t, fs.setAddress(address))
	r, err := runIdentity(f, fs, operands)
	require.NoError(t, err)
	return r
}

// whoami runs the whoami command.
func whoami(t *testing.T, f *Interface) commands.Result {
	t.Helper()
	r, err := runWhoami(f)
	require.NoError(t, err)
	return r
}

// TestWhoamiWithoutACertificateRefuses: no certificate is a refusal with the reason, as
// print-cert answers it, not an error a surface collapses to "command failed".
func TestWhoamiWithoutACertificateRefuses(t *testing.T) {
	r := whoami(t, &Interface{pki: &PKI{}})
	assert.False(t, r.OK)
	assert.Equal(t, "No certificate is loaded", r.Reason)
}

func TestWhoamiReportsThisNode(t *testing.T) {
	f, _ := identityFixture(t)

	r := whoami(t, f)
	require.True(t, r.OK)
	id, ok := r.Value.(hostIdentity)
	require.True(t, ok, "got %T", r.Value)
	assert.Equal(t, "me", id.Name)
	assert.Equal(t, []netip.Addr{netip.MustParseAddr("10.0.0.1")}, id.VpnAddrs)
	assert.Equal(t, 2, id.CertVersion)
	assert.NotEmpty(t, id.Fingerprint)
	assert.NotEmpty(t, id.Issuer)

	// Our own address answers the same way: the hostmap never holds ourselves.
	self := identity(t, f, "10.0.0.1")
	assert.Equal(t, id, self.Value)
}

func TestIdentityReportsAPeerFromItsCertificate(t *testing.T) {
	f, peerCert := identityFixture(t)

	for _, addr := range []string{
		"10.0.0.2",
		"10.0.0.2:54321",      // a connection's RemoteAddr, as a server has it
		"::ffff:10.0.0.2",     // the same peer seen through a dual stack listener
		"[::ffff:10.0.0.2]:8", // and with a port
	} {
		r := identity(t, f, addr)
		require.True(t, r.OK, "%s: %s", addr, r.Reason)
		id := r.Value.(hostIdentity)
		assert.Equal(t, "peer", id.Name, addr)
		assert.Equal(t, []netip.Addr{netip.MustParseAddr("10.0.0.2")}, id.VpnAddrs, addr)
		assert.Equal(t, []netip.Prefix{netip.MustParsePrefix("10.0.0.2/24")}, id.Networks, addr)
		assert.Equal(t, []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")}, id.UnsafeNetworks, addr)
		assert.Equal(t, []string{"web", "db"}, id.Groups, addr)
		assert.Equal(t, peerCert.Issuer(), id.Issuer, addr)
		assert.Equal(t, peerCert.NotAfter(), id.NotAfter, addr)
	}
}

// TestIdentityRefusals: the ways a lookup fails are told apart, because a program
// deciding whether to let a connection in treats them differently.
func TestIdentityRefusals(t *testing.T) {
	f, _ := identityFixture(t)

	unknown := identity(t, f, "10.0.0.9")
	assert.False(t, unknown.OK)
	assert.True(t, unknown.NotFound, "no tunnel is a not found")
	assert.Equal(t, "No active tunnel for vpn addr: 10.0.0.9", unknown.Reason)

	pending := identity(t, f, "10.0.0.3:1")
	assert.True(t, pending.NotFound, "a tunnel without a certificate yet is not active")
	assert.Equal(t, "No active tunnel for vpn addr: 10.0.0.3", pending.Reason, "the reason names the address, not the port")

	// A peer's address in a network we do not hold is answered by nothing that vouches
	// for a sender, though the same peer's address in our network is; see hostIdentity.
	far := identity(t, f, "9.9.9.9")
	assert.False(t, far.OK)
	assert.True(t, far.NotFound, "an address outside our networks is not found, with a tunnel to its holder up")
	assert.Equal(t, "No active tunnel for vpn addr: 9.9.9.9", far.Reason)
	near := identity(t, f, "10.0.0.4")
	require.True(t, near.OK, near.Reason)
	assert.Equal(t, "far", near.Value.(hostIdentity).Name)

	garbage := identity(t, f, "not-an-address")
	assert.False(t, garbage.OK)
	assert.False(t, garbage.NotFound, "an address that does not parse is the caller's mistake")
	assert.Equal(t, "The provided vpn addr could not be parsed: not-an-address", garbage.Reason)

	// An address that was given and is empty is a caller that failed to fill it in, and
	// must not be answered with our own identity.
	empty := identity(t, f, "")
	assert.False(t, empty.OK)
	assert.False(t, empty.NotFound)
	assert.Equal(t, "The provided vpn addr could not be parsed: ", empty.Reason)

	operand := identity(t, f, "", "10.0.0.2")
	assert.False(t, operand.OK)
	assert.Contains(t, operand.Reason, "identity -address 10.0.0.2")

	// No address at all is a caller that forgot the parameter, and is pointed at whoami
	// rather than handed this node's identity.
	omitted, err := runIdentity(f, &identityFlags{}, nil)
	require.NoError(t, err)
	assert.False(t, omitted.OK)
	assert.False(t, omitted.NotFound)
	assert.Contains(t, omitted.Reason, "-address")
	assert.Contains(t, omitted.Reason, "whoami")
}

// TestOwnCertificatePrefersV2: with both versions loaded, the v2 certificate is the one
// myVpnAddrsTable is built from and may carry addresses the v1 does not, so it is the one
// whoami and an identity lookup of our own address report, whichever version handshakes
// are initiated with.
func TestOwnCertificatePrefersV2(t *testing.T) {
	v4 := netip.MustParsePrefix("10.0.0.1/24")
	ca1, _, caKey1, _ := cert_test.NewTestCaCert(cert.Version1, cert.Curve_CURVE25519, time.Time{}, time.Time{}, nil, nil, nil)
	v1, _, _, _ := cert_test.NewTestCert(cert.Version1, cert.Curve_CURVE25519, ca1, caKey1, "me", time.Time{}, time.Time{}, []netip.Prefix{v4}, nil, nil)
	ca2, _, caKey2, _ := cert_test.NewTestCaCert(cert.Version2, cert.Curve_CURVE25519, time.Time{}, time.Time{}, nil, nil, nil)
	v2, _, _, _ := cert_test.NewTestCert(cert.Version2, cert.Curve_CURVE25519, ca2, caKey2, "me", time.Time{}, time.Time{},
		[]netip.Prefix{v4, netip.MustParsePrefix("fd00::1/64")}, nil, nil)

	assert.Nil(t, ownCertificate(nil))
	assert.Equal(t, v1, ownCertificate(&CertState{v1Cert: v1, initiatingVersion: cert.Version1}))
	assert.Equal(t, v2, ownCertificate(&CertState{v2Cert: v2, initiatingVersion: cert.Version2}))
	assert.Equal(t, v2, ownCertificate(&CertState{v1Cert: v1, v2Cert: v2, initiatingVersion: cert.Version1}),
		"the initiating version is v1, the reported certificate is still the v2")
}

// TestIdentityShapes pins the JSON a program reads and the text a person reads. The
// field names are an API served to programs not built against nebula.
func TestIdentityShapes(t *testing.T) {
	f, _ := identityFixture(t)
	r := identity(t, f, "10.0.0.2")

	b, err := json.Marshal(r.Payload())
	require.NoError(t, err)
	var got map[string]any
	require.NoError(t, json.Unmarshal(b, &got))
	var keys []string
	for k := range got {
		keys = append(keys, k)
	}
	assert.ElementsMatch(t, []string{
		"name", "vpnAddrs", "networks", "unsafeNetworks", "groups",
		"fingerprint", "issuer", "notBefore", "notAfter", "certVersion",
	}, keys)

	// Empty lists marshal as [], never null.
	self := whoami(t, f)
	b, err = json.Marshal(self.Payload())
	require.NoError(t, err)
	assert.Contains(t, string(b), `"groups":[]`)
	assert.Contains(t, string(b), `"unsafeNetworks":[]`)

	out := &bytes.Buffer{}
	require.NoError(t, commands.Render(&commands.Command{Name: commands.Identity, Text: commands.Typed(textIdentity)}, r, commands.FormatText, out))
	assert.Contains(t, out.String(), "name: peer\n")
	assert.Contains(t, out.String(), "vpn addrs: 10.0.0.2\n")
	assert.Contains(t, out.String(), "groups: web, db\n")
	assert.Contains(t, out.String(), "cert version: 2\n")
}

func TestParseVpnAddrWithOptionalPort(t *testing.T) {
	for in, want := range map[string]string{
		"10.0.0.2":            "10.0.0.2",
		"10.0.0.2:443":        "10.0.0.2",
		"fd00::1":             "fd00::1",
		"[fd00::1]:443":       "fd00::1",
		"::ffff:10.0.0.2":     "10.0.0.2",
		"[::ffff:10.0.0.2]:1": "10.0.0.2",
		"fe80::1%eth0":        "fe80::1",
	} {
		got, err := parseVpnAddrWithOptionalPort(in)
		require.NoError(t, err, in)
		assert.Equal(t, netip.MustParseAddr(want), got, in)
	}

	for _, in := range []string{"", "10.0.0.2:", ":443", "10.0.0", "example.com:80"} {
		_, err := parseVpnAddrWithOptionalPort(in)
		assert.Error(t, err, in)
	}
}
