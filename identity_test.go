package nebula

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"testing"
	"time"

	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/cert_test"
	"github.com/slackhq/nebula/commands"
	"github.com/slackhq/nebula/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// identityFixture is an Interface with our own certificate loaded and one peer behind an
// established tunnel, which is all identity reads.
func identityFixture(t *testing.T) (*Interface, cert.Certificate) {
	t.Helper()

	l := test.NewLogger()
	me := netip.MustParseAddr("10.0.0.1")
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

	return &Interface{pki: newTestPKI(t, "me", []netip.Addr{me}), hostMap: hm}, peerCert
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

// identityOfSelf runs the command with no -address.
func identityOfSelf(t *testing.T, f *Interface) commands.Result {
	t.Helper()
	r, err := runIdentity(f, &identityFlags{}, nil)
	require.NoError(t, err)
	return r
}

func TestIdentityReportsThisNodeByDefault(t *testing.T) {
	f, _ := identityFixture(t)

	r := identityOfSelf(t, f)
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
	self := identityOfSelf(t, f)
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
