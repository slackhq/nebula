package nebula

import (
	"bytes"
	"encoding/json"
	"io"
	"net/netip"
	"testing"
	"time"

	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/cert_test"
	"github.com/slackhq/nebula/commands"
	"github.com/slackhq/nebula/logging"
	"github.com/slackhq/nebula/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLogFormatRefusalIsShown: a format the logger does not know is a refusal the user
// sees, rather than a bare error, which over ssh was silence.
func TestLogFormatRefusalIsShown(t *testing.T) {
	l := logging.NewLogger(io.Discard)

	res, err := runLogFormat(l, []string{"bogus"})
	require.NoError(t, err)
	assert.False(t, res.OK)
	assert.Equal(t, "Unable to set log format: unknown log format `bogus`. possible formats: [text json]", res.Reason)

	res, err = runLogFormat(l, []string{"JSON"})
	require.NoError(t, err)
	out := &bytes.Buffer{}
	require.NoError(t, commands.Typed(textLogFormat)(res.Value, out))
	assert.Equal(t, "Log format is: json\n", out.String())
}

// TestPrintRelaysReportsErrorsAsText: the Error field was an error value, which encodes
// as {} and lost the message. It is the message now, and absent when there is none.
func TestPrintRelaysReportsErrorsAsText(t *testing.T) {
	l := test.NewLogger()
	hm := newHostMap(l)
	relay := netip.MustParseAddr("10.0.0.1")
	peer := netip.MustParseAddr("10.0.0.2")

	// A relay host that is in Relays but not in Hosts, so its hostinfo cannot be found.
	hm.Relays[1] = &HostInfo{vpnAddrs: []netip.Addr{relay}}
	ifce := &Interface{hostMap: hm}

	marshal := func() string {
		b, err := json.Marshal(runPrintRelays(ifce))
		require.NoError(t, err)
		return string(b)
	}
	assert.JSONEq(t, `{"Relays":[{"NebulaAddr":"10.0.0.1","RelayForAddrs":[{"Error":"could not find hostinfo","Type":"","State":"","PeerAddr":"","LocalIndex":0,"RemoteIndex":0,"RelayedThrough":null}]}]}`, marshal())

	// The same relay host, found, relaying for a peer whose index matches: no Error key.
	hi := hm.Relays[1]
	r := &Relay{Type: ForwardingType, State: Established, PeerAddr: peer, LocalIndex: 1, RemoteIndex: 2}
	hi.relayState = RelayState{
		relayForByAddr: map[netip.Addr]*Relay{peer: r},
		relayForByIdx:  map[uint32]*Relay{r.LocalIndex: r},
	}
	hm.Hosts[relay] = hi
	assert.JSONEq(t, `{"Relays":[{"NebulaAddr":"10.0.0.1","RelayForAddrs":[{"Type":"forwarding","State":"established","PeerAddr":"10.0.0.2","LocalIndex":1,"RemoteIndex":2,"RelayedThrough":null}]}]}`, marshal())

	// And an index mismatch names it.
	hm.Relays[7] = hi
	delete(hm.Relays, 1)
	assert.Contains(t, marshal(), `"Error":"hostmap LocalIndex '7' does not match RelayState LocalIndex"`)
}

// TestPrintCertOfATunnelWithoutACertificate: a tunnel still handshaking, or one being
// torn down, has no certificate, and print-cert refuses rather than panicking.
func TestPrintCertOfATunnelWithoutACertificate(t *testing.T) {
	f, _ := identityFixture(t)

	r, err := runPrintCert(f, &printCertFlags{}, []string{"10.0.0.3"})
	require.NoError(t, err)
	assert.False(t, r.OK)
	assert.Equal(t, "Could not find tunnel for vpn addr: 10.0.0.3", r.Reason)

	r, err = runPrintCert(f, &printCertFlags{}, []string{"10.0.0.2"})
	require.NoError(t, err)
	assert.True(t, r.OK, "a tunnel with a certificate is printed")
}

// TestPrintCertByAddressFlag: -address is the info API's spelling of the operand, takes a
// port and a 4in6 form the way identity does, answers our own address with our own
// certificate, and is refused together with an operand.
func TestPrintCertByAddressFlag(t *testing.T) {
	f, peerCert := identityFixture(t)

	for _, addr := range []string{"10.0.0.2", "10.0.0.2:4242", "[::ffff:10.0.0.2]:4242"} {
		fl := &printCertFlags{}
		require.NoError(t, fl.setAddress(addr))
		r, err := runPrintCert(f, fl, nil)
		require.NoError(t, err)
		require.True(t, r.OK, addr)
		assert.Equal(t, peerCert, r.Value, addr)
	}

	fl := &printCertFlags{}
	require.NoError(t, fl.setAddress("10.0.0.1"))
	r, err := runPrintCert(f, fl, nil)
	require.NoError(t, err)
	require.True(t, r.OK)
	assert.Equal(t, ownCertificate(f.pki.getCertState()), r.Value, "our own address is our own certificate")

	fl = &printCertFlags{}
	require.NoError(t, fl.setAddress("10.0.0.3"))
	r, err = runPrintCert(f, fl, nil)
	require.NoError(t, err)
	assert.False(t, r.OK)
	assert.True(t, r.NotFound)

	fl = &printCertFlags{}
	require.NoError(t, fl.setAddress("not-an-address"))
	r, err = runPrintCert(f, fl, nil)
	require.NoError(t, err)
	assert.Equal(t, "The provided vpn addr could not be parsed: not-an-address", r.Reason)

	fl = &printCertFlags{}
	require.NoError(t, fl.setAddress("10.0.0.2"))
	r, err = runPrintCert(f, fl, []string{"10.0.0.2"})
	require.NoError(t, err)
	assert.Equal(t, "print-cert takes one vpn addr, as -address or as an operand, not both", r.Reason)
}

// TestPrintCertPrefersOwnV2: with no address print-cert reports the certificate whoami
// does, the v2 when both versions are loaded, rather than the one handshakes start with.
func TestPrintCertPrefersOwnV2(t *testing.T) {
	v4 := netip.MustParsePrefix("10.0.0.1/24")
	ca1, _, caKey1, _ := cert_test.NewTestCaCert(cert.Version1, cert.Curve_CURVE25519, time.Time{}, time.Time{}, nil, nil, nil)
	v1, _, _, _ := cert_test.NewTestCert(cert.Version1, cert.Curve_CURVE25519, ca1, caKey1, "me", time.Time{}, time.Time{}, []netip.Prefix{v4}, nil, nil)
	ca2, _, caKey2, _ := cert_test.NewTestCaCert(cert.Version2, cert.Curve_CURVE25519, time.Time{}, time.Time{}, nil, nil, nil)
	v2, _, _, _ := cert_test.NewTestCert(cert.Version2, cert.Curve_CURVE25519, ca2, caKey2, "me", time.Time{}, time.Time{}, []netip.Prefix{v4}, nil, nil)

	f := &Interface{pki: &PKI{}, hostMap: newHostMap(test.NewLogger())}
	f.pki.cs.Store(&CertState{v1Cert: v1, v2Cert: v2, initiatingVersion: cert.Version1})

	r, err := runPrintCert(f, &printCertFlags{}, nil)
	require.NoError(t, err)
	require.True(t, r.OK)
	assert.Equal(t, v2, r.Value)
}
