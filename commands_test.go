package nebula

import (
	"bytes"
	"encoding/json"
	"io"
	"net/netip"
	"testing"

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
