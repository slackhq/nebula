package nebula

import (
	"bytes"
	"io"
	"net/netip"
	"testing"

	"github.com/slackhq/nebula/commands"
	"github.com/slackhq/nebula/logging"
	"github.com/slackhq/nebula/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLogFormatRefusalIsShown: a format the logger does not know is reported to the user
// as a failure, rather than returned bare, which over ssh was silence.
func TestLogFormatRefusalIsShown(t *testing.T) {
	l := logging.NewLogger(io.Discard)
	out := &bytes.Buffer{}
	w := commands.NewStringWriter(out)

	var f *commands.Failure
	require.ErrorAs(t, sshLogFormat(l, nil, []string{"bogus"}, w), &f)
	assert.Equal(t, "Unable to set log format: unknown log format `bogus`. possible formats: [text json]\n", out.String())

	out.Reset()
	require.NoError(t, sshLogFormat(l, nil, []string{"JSON"}, w))
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

	out := &bytes.Buffer{}
	require.NoError(t, sshPrintRelays(ifce, &sshPrintTunnelFlags{}, nil, commands.NewStringWriter(out)))
	assert.JSONEq(t, `{"Relays":[{"NebulaAddr":"10.0.0.1","RelayForAddrs":[{"Error":"could not find hostinfo","Type":"","State":"","PeerAddr":"","LocalIndex":0,"RemoteIndex":0,"RelayedThrough":null}]}]}`, out.String())

	// The same relay host, found, relaying for a peer whose index matches: no Error key.
	hi := hm.Relays[1]
	r := &Relay{Type: ForwardingType, State: Established, PeerAddr: peer, LocalIndex: 1, RemoteIndex: 2}
	hi.relayState = RelayState{
		relayForByAddr: map[netip.Addr]*Relay{peer: r},
		relayForByIdx:  map[uint32]*Relay{r.LocalIndex: r},
	}
	hm.Hosts[relay] = hi

	out.Reset()
	require.NoError(t, sshPrintRelays(ifce, &sshPrintTunnelFlags{}, nil, commands.NewStringWriter(out)))
	assert.JSONEq(t, `{"Relays":[{"NebulaAddr":"10.0.0.1","RelayForAddrs":[{"Type":"forwarding","State":"established","PeerAddr":"10.0.0.2","LocalIndex":1,"RemoteIndex":2,"RelayedThrough":null}]}]}`, out.String())

	// And an index mismatch names it.
	hm.Relays[7] = hi
	delete(hm.Relays, 1)
	out.Reset()
	require.NoError(t, sshPrintRelays(ifce, &sshPrintTunnelFlags{}, nil, commands.NewStringWriter(out)))
	assert.Contains(t, out.String(), `"Error":"hostmap LocalIndex '7' does not match RelayState LocalIndex"`)
}
