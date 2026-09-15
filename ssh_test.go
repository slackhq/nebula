package nebula

import (
	"io"
	"net/netip"
	"strings"
	"testing"

	"github.com/slackhq/nebula/sshd"
	"github.com/slackhq/nebula/test"
	"github.com/slackhq/nebula/udp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sshStringRecorder is a minimal sshd.StringWriter that captures output.
type sshStringRecorder struct{ buf strings.Builder }

func (s *sshStringRecorder) WriteLine(v string) error  { s.buf.WriteString(v + "\n"); return nil }
func (s *sshStringRecorder) Write(v string) error      { s.buf.WriteString(v); return nil }
func (s *sshStringRecorder) WriteBytes(b []byte) error { s.buf.Write(b); return nil }
func (s *sshStringRecorder) GetWriter() io.Writer      { return io.Discard }

var _ sshd.StringWriter = (*sshStringRecorder)(nil)

// Regression test: `create-tunnel -address <ip:port> <vpn>` used to crash the
// daemon. StartHandshake returns a HostInfo whose remotes (*RemoteList) is nil
// (it is populated lazily by the handshake worker), so SetRemote dereferenced
// nil and SIGSEGV'd. The handler must initialize remotes first — and the
// operator-provided address must actually be applied.
func TestSSHCreateTunnelWithAddress(t *testing.T) {
	l := test.NewLogger()
	mainHM := newHostMap(l)
	preferredRanges := []netip.Prefix{netip.MustParsePrefix("10.1.1.1/24")}
	mainHM.preferredRanges.Store(&preferredRanges)
	lh := newTestLighthouse()
	hm := NewHandshakeManager(l, mainHM, lh, &udp.NoopConn{}, defaultHandshakeConfig)

	ifce := &Interface{
		hostMap:          mainHM,
		handshakeManager: hm,
		lightHouse:       lh,
		l:                l,
	}
	hm.f = ifce

	vpn := netip.MustParseAddr("172.1.1.2")
	flags := &sshCreateTunnelFlags{Address: "198.51.100.97:4242"}
	w := &sshStringRecorder{}

	require.NoError(t, sshCreateTunnel(ifce, flags, []string{vpn.String()}, w))
	assert.Equal(t, "Created", strings.TrimSpace(w.buf.String()))

	// The new handshake must carry a RemoteList and the operator-provided remote.
	hi := hm.QueryVpnAddr(vpn)
	require.NotNil(t, hi)
	require.NotNil(t, hi.remotes)
	assert.Equal(t, netip.MustParseAddrPort("198.51.100.97:4242"), hi.remote)
}
