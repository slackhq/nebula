//go:build linux || darwin

package nebula

import (
	"net/netip"
	"testing"
	"time"

	"github.com/rcrowley/go-metrics"
	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/firewall"
	"github.com/slackhq/nebula/overlay/overlaytest"
	"github.com/slackhq/nebula/test"
	"github.com/slackhq/nebula/udp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Priming before the first tick (issue #907) is Start's job, see TestStatsServer_Start_primes.
func Test_statsEmitter_setsGauges(t *testing.T) {
	defer metrics.DefaultRegistry.UnregisterAll()

	l := test.NewLogger()
	hostMap := newHostMap(l)
	preferredRanges := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	hostMap.preferredRanges.Store(&preferredRanges)

	notAfter := time.Now().Add(time.Hour)
	cs := &CertState{
		initiatingVersion: cert.Version1,
		privateKey:        []byte{},
		v1Cert:            &dummyCert{version: cert.Version1, notAfter: notAfter},
		v1Credential:      nil,
	}

	lh := newTestLighthouse()
	ifce := &Interface{
		hostMap:          hostMap,
		inside:           &overlaytest.NoopTun{},
		outside:          &udp.NoopConn{},
		firewall:         &Firewall{Conntrack: &FirewallConntrack{Conns: map[firewall.Packet]*conn{}}},
		lightHouse:       lh,
		pki:              &PKI{},
		handshakeManager: NewHandshakeManager(l, hostMap, lh, &udp.NoopConn{}, defaultHandshakeConfig),
		l:                l,
		// On linux, udp.NewUDPStatsEmitter indexes writers[0] and asserts to
		// *udp.StdConn. A zero value works: getMemInfo sees a nil rawConn,
		// returns an error, and the emitter falls through to a no-op.
		writers: []udp.Conn{&udp.StdConn{}},
	}
	ifce.pki.cs.Store(cs)

	ttlGauge := metrics.GetOrRegisterGauge("certificate.ttl_seconds", nil)
	require.Zero(t, ttlGauge.Value(), "gauge should be zero before the emitter runs")

	ifce.statsEmitter()()

	ttl := ttlGauge.Value()
	assert.Positive(t, ttl, "ttl gauge should be set by one run of the emitter")
	assert.LessOrEqual(t, ttl, int64(3600))
	assert.Equal(t, int64(cert.Version1), metrics.GetOrRegisterGauge("certificate.initiating_version", nil).Value())
	assert.Equal(t, int64(cert.Version1), metrics.GetOrRegisterGauge("certificate.max_version", nil).Value())
}
