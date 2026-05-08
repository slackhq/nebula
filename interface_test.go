package nebula

import (
	"context"
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
)

// Test_emitStats_primesGauges verifies issue #907: certificate gauges should
// not read 0 between goroutine launch and the first ticker fire. The ticker
// interval here is set far longer than the test runtime so that any non-zero
// reading must come from the synchronous prime call, not a tick.
func Test_emitStats_primesGauges(t *testing.T) {
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
	}
	ifce.pki.cs.Store(cs)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		ifce.emitStats(ctx, time.Hour) // ticker interval that will never fire
		close(done)
	}()

	// Give the goroutine a beat to run the synchronous prime call. This is
	// generous: emit() is microseconds of work in practice.
	assert.Eventually(t, func() bool {
		return metrics.GetOrRegisterGauge("certificate.ttl_seconds", nil).Value() > 0
	}, time.Second, 10*time.Millisecond, "certificate.ttl_seconds should be primed before first tick")

	ttl := metrics.GetOrRegisterGauge("certificate.ttl_seconds", nil).Value()
	assert.Positive(t, ttl, int64(0))
	assert.LessOrEqual(t, ttl, int64(3600))

	assert.Equal(t, int64(cert.Version1), metrics.GetOrRegisterGauge("certificate.initiating_version", nil).Value())
	assert.Equal(t, int64(cert.Version1), metrics.GetOrRegisterGauge("certificate.max_version", nil).Value())

	cancel()
	<-done
}
