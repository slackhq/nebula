package nebula

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/flynn/noise"
	"github.com/gaissmai/bart"
	"github.com/rcrowley/go-metrics"
	"github.com/slackhq/nebula/cert"
	ct "github.com/slackhq/nebula/cert_test"
	"github.com/slackhq/nebula/handshake"
	"github.com/slackhq/nebula/header"
	"github.com/slackhq/nebula/udp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type packetCacheLog struct {
	slog.Handler
	observe func(slog.Record)
}

func (h *packetCacheLog) Enabled(_ context.Context, level slog.Level) bool {
	return level >= slog.LevelInfo
}
func (h *packetCacheLog) Handle(_ context.Context, record slog.Record) error {
	if record.Message == "Handshake message received" {
		h.observe(record)
	}
	return nil
}

type packetCacheFixture struct {
	manager  *HandshakeManager
	pending  *HandshakeHostInfo
	response []byte
	via      ViaSender
}

// Use real Noise messages and verified certificates so completion follows the
// same path as service handshakes. beforeVerify is a test-only scheduling barrier.
func newPacketCacheFixture(tb testing.TB, logger *slog.Logger, beforeVerify func()) packetCacheFixture {
	tb.Helper()
	ca, _, caKey, _ := ct.NewTestCaCert(cert.Version2, cert.Curve_CURVE25519, time.Time{}, time.Time{}, nil, nil, nil)
	pool := ct.NewTestCAPool(ca)
	credential := func(name, network string) *handshake.Credential {
		certificate, _, pemKey, _ := ct.NewTestCert(cert.Version2, cert.Curve_CURVE25519, ca, caKey,
			name, ca.NotBefore(), ca.NotAfter(), []netip.Prefix{netip.MustParsePrefix(network)}, nil, nil)
		key, _, _, err := cert.UnmarshalPrivateKeyFromPEM(pemKey)
		require.NoError(tb, err)
		raw, err := certificate.MarshalForHandshakes()
		require.NoError(tb, err)
		suite := noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256)
		return handshake.NewCredential(certificate, raw, key, suite)
	}
	local := credential("initiator", "10.0.0.1/24")
	remote := credential("responder", "10.0.0.2/24")
	machine := func(cred *handshake.Credential, initiator bool, index uint32) *handshake.Machine {
		result, err := handshake.NewMachine(cert.Version2,
			func(cert.Version) *handshake.Credential { return cred },
			func(certificate cert.Certificate) (*cert.CachedCertificate, error) {
				if initiator && beforeVerify != nil {
					beforeVerify()
				}
				return pool.VerifyCertificate(time.Now(), certificate)
			}, func() (uint32, error) { return index, nil }, initiator, header.HandshakeIXPSK0)
		require.NoError(tb, err)
		return result
	}
	initiator := machine(local, true, 1)
	request, err := initiator.Initiate(nil)
	require.NoError(tb, err)
	response, _, err := machine(remote, false, 2).ProcessPacket(nil, request)
	require.NoError(tb, err)

	hostMap := newHostMap(logger)
	ranges := []netip.Prefix{}
	hostMap.preferredRanges.Store(&ranges)
	lighthouse := newTestLighthouse()
	lighthouse.l = logger
	lighthouse.remoteAllowList.Store(&RemoteAllowList{})
	manager := NewHandshakeManager(logger, hostMap, lighthouse, &udp.NoopConn{}, defaultHandshakeConfig)
	manager.metricInitiated = metrics.NewCounter()
	manager.f = &Interface{
		l: logger, hostMap: hostMap, lightHouse: lighthouse, handshakeManager: manager,
		myVpnAddrsTable: new(bart.Lite), myVpnNetworksTable: new(bart.Lite),
		cachedPacketMetrics: &cachedPacketMetrics{sent: metrics.NewCounter(), dropped: metrics.NewCounter()},
		metricHandshakes:    metrics.NewHistogram(metrics.NewUniformSample(32)),
	}
	manager.f.myVpnAddrsTable.Insert(netip.MustParsePrefix("10.0.0.1/32"))
	manager.f.myVpnNetworksTable.Insert(netip.MustParsePrefix("10.0.0.0/24"))
	var pending *HandshakeHostInfo
	manager.StartHandshake(netip.MustParseAddr("10.0.0.2"), func(hh *HandshakeHostInfo) { pending = hh })
	pending.hostinfo.localIndexId = 1
	pending.machine = initiator
	manager.indexes[1] = pending
	return packetCacheFixture{manager: manager, pending: pending, response: response,
		via: ViaSender{UdpAddr: netip.MustParseAddrPort("198.51.100.7:4242")}}
}

func (f packetCacheFixture) enqueue(packet []byte, callback packetCallback) {
	f.manager.StartHandshake(netip.MustParseAddr("10.0.0.2"), func(hh *HandshakeHostInfo) {
		hh.cachePacket(f.manager.l, header.Message, 0, packet, callback, f.manager.f.cachedPacketMetrics)
	})
}

func TestHandshakePacketCacheCompletion(t *testing.T) {
	tests := []struct {
		name, description              string
		packets, wantSent, wantDropped int
		malformed, duplicate           bool
		wantComplete                   bool
	}{
		{"empty", "an empty handshake publishes before logging zero", 0, 0, 0, false, false, true},
		{"one", "one copied packet is replayed once", 1, 1, 0, false, false, true},
		{"typical", "multiple packets preserve admission order", 4, 4, 0, false, false, true},
		{"below_limit", "the penultimate slot is accepted", maxCachedPackets - 1, maxCachedPackets - 1, 0, false, false, true},
		{"at_limit", "the final cache slot is accepted", maxCachedPackets, maxCachedPackets, 0, false, false, true},
		{"over_limit", "excess packets are dropped and counted", maxCachedPackets + 1, maxCachedPackets, 1, false, false, true},
		{"malformed", "a rejected response never drains the cache", 2, 0, 0, true, false, false},
		{"duplicate", "a late duplicate cannot replay the cache twice", 2, 2, 0, false, true, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Log(tc.description)
			var fixture packetCacheFixture
			var counts []int64
			var pendingAtLog []bool
			logger := slog.New(&packetCacheLog{Handler: slog.DiscardHandler, observe: func(record slog.Record) {
				pendingAtLog = append(pendingAtLog, fixture.manager.queryIndex(1) != nil)
				record.Attrs(func(attr slog.Attr) bool {
					if attr.Key == "sentCachedPackets" {
						counts = append(counts, attr.Value.Int64())
					}
					return true
				})
			}})
			fixture = newPacketCacheFixture(t, logger, nil)
			received := []byte{}
			callback := func(_ header.MessageType, _ header.MessageSubType, _ *HostInfo, packet, _, _ []byte) {
				received = append(received, packet...)
			}
			for i := range tc.packets {
				packet := []byte{byte(i)}
				fixture.enqueue(packet, callback)
				packet[0] = 255 // mutations must not leak into the queued copy
			}
			response := fixture.response
			if tc.malformed {
				response = nil
			}
			fixture.manager.continueHandshake(fixture.via, fixture.pending, response)
			if tc.duplicate {
				fixture.manager.continueHandshake(fixture.via, fixture.pending, response)
			}
			want := make([]byte, tc.wantSent)
			for i := range want {
				want[i] = byte(i)
			}
			assert.Equal(t, want, received)
			assert.Equal(t, int64(tc.wantSent), fixture.manager.f.cachedPacketMetrics.sent.Count())
			assert.Equal(t, int64(tc.wantDropped), fixture.manager.f.cachedPacketMetrics.dropped.Count())
			if tc.wantComplete {
				assert.Equal(t, []int64{int64(tc.wantSent)}, counts)
				assert.Equal(t, []bool{false}, pendingAtLog, "completion must exclude further cache writers before logging")
				assert.Same(t, fixture.pending.hostinfo, fixture.manager.mainHostMap.QueryVpnAddr(netip.MustParseAddr("10.0.0.2")))
			} else {
				assert.Empty(t, counts)
				assert.Nil(t, fixture.manager.mainHostMap.QueryVpnAddr(netip.MustParseAddr("10.0.0.2")))
			}
		})
	}
}

func TestHandshakePacketCacheConcurrentCompletion(t *testing.T) {
	for _, tc := range []struct {
		name, description string
		packets, wantSent int
	}{
		{"one", "completion includes an admitted callback that still holds the manager lock", 1, 1},
		{"full", "completion includes all admitted packets through the cache boundary", maxCachedPackets, maxCachedPackets},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Log(tc.description)
			verifying, resumeVerify := make(chan struct{}), make(chan struct{})
			cacheHeld, releaseCache := make(chan struct{}), make(chan struct{})
			var verifyOnce, cacheOnce sync.Once
			// Release both barriers even if an assertion fails; join all launched workers.
			var workers sync.WaitGroup
			t.Cleanup(func() {
				verifyOnce.Do(func() { close(resumeVerify) })
				cacheOnce.Do(func() { close(releaseCache) })
				workers.Wait()
			})
			var fixture packetCacheFixture
			observed := make(chan bool, 1)
			logger := slog.New(&packetCacheLog{Handler: slog.DiscardHandler, observe: func(slog.Record) {
				observed <- fixture.manager.queryIndex(1) == nil
			}})
			fixture = newPacketCacheFixture(t, logger, func() { close(verifying); <-resumeVerify })
			finished := make(chan struct{})
			workers.Go(func() {
				fixture.manager.continueHandshake(fixture.via, fixture.pending, fixture.response)
				close(finished)
			})
			waitPacketCacheSignal(t, verifying)
			received := []byte{}
			cached := make(chan struct{})
			workers.Go(func() {
				fixture.manager.StartHandshake(netip.MustParseAddr("10.0.0.2"), func(hh *HandshakeHostInfo) {
					for i := range tc.packets {
						hh.cachePacket(logger, header.Message, 0, []byte{byte(i)},
							func(_ header.MessageType, _ header.MessageSubType, _ *HostInfo, packet, _, _ []byte) {
								received = append(received, packet...)
							},
							fixture.manager.f.cachedPacketMetrics)
					}
					close(cacheHeld)
					<-releaseCache
				})
				close(cached)
			})
			waitPacketCacheSignal(t, cacheHeld)
			verifyOnce.Do(func() { close(resumeVerify) })
			cacheOnce.Do(func() { close(releaseCache) })
			waitPacketCacheSignal(t, cached)
			waitPacketCacheSignal(t, finished)
			assert.True(t, <-observed, "logged before the pending handshake was removed")
			want := make([]byte, tc.wantSent)
			for i := range want {
				want[i] = byte(i)
			}
			assert.Equal(t, want, received)
			assert.Equal(t, int64(tc.wantSent), fixture.manager.f.cachedPacketMetrics.sent.Count())
		})
	}
}

func waitPacketCacheSignal(t *testing.T, signal <-chan struct{}) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(5 * time.Second):
		t.Fatal("handshake worker did not reach its barrier")
	}
}

func BenchmarkHandshakePacketCache(b *testing.B) {
	for _, count := range []int{0, 8, maxCachedPackets} {
		b.Run(fmt.Sprintf("admission/%d", count), func(b *testing.B) {
			logger := slog.New(slog.DiscardHandler)
			counters := &cachedPacketMetrics{sent: metrics.NewCounter(), dropped: metrics.NewCounter()}
			manager := NewHandshakeManager(logger, nil, nil, nil, defaultHandshakeConfig)
			address := netip.MustParseAddr("10.0.0.2")
			pending := &HandshakeHostInfo{hostinfo: &HostInfo{vpnAddrs: []netip.Addr{address}}}
			manager.vpnIps[address] = pending
			packet := make([]byte, 128)
			b.ReportAllocs()
			for b.Loop() {
				pending.packetStore = pending.packetStore[:0]
				for range count {
					manager.StartHandshake(address, func(hh *HandshakeHostInfo) { hh.cachePacket(logger, header.Message, 0, packet, nil, counters) })
				}
			}
		})
		b.Run(fmt.Sprintf("completion/%d", count), func(b *testing.B) {
			logger := slog.New(slog.DiscardHandler)
			packet := make([]byte, 128)
			b.ReportAllocs()
			for b.Loop() {
				b.StopTimer()
				fixture := newPacketCacheFixture(b, logger, nil)
				for range count {
					fixture.enqueue(packet, func(header.MessageType, header.MessageSubType, *HostInfo, []byte, []byte, []byte) {})
				}
				b.StartTimer()
				fixture.manager.continueHandshake(fixture.via, fixture.pending, fixture.response)
			}
		})
	}
}
