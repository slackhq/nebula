package nebula

import (
	"log/slog"
	"net/netip"
	"sync"
	"testing"

	"github.com/rcrowley/go-metrics"
	"github.com/slackhq/nebula/header"
	"github.com/slackhq/nebula/udp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newWrongResponderManager() (*HandshakeManager, netip.Addr, ViaSender) {
	l := slog.New(slog.DiscardHandler)
	hm := NewHandshakeManager(l, newHostMap(l), newTestLighthouse(), &udp.NoopConn{}, defaultHandshakeConfig)
	hm.metricInitiated = metrics.NewCounter()
	hm.f = &Interface{cachedPacketMetrics: &cachedPacketMetrics{
		sent: metrics.NewCounter(), dropped: metrics.NewCounter(),
	}}
	return hm, netip.MustParseAddr("10.0.0.3"), ViaSender{UdpAddr: netip.MustParseAddrPort("198.51.100.7:4242")}
}

func TestWrongResponderRetry(t *testing.T) {
	tests := []struct {
		name            string
		description     string
		expectedOutcome string
		oldPackets      int
		newPackets      int
		replacement     bool
		relayed         bool
		wantTransferred int
		wantDropped     int64
	}{
		{
			name:            "fresh",
			description:     "no sender starts a replacement",
			expectedOutcome: "all old packets transfer",
			oldPackets:      2,
			wantTransferred: 2,
		},
		{
			name:            "empty",
			description:     "neither cache has packets",
			expectedOutcome: "retry has an empty cache",
		},
		{
			name:            "fresh_full",
			description:     "old cache is at the limit",
			expectedOutcome: "all 100 packets transfer",
			oldPackets:      100,
			wantTransferred: 100,
		},
		{
			name:            "replacement_empty",
			description:     "replacement exists without packets",
			expectedOutcome: "all old packets transfer",
			oldPackets:      2,
			replacement:     true,
			wantTransferred: 2,
		},
		{
			name:            "replacement_only",
			description:     "old cache is empty",
			expectedOutcome: "replacement packets survive",
			newPackets:      2,
			replacement:     true,
		},
		{
			name:            "merge",
			description:     "both caches contain packets",
			expectedOutcome: "replacement packets precede old packets",
			oldPackets:      2,
			newPackets:      2,
			replacement:     true,
			wantTransferred: 2,
		},
		{
			name:            "exact_limit",
			description:     "combined caches reach the limit",
			expectedOutcome: "100 packets survive without drops",
			oldPackets:      1,
			newPackets:      99,
			replacement:     true,
			wantTransferred: 1,
		},
		{
			name:            "overflow",
			description:     "combined caches exceed the limit by one",
			expectedOutcome: "one old packet is counted as dropped",
			oldPackets:      2,
			newPackets:      99,
			replacement:     true,
			wantTransferred: 1,
			wantDropped:     1,
		},
		{
			name:            "both_full",
			description:     "both caches are full",
			expectedOutcome: "replacement survives and 100 old packets are counted as dropped",
			oldPackets:      100,
			newPackets:      100,
			replacement:     true,
			wantDropped:     100,
		},
		{
			name:            "relayed",
			description:     "wrong response arrived over a relay",
			expectedOutcome: "packets merge without blocking a UDP address",
			oldPackets:      2,
			newPackets:      1,
			replacement:     true,
			relayed:         true,
			wantTransferred: 2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Logf("%s; expected: %s", tt.description, tt.expectedOutcome)
			hm, vpnAddr, via := newWrongResponderManager()
			via.IsRelayed = tt.relayed
			var old, replacement *HandshakeHostInfo
			replayed := make([]byte, 0, tt.newPackets+tt.wantTransferred)
			callback := func(mt header.MessageType, st header.MessageSubType, _ *HostInfo, packet, _, _ []byte) {
				assert.Equal(t, header.Message, mt)
				assert.Equal(t, header.MessageNone, st)
				replayed = append(replayed, packet[0])
			}
			cache := func(hh *HandshakeHostInfo, count int, id byte) {
				for range count {
					hh.cachePacket(hm.l, header.Message, header.MessageNone, []byte{id}, callback, hm.f.cachedPacketMetrics)
					id++
				}
			}
			hm.StartHandshake(vpnAddr, func(hh *HandshakeHostInfo) {
				old = hh
				cache(hh, tt.oldPackets, 0)
			})
			oldPackets := append([]*cachedPacket(nil), old.packetStore...)
			old.Lock()
			defer old.Unlock()
			hm.DeleteHostInfo(old.hostinfo)

			// Reproduce the gap between DeleteHostInfo and retryHandshake without
			// sleeps: another sender has already created and populated a replacement.
			if tt.replacement {
				hm.StartHandshake(vpnAddr, func(hh *HandshakeHostInfo) {
					replacement = hh
					cache(hh, tt.newPackets, 100)
				})
			}
			var wantPackets []*cachedPacket
			if replacement != nil {
				wantPackets = append(wantPackets, replacement.packetStore...)
			}
			wantPackets = append(wantPackets, oldPackets[:tt.wantTransferred]...)

			hm.retryHandshake(old, via)
			retried := hm.vpnIps[vpnAddr]
			require.NotNil(t, retried)
			assert.NotSame(t, old, retried)
			if replacement != nil {
				assert.Same(t, replacement, retried)
			}
			require.Len(t, retried.packetStore, len(wantPackets))
			wantReplay := make([]byte, 0, len(wantPackets))
			for i, cp := range retried.packetStore {
				require.Same(t, wantPackets[i], cp, "packet %d retains its payload and callback", i)
				wantReplay = append(wantReplay, wantPackets[i].packet[0])
				cp.callback(cp.messageType, cp.messageSubType, retried.hostinfo, cp.packet, nil, nil)
			}
			assert.Equal(t, wantReplay, replayed)
			assert.Empty(t, old.packetStore)
			assert.Equal(t, tt.wantDropped, hm.f.cachedPacketMetrics.dropped.Count())
			assert.Zero(t, hm.f.cachedPacketMetrics.sent.Count(), "transfer does not send packets")
			if tt.relayed {
				assert.Empty(t, retried.hostinfo.remotes.CopyBlockedRemotes())
			} else {
				assert.Equal(t, []netip.AddrPort{via.UdpAddr}, retried.hostinfo.remotes.CopyBlockedRemotes())
			}
		})
	}
}

func TestWrongResponderRetryConcurrentAdmission(t *testing.T) {
	tests := []struct {
		name            string
		description     string
		expectedOutcome string
		oldPackets      int
		newPackets      int
		wantCached      int
		wantDropped     int64
	}{
		{
			name:            "fits",
			description:     "retry and another sender contend for the replacement",
			expectedOutcome: "all 31 packets survive once",
			oldPackets:      10,
			newPackets:      20,
			wantCached:      31,
		},
		{
			name:            "full",
			description:     "retry and another sender exceed capacity",
			expectedOutcome: "100 packets survive and 21 drops are counted",
			oldPackets:      100,
			newPackets:      20,
			wantCached:      100,
			wantDropped:     21,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Logf("%s; expected: %s", tt.description, tt.expectedOutcome)
			hm, vpnAddr, via := newWrongResponderManager()
			var old *HandshakeHostInfo
			cache := func(hh *HandshakeHostInfo, id byte) {
				hh.cachePacket(hm.l, header.Message, header.MessageNone, []byte{id}, nil, hm.f.cachedPacketMetrics)
			}
			hm.StartHandshake(vpnAddr, func(hh *HandshakeHostInfo) {
				old = hh
				for i := range tt.oldPackets {
					cache(hh, byte(i))
				}
			})
			hm.DeleteHostInfo(old.hostinfo)
			// This packet must survive whichever goroutine acquires the manager lock first.
			hm.StartHandshake(vpnAddr, func(hh *HandshakeHostInfo) { cache(hh, 200) })
			start := make(chan struct{})
			var workers sync.WaitGroup
			workers.Go(func() {
				<-start
				old.Lock()
				defer old.Unlock()
				hm.retryHandshake(old, via)
			})
			workers.Go(func() {
				<-start
				id := byte(100)
				for range tt.newPackets {
					hm.StartHandshake(vpnAddr, func(hh *HandshakeHostInfo) { cache(hh, id) })
					id++
				}
			})
			close(start)
			workers.Wait()
			seen := make(map[byte]bool)
			for _, cp := range hm.vpnIps[vpnAddr].packetStore {
				require.False(t, seen[cp.packet[0]], "no duplicate packets")
				seen[cp.packet[0]] = true
			}
			assert.True(t, seen[200], "the replacement's original packet survives")
			assert.Len(t, seen, tt.wantCached)
			assert.Equal(t, tt.wantDropped, hm.f.cachedPacketMetrics.dropped.Count())
			assert.Empty(t, old.packetStore)
		})
	}
}

func BenchmarkWrongResponderRetry(b *testing.B) {
	for _, bb := range []struct {
		name                   string
		oldPackets, newPackets int
	}{
		{name: "empty", oldPackets: 0, newPackets: 0},
		{name: "transfer_1", oldPackets: 1, newPackets: 0},
		{name: "transfer_100", oldPackets: 100, newPackets: 0},
		{name: "merge", oldPackets: 50, newPackets: 50},
		{name: "full", oldPackets: 100, newPackets: 100},
	} {
		b.Run(bb.name, func(b *testing.B) {
			hm, vpnAddr, via := newWrongResponderManager()
			old := &HandshakeHostInfo{hostinfo: &HostInfo{vpnAddrs: []netip.Addr{vpnAddr}}}
			oldPackets := make([]*cachedPacket, bb.oldPackets)
			newPackets := make([]*cachedPacket, bb.newPackets)
			var replacement *HandshakeHostInfo
			hm.StartHandshake(vpnAddr, func(hh *HandshakeHostInfo) { replacement = hh })
			replacement.hostinfo.remotes.BlockRemote(via)
			old.Lock()
			defer old.Unlock()
			b.ReportAllocs()
			for b.Loop() {
				old.packetStore = oldPackets
				replacement.packetStore = newPackets
				hm.retryHandshake(old, via)
			}
		})
	}
}
