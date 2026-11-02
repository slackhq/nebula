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

// retryOutcome counts the packets kept from each cache, old first.
type retryOutcome struct {
	old, replacement int
	dropped          int64
}

func TestWrongResponderRetry(t *testing.T) {
	tests := []struct {
		name        string
		description string
		oldPackets  int
		newPackets  int
		replacement bool
		relayed     bool
		expected    retryOutcome
	}{
		{
			name:        "fresh",
			description: "no sender starts a replacement, so all old packets transfer",
			oldPackets:  2,
			expected:    retryOutcome{old: 2},
		},
		{
			name:        "empty",
			description: "neither cache has packets, so the retry starts empty",
			expected:    retryOutcome{},
		},
		{
			name:        "fresh_full",
			description: "an old cache at the limit transfers whole",
			oldPackets:  maxCachedPackets,
			expected:    retryOutcome{old: maxCachedPackets},
		},
		{
			name:        "replacement_empty",
			description: "a replacement without packets receives all old packets",
			oldPackets:  2,
			replacement: true,
			expected:    retryOutcome{old: 2},
		},
		{
			name:        "replacement_only",
			description: "with an empty old cache the replacement packets survive",
			newPackets:  2,
			replacement: true,
			expected:    retryOutcome{replacement: 2},
		},
		{
			name:        "merge",
			description: "old packets precede the newer replacement packets",
			oldPackets:  2,
			newPackets:  2,
			replacement: true,
			expected:    retryOutcome{old: 2, replacement: 2},
		},
		{
			name:        "exact_limit",
			description: "combined caches reach the limit without drops",
			oldPackets:  1,
			newPackets:  maxCachedPackets - 1,
			replacement: true,
			expected:    retryOutcome{old: 1, replacement: maxCachedPackets - 1},
		},
		{
			name:        "overflow",
			description: "one packet over the limit drops the newest replacement packet",
			oldPackets:  2,
			newPackets:  maxCachedPackets - 1,
			replacement: true,
			expected:    retryOutcome{old: 2, replacement: maxCachedPackets - 2, dropped: 1},
		},
		{
			name:        "both_full",
			description: "with both caches full the old cache survives and the replacement is dropped",
			oldPackets:  maxCachedPackets,
			newPackets:  maxCachedPackets,
			replacement: true,
			expected:    retryOutcome{old: maxCachedPackets, dropped: maxCachedPackets},
		},
		{
			name:        "relayed",
			description: "a relayed wrong response merges without blocking a UDP address",
			oldPackets:  2,
			newPackets:  1,
			replacement: true,
			relayed:     true,
			expected:    retryOutcome{old: 2, replacement: 1},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Log(tt.description)
			hm, vpnAddr, via := newWrongResponderManager()
			via.IsRelayed = tt.relayed
			var old, replacement *HandshakeHostInfo
			var replayed []byte
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
			var newPackets []*cachedPacket
			if tt.replacement {
				hm.StartHandshake(vpnAddr, func(hh *HandshakeHostInfo) {
					replacement = hh
					cache(hh, tt.newPackets, 100)
				})
				newPackets = append(newPackets, replacement.packetStore...)
			}
			var wantPackets []*cachedPacket
			wantPackets = append(wantPackets, oldPackets[:tt.expected.old]...)
			wantPackets = append(wantPackets, newPackets[:tt.expected.replacement]...)

			hm.retryHandshake(old, via)
			retried := hm.vpnIps[vpnAddr]
			require.NotNil(t, retried)
			assert.NotSame(t, old, retried)
			if replacement != nil {
				assert.Same(t, replacement, retried)
			}
			require.Len(t, retried.packetStore, len(wantPackets))
			var wantReplay []byte
			for i, cp := range retried.packetStore {
				require.Same(t, wantPackets[i], cp, "packet %d retains its payload and callback", i)
				wantReplay = append(wantReplay, wantPackets[i].packet[0])
				cp.callback(cp.messageType, cp.messageSubType, retried.hostinfo, cp.packet, nil, nil)
			}
			assert.Equal(t, wantReplay, replayed)
			assert.Empty(t, old.packetStore)
			assert.Equal(t, tt.expected.dropped, hm.f.cachedPacketMetrics.dropped.Count())
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
		name        string
		description string
		oldPackets  int
		newPackets  int
		expected    retryOutcome // replacement counts the other senders' packets
	}{
		{
			name:        "fits",
			description: "retry and another sender contend for the replacement; every packet survives once",
			oldPackets:  10,
			newPackets:  20,
			expected:    retryOutcome{old: 10, replacement: 21},
		},
		{
			name:        "full",
			description: "retry and another sender exceed capacity; the old cache survives and 21 drops are counted",
			oldPackets:  maxCachedPackets,
			newPackets:  20,
			expected:    retryOutcome{old: maxCachedPackets, dropped: 21},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Log(tt.description)
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
			// Ensure a replacement exists whichever goroutine acquires the manager lock first.
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
			store := hm.vpnIps[vpnAddr].packetStore
			require.Len(t, store, tt.expected.old+tt.expected.replacement)
			for i := range tt.expected.old {
				assert.Equal(t, byte(i), store[i].packet[0], "old packets lead in arrival order")
			}
			seen := make(map[byte]bool)
			for _, cp := range store {
				require.False(t, seen[cp.packet[0]], "no duplicate packets")
				seen[cp.packet[0]] = true
			}
			assert.Equal(t, tt.expected.dropped, hm.f.cachedPacketMetrics.dropped.Count())
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
