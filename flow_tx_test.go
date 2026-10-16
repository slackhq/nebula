//go:build linux && !android && !e2e_testing

package nebula

import (
	"testing"

	"github.com/flynn/noise"
	"github.com/slackhq/nebula/firewall"
	"github.com/slackhq/nebula/overlay/batch"
	"github.com/slackhq/nebula/overlay/tio"
	"github.com/stretchr/testify/require"
)

// TestReservedEncryptionMatchesInline encrypts a batch with counters reserved up front: the receiver accepts every
// segment, in order.
func TestReservedEncryptionMatchesInline(t *testing.T) {
	sender, receiver := newFlowTestPair(t, noise.CipherChaChaPoly)
	packets, want := flowTestBatches(1, 3, 3, 9)
	r := txReserver{f: sender.f}
	items := r.collect(nil, packets[0], &firewall.ParsedPacket{}, make([]byte, mtu), 0, nil)
	require.Equal(t, uint64(len(want)), r.tunnels[0].n)
	sb := batch.NewSendBatch(sender.conn, 128, 65536)
	for _, it := range r.reserve(items) {
		sender.f.encryptTxItem(&it, make([]byte, 12), sb)
	}
	sender.f.flushSendBatch(sb, 0)
	require.Equal(t, want, decryptWire(t, receiver, sender.conn.captured()))
}

// TestSegmentCount checks segmentCount predicts exactly the segments tio.SegmentSuperpacket cuts, odd tails included.
func TestSegmentCount(t *testing.T) {
	require.Equal(t, uint64(1), segmentCount(tio.Packet{Bytes: make([]byte, 60)}))
	for _, segs := range []int{1, 2, 3, 45} {
		for _, tail := range []int{0, 1, flowTestMSS - 1} {
			pkt := flowTCPSuperpacket(0, 0, segs)
			pkt.Bytes = pkt.Bytes[:len(pkt.Bytes)-tail]
			pkt.GSO = tio.GSOInfo{Size: flowTestMSS, HdrLen: 40, CsumStart: 20, Proto: tio.GSOProtoTCP}
			want, got := segmentCount(pkt), uint64(0)
			require.NoError(t, tio.SegmentSuperpacket(pkt, func([]byte) error { got++; return nil }))
			require.Equal(t, want, got, "segs %d tail %d", segs, tail)
		}
	}
}
