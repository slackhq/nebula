package batch

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/slackhq/nebula/firewall"
)

// parseV4InboundBaseline mirrors what outside.go's parseV4(incoming=true)
// does, so the "split" bench measures the *current* state: firewall-side
// parse, then m.Commit re-parses inside the coalescer. Two walks per
// packet. Kept faithful in shape (one read per field, AddrFromSlice for
// the addrs) so the CPU profile matches the production parseV4.
func parseV4InboundBaseline(pkt []byte, fp *firewall.Packet) bool {
	if len(pkt) < 20 {
		return false
	}
	ihl := int(pkt[0]&0x0f) << 2
	if ihl < 20 {
		return false
	}
	flagsfrags := binary.BigEndian.Uint16(pkt[6:8])
	fp.Fragment = (flagsfrags & 0x1FFF) != 0
	fp.Protocol = pkt[9]
	minLen := ihl
	if !fp.Fragment {
		if fp.Protocol == firewall.ProtoICMP {
			minLen += 4 + 2
		} else {
			minLen += 4
		}
	}
	if len(pkt) < minLen {
		return false
	}
	fp.RemoteAddr, _ = netip.AddrFromSlice(pkt[12:16])
	fp.LocalAddr, _ = netip.AddrFromSlice(pkt[16:20])
	switch {
	case fp.Fragment:
		fp.RemotePort = 0
		fp.LocalPort = 0
	case fp.Protocol == firewall.ProtoICMP:
		fp.RemotePort = binary.BigEndian.Uint16(pkt[ihl+4 : ihl+6])
		fp.LocalPort = 0
	default:
		fp.RemotePort = binary.BigEndian.Uint16(pkt[ihl : ihl+2])
		fp.LocalPort = binary.BigEndian.Uint16(pkt[ihl+2 : ihl+4])
	}
	return true
}

// parseV6InboundBaseline is the v6 analogue: replicates parseV6's
// extension-header walk so the split bench captures its true cost.
func parseV6InboundBaseline(pkt []byte, fp *firewall.Packet) bool {
	dataLen := len(pkt)
	if dataLen < 40 {
		return false
	}
	fp.RemoteAddr, _ = netip.AddrFromSlice(pkt[8:24])
	fp.LocalAddr, _ = netip.AddrFromSlice(pkt[24:40])

	protoAt := 6
	offset := 40
	next := 0
	for {
		if protoAt >= dataLen {
			return false
		}
		proto := pkt[protoAt]
		switch proto {
		case ipProtoESP, ipProtoNoNextHdr:
			fp.Protocol = proto
			fp.RemotePort = 0
			fp.LocalPort = 0
			fp.Fragment = false
			return true
		case ipProtoICMPv6:
			if dataLen < offset+6 {
				return false
			}
			fp.Protocol = proto
			fp.LocalPort = 0
			switch pkt[offset+1] {
			case icmpv6TypeEchoRequest, icmpv6TypeEchoReply:
				fp.RemotePort = binary.BigEndian.Uint16(pkt[offset+4 : offset+6])
			default:
				fp.RemotePort = 0
			}
			fp.Fragment = false
			return true
		case ipProtoTCP, ipProtoUDP:
			if dataLen < offset+4 {
				return false
			}
			fp.Protocol = proto
			fp.RemotePort = binary.BigEndian.Uint16(pkt[offset : offset+2])
			fp.LocalPort = binary.BigEndian.Uint16(pkt[offset+2 : offset+4])
			fp.Fragment = false
			return true
		case ipProtoIPv6Fragment:
			if dataLen < offset+8 {
				return false
			}
			fragmentOffset := binary.BigEndian.Uint16(pkt[offset+2:offset+4]) &^ uint16(0x7)
			if fragmentOffset != 0 {
				fp.Protocol = pkt[offset]
				fp.Fragment = true
				fp.RemotePort = 0
				fp.LocalPort = 0
				return true
			}
			next = 8
		case ipProtoAH:
			if dataLen <= offset+1 {
				return false
			}
			next = int(pkt[offset+1]+2) << 2
		default:
			if dataLen <= offset+1 {
				return false
			}
			next = int(pkt[offset+1]+1) << 3
		}
		if next <= 0 {
			next = 8
		}
		protoAt = offset
		offset = offset + next
	}
}

// runRxSplit drives the split path: faithful inbound parse for the firewall
// side, then m.Commit re-parses to coalesce. v6 controls which baseline
// parser we run.
func runRxSplit(b *testing.B, pkts [][]byte, batchSize int, v6 bool) {
	b.Helper()
	m := NewMultiCoalescer(nopTunWriter{}, true, true)
	var fp firewall.Packet
	b.ReportAllocs()
	b.SetBytes(int64(len(pkts[0])))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pkt := pkts[i%len(pkts)]
		var ok bool
		if v6 {
			ok = parseV6InboundBaseline(pkt, &fp)
		} else {
			ok = parseV4InboundBaseline(pkt, &fp)
		}
		if !ok {
			b.Fatal("baseline parse failed")
		}
		if err := m.Commit(pkt); err != nil {
			b.Fatal(err)
		}
		if (i+1)%batchSize == 0 {
			if err := m.Flush(); err != nil {
				b.Fatal(err)
			}
		}
	}
	_ = m.Flush()
}

// runRxUnified drives the unified path: ParseInbound walks once, filling
// the conntrack key + coalescer hint in parsed; CommitInbound dispatches
// without re-parsing.
func runRxUnified(b *testing.B, pkts [][]byte, batchSize int) {
	b.Helper()
	m := NewMultiCoalescer(nopTunWriter{}, true, true)
	var parsed RxParsed
	b.ReportAllocs()
	b.SetBytes(int64(len(pkts[0])))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pkt := pkts[i%len(pkts)]
		if err := ParseInbound(pkt, &parsed); err != nil {
			b.Fatal(err)
		}
		if err := m.CommitInbound(pkt, &parsed); err != nil {
			b.Fatal(err)
		}
		if (i+1)%batchSize == 0 {
			if err := m.Flush(); err != nil {
				b.Fatal(err)
			}
		}
	}
	_ = m.Flush()
}

// buildUDPv4Bulk returns N UDP packets on a single 5-tuple suitable for the
// UDP coalescer's append path.
func buildUDPv4Bulk(n, payloadLen int) [][]byte {
	pkts := make([][]byte, n)
	pay := make([]byte, payloadLen)
	for i := range n {
		pkts[i] = buildUDPv4(1000, 53, pay)
	}
	return pkts
}

func buildTCPv6Bulk(n, payloadLen int) [][]byte {
	pkts := make([][]byte, n)
	pay := make([]byte, payloadLen)
	seq := uint32(1000)
	for i := range n {
		pkts[i] = buildTCPv6(0, seq, tcpAck, pay)
		seq += uint32(payloadLen)
	}
	return pkts
}

func buildICMPv4Bulk(n int) [][]byte {
	pkts := make([][]byte, n)
	for i := range pkts {
		pkts[i] = buildICMPv4()
	}
	return pkts
}

// === TCPv4 ===

func BenchmarkRxSplitTCPv4(b *testing.B) {
	pkts := buildTCPv4BulkFlow(tcpCoalesceMaxSegs, 1200)
	runRxSplit(b, pkts, tcpCoalesceMaxSegs, false)
}

func BenchmarkRxUnifiedTCPv4(b *testing.B) {
	pkts := buildTCPv4BulkFlow(tcpCoalesceMaxSegs, 1200)
	runRxUnified(b, pkts, tcpCoalesceMaxSegs)
}

// === TCPv4 interleaved (4 flows) ===

func BenchmarkRxSplitTCPv4Interleaved4(b *testing.B) {
	pkts := buildTCPv4Interleaved(4, tcpCoalesceMaxSegs, 1200)
	runRxSplit(b, pkts, len(pkts), false)
}

func BenchmarkRxUnifiedTCPv4Interleaved4(b *testing.B) {
	pkts := buildTCPv4Interleaved(4, tcpCoalesceMaxSegs, 1200)
	runRxUnified(b, pkts, len(pkts))
}

// === UDPv4 ===

func BenchmarkRxSplitUDPv4(b *testing.B) {
	pkts := buildUDPv4Bulk(udpCoalesceMaxSegs, 1200)
	runRxSplit(b, pkts, udpCoalesceMaxSegs, false)
}

func BenchmarkRxUnifiedUDPv4(b *testing.B) {
	pkts := buildUDPv4Bulk(udpCoalesceMaxSegs, 1200)
	runRxUnified(b, pkts, udpCoalesceMaxSegs)
}

// === TCPv6 ===

func BenchmarkRxSplitTCPv6(b *testing.B) {
	pkts := buildTCPv6Bulk(tcpCoalesceMaxSegs, 1200)
	runRxSplit(b, pkts, tcpCoalesceMaxSegs, true)
}

func BenchmarkRxUnifiedTCPv6(b *testing.B) {
	pkts := buildTCPv6Bulk(tcpCoalesceMaxSegs, 1200)
	runRxUnified(b, pkts, tcpCoalesceMaxSegs)
}

// === ICMPv4 (passthrough) — measures the unified parser on the coalescer-
// rejected path, where both lenient and unified must still fill fp. ===

func BenchmarkRxSplitICMPv4(b *testing.B) {
	pkts := buildICMPv4Bulk(64)
	runRxSplit(b, pkts, 64, false)
}

func BenchmarkRxUnifiedICMPv4(b *testing.B) {
	pkts := buildICMPv4Bulk(64)
	runRxUnified(b, pkts, 64)
}

// === Firewall fast-path (conntrack-hit) — exercises the savings from the
// dense PacketKey: smaller hash key for the per-routine ConntrackCache,
// and skipping the AddrFrom4 calls that the old path needed to fill the
// netip.Addr-rich firewall.Packet up-front. ===
//
// The "split" baseline simulates the legacy path: parseV4InboundBaseline
// fills a netip.Addr-rich Packet, then we probe a localCache keyed on
// Packet. The "unified" path: ParseInbound fills only the dense PacketKey,
// and we probe a localCache keyed on PacketKey. Both paths follow with
// the coalescer Commit so the bench captures end-to-end RX-side cost.

// runRxSplitWithCache mirrors runRxSplit but runs the legacy-style
// firewall fast path (localCache keyed on firewall.Packet) on every
// packet so we can compare against the unified path.
func runRxSplitWithCache(b *testing.B, pkts [][]byte, batchSize int) {
	b.Helper()
	m := NewMultiCoalescer(nopTunWriter{}, true, true)
	var fp firewall.Packet

	// Pre-warm a per-packet cache keyed on the netip.Addr-rich Packet form.
	cache := make(map[firewall.Packet]struct{}, len(pkts))
	for _, pkt := range pkts {
		var seedFp firewall.Packet
		if !parseV4InboundBaseline(pkt, &seedFp) {
			b.Fatal("seed parse failed")
		}
		cache[seedFp] = struct{}{}
	}

	b.ReportAllocs()
	b.SetBytes(int64(len(pkts[0])))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pkt := pkts[i%len(pkts)]
		if !parseV4InboundBaseline(pkt, &fp) {
			b.Fatal("baseline parse failed")
		}
		if _, ok := cache[fp]; !ok {
			b.Fatal("cache miss")
		}
		if err := m.Commit(pkt); err != nil {
			b.Fatal(err)
		}
		if (i+1)%batchSize == 0 {
			if err := m.Flush(); err != nil {
				b.Fatal(err)
			}
		}
	}
	_ = m.Flush()
}

// runRxUnifiedWithCache: unified path with a PacketKey-keyed localCache.
// Each iteration: ParseInbound → conntrack-cache hit → CommitInbound.
func runRxUnifiedWithCache(b *testing.B, pkts [][]byte, batchSize int) {
	b.Helper()
	m := NewMultiCoalescer(nopTunWriter{}, true, true)
	var parsed RxParsed

	cache := make(firewall.ConntrackCache, len(pkts))
	for _, pkt := range pkts {
		var seed RxParsed
		if err := ParseInbound(pkt, &seed); err != nil {
			b.Fatal(err)
		}
		cache[seed.Key] = struct{}{}
	}

	b.ReportAllocs()
	b.SetBytes(int64(len(pkts[0])))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pkt := pkts[i%len(pkts)]
		if err := ParseInbound(pkt, &parsed); err != nil {
			b.Fatal(err)
		}
		if _, ok := cache[parsed.Key]; !ok {
			b.Fatal("cache miss")
		}
		if err := m.CommitInbound(pkt, &parsed); err != nil {
			b.Fatal(err)
		}
		if (i+1)%batchSize == 0 {
			if err := m.Flush(); err != nil {
				b.Fatal(err)
			}
		}
	}
	_ = m.Flush()
}

func BenchmarkRxSplitTCPv4WithCache(b *testing.B) {
	pkts := buildTCPv4BulkFlow(tcpCoalesceMaxSegs, 1200)
	runRxSplitWithCache(b, pkts, tcpCoalesceMaxSegs)
}

func BenchmarkRxUnifiedTCPv4WithCache(b *testing.B) {
	pkts := buildTCPv4BulkFlow(tcpCoalesceMaxSegs, 1200)
	runRxUnifiedWithCache(b, pkts, tcpCoalesceMaxSegs)
}

func BenchmarkRxSplitInterleaved4WithCache(b *testing.B) {
	pkts := buildTCPv4Interleaved(4, tcpCoalesceMaxSegs, 1200)
	runRxSplitWithCache(b, pkts, len(pkts))
}

func BenchmarkRxUnifiedInterleaved4WithCache(b *testing.B) {
	pkts := buildTCPv4Interleaved(4, tcpCoalesceMaxSegs, 1200)
	runRxUnifiedWithCache(b, pkts, len(pkts))
}
