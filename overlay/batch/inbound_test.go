package batch

import (
	"net/netip"
	"testing"

	"github.com/slackhq/nebula/firewall"
)

// TestParseInboundParity asserts that ParseInbound + Key.Hydrate produces
// the same firewall.Packet that the lenient baseline parsers (which
// mirror outside.go's parseV4/parseV6 with incoming=true) produce for
// every shape we care about. Catches drift between the unified
// parse-then-hydrate flow and the production newPacket behavior so
// swapping one for the other is observably safe.
func TestParseInboundParity(t *testing.T) {
	cases := []struct {
		name string
		pkt  []byte
		v6   bool
	}{
		{"tcp_v4", buildTCPv4Ports(1234, 443, 1000, tcpAck, []byte("payload")), false},
		{"tcp_v4_psh", buildTCPv4Ports(1234, 443, 2000, tcpAckPsh, make([]byte, 1200)), false},
		{"udp_v4", buildUDPv4(40000, 53, []byte("dnsquery")), false},
		{"icmp_v4", buildICMPv4(), false},
		{"tcp_v6", buildTCPv6(0, 5000, tcpAck, make([]byte, 800)), true},
		{"udp_v6", buildUDPv6(40001, 53, []byte("v6dns")), true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var fpUnified, fpBaseline firewall.Packet
			var parsed RxParsed

			if err := ParsePacket(tc.pkt, true, &parsed); err != nil {
				t.Fatalf("ParsePacket: %v", err)
			}
			parsed.Key.Hydrate(&fpUnified)
			var ok bool
			if tc.v6 {
				ok = parseV6InboundBaseline(tc.pkt, &fpBaseline)
			} else {
				ok = parseV4InboundBaseline(tc.pkt, &fpBaseline)
			}
			if !ok {
				t.Fatalf("baseline parse failed")
			}

			if fpUnified != fpBaseline {
				t.Errorf("firewall.Packet mismatch:\n  unified:  %+v\n  baseline: %+v", fpUnified, fpBaseline)
			}
		})
	}
}

// TestParseInboundFlowKey checks that the coalescer hint the unified parser
// produces matches what parseTCPBase/parseUDP would produce on the same
// packet — same flowKey, ipHdrLen, payLen, etc. The hint is only valid
// when Kind is RxKindTCP/RxKindUDP.
func TestParseInboundFlowKey(t *testing.T) {
	t.Run("tcp_v4", func(t *testing.T) {
		pkt := buildTCPv4Ports(1234, 443, 5000, tcpAck, make([]byte, 800))
		var parsed RxParsed
		if err := ParsePacket(pkt, true, &parsed); err != nil {
			t.Fatal(err)
		}
		if parsed.Kind != RxKindTCP {
			t.Fatalf("kind=%v want TCP", parsed.Kind)
		}
		ref, ok := parseTCPBase(pkt)
		if !ok {
			t.Fatal("parseTCPBase failed")
		}
		if parsed.tcp != ref {
			t.Errorf("parsedTCP mismatch:\n  unified: %+v\n  ref:     %+v", parsed.tcp, ref)
		}
	})

	t.Run("udp_v4", func(t *testing.T) {
		pkt := buildUDPv4(40000, 53, []byte("dnsquery"))
		var parsed RxParsed
		if err := ParsePacket(pkt, true, &parsed); err != nil {
			t.Fatal(err)
		}
		if parsed.Kind != RxKindUDP {
			t.Fatalf("kind=%v want UDP", parsed.Kind)
		}
		ref, ok := parseUDP(pkt)
		if !ok {
			t.Fatal("parseUDP failed")
		}
		if parsed.udp != ref {
			t.Errorf("parsedUDP mismatch:\n  unified: %+v\n  ref:     %+v", parsed.udp, ref)
		}
	})

	t.Run("tcp_v6", func(t *testing.T) {
		pkt := buildTCPv6(0, 9000, tcpAck, make([]byte, 800))
		var parsed RxParsed
		if err := ParsePacket(pkt, true, &parsed); err != nil {
			t.Fatal(err)
		}
		if parsed.Kind != RxKindTCP {
			t.Fatalf("kind=%v want TCP", parsed.Kind)
		}
		ref, ok := parseTCPBase(pkt)
		if !ok {
			t.Fatal("parseTCPBase failed")
		}
		if parsed.tcp != ref {
			t.Errorf("parsedTCP mismatch:\n  unified: %+v\n  ref:     %+v", parsed.tcp, ref)
		}
	})
}

// TestParseInboundICMPPassthrough confirms ICMP packets populate the
// conntrack key (including the ICMP identifier in RemotePort) but stay
// RxKindPassthrough so the batcher writes them verbatim. After Hydrate
// the firewall.Packet form should match what the legacy parseV4 produced.
func TestParseInboundICMPPassthrough(t *testing.T) {
	pkt := buildICMPv4()
	// Stamp a non-zero identifier into the ICMP header so we can check
	// RemotePort gets it.
	pkt[20] = 8 // type=echo
	pkt[24] = 0xab
	pkt[25] = 0xcd

	var parsed RxParsed
	if err := ParsePacket(pkt, true, &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed.Kind != RxKindPassthrough {
		t.Errorf("kind=%v want Passthrough", parsed.Kind)
	}
	var fp firewall.Packet
	parsed.Key.Hydrate(&fp)
	if fp.Protocol != firewall.ProtoICMP {
		t.Errorf("Protocol=%d want %d", fp.Protocol, firewall.ProtoICMP)
	}
	if fp.RemotePort != 0xabcd {
		t.Errorf("RemotePort=0x%x want 0xabcd", fp.RemotePort)
	}
	if fp.LocalPort != 0 {
		t.Errorf("LocalPort=%d want 0", fp.LocalPort)
	}
	wantRemote := netip.MustParseAddr("10.0.0.1")
	wantLocal := netip.MustParseAddr("10.0.0.2")
	if fp.RemoteAddr != wantRemote || fp.LocalAddr != wantLocal {
		t.Errorf("addrs: remote=%v local=%v want %v/%v", fp.RemoteAddr, fp.LocalAddr, wantRemote, wantLocal)
	}
}

// TestParseInboundV4Fragment confirms a fragmented v4 packet fills the
// conntrack key with Fragment=true and falls into Passthrough on the
// coalescer side.
func TestParseInboundV4Fragment(t *testing.T) {
	// Build a TCP packet then twiddle the IP flags to make it look like a
	// non-first fragment (offset != 0).
	pkt := buildTCPv4Ports(1234, 443, 1000, tcpAck, []byte("payload"))
	// Set a non-zero fragment offset (bytes 6-7, low 13 bits).
	pkt[6] = 0x00
	pkt[7] = 0x10 // offset = 16 (in 8-byte units)

	var parsed RxParsed
	if err := ParsePacket(pkt, true, &parsed); err != nil {
		t.Fatal(err)
	}
	if !parsed.Key.Fragment {
		t.Error("Fragment=false, want true")
	}
	if parsed.Kind != RxKindPassthrough {
		t.Errorf("kind=%v want Passthrough", parsed.Kind)
	}
}
