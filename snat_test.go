package nebula

import (
	"encoding/binary"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/gaissmai/bart"
	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/firewall"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Canonical test packets with all checksums computed from scratch by
// /tmp/gen_canonical.go. Tests feed these into the production rewrite
// functions and compare byte-for-byte against expected outputs.

// canonicalUDP: src=10.0.0.1:12345 dst=192.168.1.1:80 proto=UDP payload="hello world"
var canonicalUDP = []byte{
	0x45, 0x00, 0x00, 0x27, 0x12, 0x34, 0x40, 0x00, 0x40, 0x11, 0x5c, 0xe8, 0x0a, 0x00, 0x00, 0x01,
	0xc0, 0xa8, 0x01, 0x01, 0x30, 0x39, 0x00, 0x50, 0x00, 0x13, 0x71, 0xc6, 0x68, 0x65, 0x6c, 0x6c,
	0x6f, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64,
}

// canonicalTCP: src=10.0.0.1:12345 dst=192.168.1.1:80 proto=TCP payload="GET / HTTP/1.1"
var canonicalTCP = []byte{
	0x45, 0x00, 0x00, 0x36, 0x12, 0x34, 0x40, 0x00, 0x40, 0x06, 0x5c, 0xe4, 0x0a, 0x00, 0x00, 0x01,
	0xc0, 0xa8, 0x01, 0x01, 0x30, 0x39, 0x00, 0x50, 0x12, 0x34, 0x56, 0x78, 0x00, 0x00, 0x00, 0x00,
	0x50, 0x02, 0xff, 0xff, 0x86, 0x68, 0x00, 0x00, 0x47, 0x45, 0x54, 0x20, 0x2f, 0x20, 0x48, 0x54,
	0x54, 0x50, 0x2f, 0x31, 0x2e, 0x31,
}

// canonicalICMP: src=10.0.0.1 dst=192.168.1.1 proto=ICMP echo, id=0x1234 seq=1
var canonicalICMP = []byte{
	0x45, 0x00, 0x00, 0x1c, 0x12, 0x34, 0x40, 0x00, 0x40, 0x01, 0x5d, 0x03, 0x0a, 0x00, 0x00, 0x01,
	0xc0, 0xa8, 0x01, 0x01, 0x08, 0x00, 0xe5, 0xca, 0x12, 0x34, 0x00, 0x01,
}

// canonicalUDPReply: src=192.168.1.1:80 dst=169.254.55.96:55555 proto=UDP payload="reply"
var canonicalUDPReply = []byte{
	0x45, 0x00, 0x00, 0x21, 0x12, 0x34, 0x40, 0x00, 0x40, 0x11, 0x85, 0x90, 0xc0, 0xa8, 0x01, 0x01,
	0xa9, 0xfe, 0x37, 0x60, 0x00, 0x50, 0xd9, 0x03, 0x00, 0x0d, 0x27, 0xa6, 0x72, 0x65, 0x70, 0x6c,
	0x79,
}

// canonicalUDPTest: src=10.0.0.1:12345 dst=192.168.1.1:80 proto=UDP payload="test"
var canonicalUDPTest = []byte{
	0x45, 0x00, 0x00, 0x20, 0x12, 0x34, 0x40, 0x00, 0x40, 0x11, 0x5c, 0xef, 0x0a, 0x00, 0x00, 0x01,
	0xc0, 0xa8, 0x01, 0x01, 0x30, 0x39, 0x00, 0x50, 0x00, 0x0c, 0x1b, 0xc9, 0x74, 0x65, 0x73, 0x74,
}

// canonicalUDPHijack: src=10.0.0.1:12345 dst=192.168.1.1:80 proto=UDP payload="hijack"
var canonicalUDPHijack = []byte{
	0x45, 0x00, 0x00, 0x22, 0x12, 0x34, 0x40, 0x00, 0x40, 0x11, 0x5c, 0xed, 0x0a, 0x00, 0x00, 0x01,
	0xc0, 0xa8, 0x01, 0x01, 0x30, 0x39, 0x00, 0x50, 0x00, 0x0e, 0xcd, 0x68, 0x68, 0x69, 0x6a, 0x61,
	0x63, 0x6b,
}

// canonicalUDPBlocked: src=10.0.0.1:12345 dst=192.168.1.1:443 proto=UDP payload="blocked"
var canonicalUDPBlocked = []byte{
	0x45, 0x00, 0x00, 0x23, 0x12, 0x34, 0x40, 0x00, 0x40, 0x11, 0x5c, 0xec, 0x0a, 0x00, 0x00, 0x01,
	0xc0, 0xa8, 0x01, 0x01, 0x30, 0x39, 0x01, 0xbb, 0x00, 0x0f, 0x60, 0xfc, 0x62, 0x6c, 0x6f, 0x63,
	0x6b, 0x65, 0x64,
}

// canonicalUDPWrongDest: src=10.0.0.1:12345 dst=172.16.0.1:80 proto=UDP payload="wrong dest"
var canonicalUDPWrongDest = []byte{
	0x45, 0x00, 0x00, 0x26, 0x12, 0x34, 0x40, 0x00, 0x40, 0x11, 0x72, 0x81, 0x0a, 0x00, 0x00, 0x01,
	0xac, 0x10, 0x00, 0x01, 0x30, 0x39, 0x00, 0x50, 0x00, 0x12, 0xf3, 0x53, 0x77, 0x72, 0x6f, 0x6e,
	0x67, 0x20, 0x64, 0x65, 0x73, 0x74,
}

// canonicalUDPNoSnat: src=10.0.0.1:12345 dst=192.168.1.1:80 proto=UDP payload="no snat"
var canonicalUDPNoSnat = []byte{
	0x45, 0x00, 0x00, 0x23, 0x12, 0x34, 0x40, 0x00, 0x40, 0x11, 0x5c, 0xec, 0x0a, 0x00, 0x00, 0x01,
	0xc0, 0xa8, 0x01, 0x01, 0x30, 0x39, 0x00, 0x50, 0x00, 0x0f, 0x92, 0x58, 0x6e, 0x6f, 0x20, 0x73,
	0x6e, 0x61, 0x74,
}

// canonicalUDPV4Traffic: src=10.128.0.2:12345 dst=192.168.1.1:80 proto=UDP payload="v4 traffic"
var canonicalUDPV4Traffic = []byte{
	0x45, 0x00, 0x00, 0x26, 0x12, 0x34, 0x40, 0x00, 0x40, 0x11, 0x5c, 0x68, 0x0a, 0x80, 0x00, 0x02,
	0xc0, 0xa8, 0x01, 0x01, 0x30, 0x39, 0x00, 0x50, 0x00, 0x12, 0x2a, 0x42, 0x76, 0x34, 0x20, 0x74,
	0x72, 0x61, 0x66, 0x66, 0x69, 0x63,
}

// canonicalUDPRoundtrip: src=10.0.0.1:12345 dst=192.168.1.1:80 proto=UDP payload="roundtrip"
var canonicalUDPRoundtrip = []byte{
	0x45, 0x00, 0x00, 0x25, 0x12, 0x34, 0x40, 0x00, 0x40, 0x11, 0x5c, 0xea, 0x0a, 0x00, 0x00, 0x01,
	0xc0, 0xa8, 0x01, 0x01, 0x30, 0x39, 0x00, 0x50, 0x00, 0x11, 0xd4, 0xdc, 0x72, 0x6f, 0x75, 0x6e,
	0x64, 0x74, 0x72, 0x69, 0x70,
}

// canonicalUDPSnatMe: src=10.0.0.1:12345 dst=192.168.1.1:80 proto=UDP payload="snat me"
var canonicalUDPSnatMe = []byte{
	0x45, 0x00, 0x00, 0x23, 0x12, 0x34, 0x40, 0x00, 0x40, 0x11, 0x5c, 0xec, 0x0a, 0x00, 0x00, 0x01,
	0xc0, 0xa8, 0x01, 0x01, 0x30, 0x39, 0x00, 0x50, 0x00, 0x0f, 0xa9, 0x4c, 0x73, 0x6e, 0x61, 0x74,
	0x20, 0x6d, 0x65,
}

// Expected outputs after rewriting — built from scratch with the post-rewrite
// addresses, so all checksums are independently correct.

// canonicalUDPSnatted: canonicalUDP with src rewritten to 169.254.55.96:55555
var canonicalUDPSnatted = []byte{
	0x45, 0x00, 0x00, 0x27, 0x12, 0x34, 0x40, 0x00, 0x40, 0x11, 0x85, 0x8a, 0xa9, 0xfe, 0x37, 0x60,
	0xc0, 0xa8, 0x01, 0x01, 0xd9, 0x03, 0x00, 0x50, 0x00, 0x13, 0xf1, 0x9d, 0x68, 0x65, 0x6c, 0x6c,
	0x6f, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64,
}

// canonicalUDPReplyUnSnatted: canonicalUDPReply with dst rewritten from 169.254.55.96:55555 to 10.0.0.1:12345
var canonicalUDPReplyUnSnatted = []byte{
	0x45, 0x00, 0x00, 0x21, 0x12, 0x34, 0x40, 0x00, 0x40, 0x11, 0x5c, 0xee, 0xc0, 0xa8, 0x01, 0x01,
	0x0a, 0x00, 0x00, 0x01, 0x00, 0x50, 0x30, 0x39, 0x00, 0x0d, 0xa7, 0xce, 0x72, 0x65, 0x70, 0x6c,
	0x79,
}

// canonicalTCPSnatted: canonicalTCP with src rewritten to 169.254.55.96:55555
var canonicalTCPSnatted = []byte{
	0x45, 0x00, 0x00, 0x36, 0x12, 0x34, 0x40, 0x00, 0x40, 0x06, 0x85, 0x86, 0xa9, 0xfe, 0x37, 0x60,
	0xc0, 0xa8, 0x01, 0x01, 0xd9, 0x03, 0x00, 0x50, 0x12, 0x34, 0x56, 0x78, 0x00, 0x00, 0x00, 0x00,
	0x50, 0x02, 0xff, 0xff, 0x06, 0x40, 0x00, 0x00, 0x47, 0x45, 0x54, 0x20, 0x2f, 0x20, 0x48, 0x54,
	0x54, 0x50, 0x2f, 0x31, 0x2e, 0x31,
}

// canonicalICMPSnatted: canonicalICMP with src rewritten to 169.254.55.96, id changed from 0x1234 to 0x5678
var canonicalICMPSnatted = []byte{
	0x45, 0x00, 0x00, 0x1c, 0x12, 0x34, 0x40, 0x00, 0x40, 0x01, 0x85, 0xa5, 0xa9, 0xfe, 0x37, 0x60,
	0xc0, 0xa8, 0x01, 0x01, 0x08, 0x00, 0xa1, 0x86, 0x56, 0x78, 0x00, 0x01,
}

func TestCalcNewTransportChecksum_Identity(t *testing.T) {
	// Rewriting to the same IP/port should return the same checksum
	ip := netip.MustParseAddr("10.0.0.1")
	result := calcNewTransportChecksum(0x1234, ip, 80, ip, 80)
	assert.Equal(t, uint16(0x1234), result)
}

func TestCalcNewTransportChecksum_VsCanonical(t *testing.T) {
	srcIP := netip.MustParseAddr("10.0.0.1")
	snatIP := netip.MustParseAddr("169.254.55.96")

	// Extract the original UDP checksum from canonicalUDP (bytes 26-27)
	origChecksum := binary.BigEndian.Uint16(canonicalUDP[26:28])

	// Compute incrementally
	incremental := calcNewTransportChecksum(origChecksum, srcIP, 12345, snatIP, 55555)

	// Verify it matches the checksum in the independently-computed canonicalUDPSnatted
	expectedChecksum := binary.BigEndian.Uint16(canonicalUDPSnatted[26:28])
	assert.Equal(t, expectedChecksum, incremental, "incremental checksum should match canonical expected output")
}

func TestCalcNewICMPChecksum_Identity(t *testing.T) {
	// Same values in and out should be identity
	result := calcNewICMPChecksum(0xABCD, 0, 0, 1234, 1234)
	assert.Equal(t, uint16(0xABCD), result)
}

func TestRewritePacket_UDP(t *testing.T) {
	srcIP := netip.MustParseAddr("10.0.0.1")
	dstIP := netip.MustParseAddr("192.168.1.1")
	snatIP := netip.MustParseAddr("169.254.55.96")

	pkt := slices.Clone(canonicalUDP)

	fp := firewall.Packet{
		LocalAddr:  dstIP,
		RemoteAddr: srcIP,
		LocalPort:  80,
		RemotePort: 12345,
		Protocol:   firewall.ProtoUDP,
	}

	// SNAT rewrites source: IP at offset 12, port at offset 0 inside transport
	oldIP := netip.AddrPortFrom(srcIP, 12345)
	newIP := netip.AddrPortFrom(snatIP, 55555)
	rewritePacket(pkt, &fp, oldIP, newIP, 12, 0)

	assert.Equal(t, canonicalUDPSnatted, pkt, "rewritten packet should match canonical expected output")
}

func TestRewritePacket_UDP_UnSNAT(t *testing.T) {
	snatIP := netip.MustParseAddr("169.254.55.96")
	dstIP := netip.MustParseAddr("192.168.1.1")
	origSrcIP := netip.MustParseAddr("10.0.0.1")

	pkt := slices.Clone(canonicalUDPReply)

	fp := firewall.Packet{
		LocalAddr:  dstIP,
		RemoteAddr: snatIP,
		LocalPort:  80,
		RemotePort: 55555,
		Protocol:   firewall.ProtoUDP,
	}

	// UnSNAT rewrites destination: IP at offset 16, port at offset 2 inside transport
	oldIP := netip.AddrPortFrom(snatIP, 55555)
	newIP := netip.AddrPortFrom(origSrcIP, 12345)
	rewritePacket(pkt, &fp, oldIP, newIP, 16, 2)

	assert.Equal(t, canonicalUDPReplyUnSnatted, pkt, "un-SNATted packet should match canonical expected output")
}

func TestRewritePacket_TCP(t *testing.T) {
	srcIP := netip.MustParseAddr("10.0.0.1")
	dstIP := netip.MustParseAddr("192.168.1.1")
	snatIP := netip.MustParseAddr("169.254.55.96")

	pkt := slices.Clone(canonicalTCP)

	fp := firewall.Packet{
		LocalAddr:  dstIP,
		RemoteAddr: srcIP,
		LocalPort:  80,
		RemotePort: 12345,
		Protocol:   firewall.ProtoTCP,
	}

	oldIP := netip.AddrPortFrom(srcIP, 12345)
	newIP := netip.AddrPortFrom(snatIP, 55555)
	rewritePacket(pkt, &fp, oldIP, newIP, 12, 0)

	assert.Equal(t, canonicalTCPSnatted, pkt, "rewritten TCP packet should match canonical expected output")
}

func TestRewritePacket_ICMP(t *testing.T) {
	srcIP := netip.MustParseAddr("10.0.0.1")
	dstIP := netip.MustParseAddr("192.168.1.1")
	snatIP := netip.MustParseAddr("169.254.55.96")

	pkt := slices.Clone(canonicalICMP)

	fp := firewall.Packet{
		LocalAddr:  dstIP,
		RemoteAddr: srcIP,
		LocalPort:  0,
		RemotePort: 0x1234, // ICMP ID used as port
		Protocol:   firewall.ProtoICMP,
	}

	oldIP := netip.AddrPortFrom(srcIP, 0x1234)
	newIP := netip.AddrPortFrom(snatIP, 0x5678)
	rewritePacket(pkt, &fp, oldIP, newIP, 12, 0)

	assert.Equal(t, canonicalICMPSnatted, pkt, "rewritten ICMP packet should match canonical expected output")
}

func TestRewritePacket_Roundtrip(t *testing.T) {
	// Test that SNAT followed by unSNAT produces the original packet
	srcIP := netip.MustParseAddr("10.0.0.1")
	dstIP := netip.MustParseAddr("192.168.1.1")
	snatIP := netip.MustParseAddr("169.254.55.96")

	pkt := slices.Clone(canonicalUDPRoundtrip)

	fp := firewall.Packet{
		LocalAddr:  dstIP,
		RemoteAddr: srcIP,
		LocalPort:  80,
		RemotePort: 12345,
		Protocol:   firewall.ProtoUDP,
	}

	// SNAT: rewrite source
	oldSrc := netip.AddrPortFrom(srcIP, 12345)
	newSrc := netip.AddrPortFrom(snatIP, 55555)
	rewritePacket(pkt, &fp, oldSrc, newSrc, 12, 0)

	// Verify intermediate state is not the original
	require.NotEqual(t, canonicalUDPRoundtrip, pkt)

	// UnSNAT: rewrite source back
	rewritePacket(pkt, &fp, newSrc, oldSrc, 12, 0)

	// Packet should be byte-for-byte identical to original
	assert.Equal(t, canonicalUDPRoundtrip, pkt, "packet should be identical after roundtrip SNAT/unSNAT")
}

func TestSnatInfo_Valid(t *testing.T) {
	t.Run("nil is invalid", func(t *testing.T) {
		var s *snatInfo
		assert.False(t, s.Valid())
	})

	t.Run("zero value is invalid", func(t *testing.T) {
		s := &snatInfo{}
		assert.False(t, s.Valid())
	})

	t.Run("with valid src is valid", func(t *testing.T) {
		s := &snatInfo{
			Src:      netip.AddrPortFrom(netip.MustParseAddr("10.0.0.1"), 1234),
			SrcVpnIp: netip.MustParseAddr("fd00::1"),
			SnatPort: 55555,
		}
		assert.True(t, s.Valid())
	})
}

func TestFirewall_ShouldUnSNAT(t *testing.T) {
	snatAddr := netip.MustParseAddr("169.254.55.96")

	t.Run("no snat addr configured", func(t *testing.T) {
		fw := &Firewall{}
		fp := &firewall.Packet{RemoteAddr: snatAddr}
		assert.False(t, fw.ShouldUnSNAT(fp))
	})

	t.Run("packet to snat addr", func(t *testing.T) {
		fw := &Firewall{snatAddr: snatAddr}
		fp := &firewall.Packet{RemoteAddr: snatAddr}
		assert.True(t, fw.ShouldUnSNAT(fp))
	})

	t.Run("packet to different addr", func(t *testing.T) {
		fw := &Firewall{snatAddr: snatAddr}
		fp := &firewall.Packet{RemoteAddr: netip.MustParseAddr("10.0.0.1")}
		assert.False(t, fw.ShouldUnSNAT(fp))
	})
}

func TestFirewall_IdentifyNetworkType_SNATPeer(t *testing.T) {
	snatAddr := netip.MustParseAddr("169.254.55.96")

	t.Run("v4 packet from v6-only host without networks table", func(t *testing.T) {
		fw := &Firewall{snatAddr: snatAddr}
		h := &HostInfo{vpnAddrs: []netip.Addr{netip.MustParseAddr("fd00::1")}}
		fp := firewall.Packet{
			RemoteAddr: netip.MustParseAddr("10.0.0.1"),
			LocalAddr:  netip.MustParseAddr("192.168.1.1"),
		}
		assert.Equal(t, NetworkTypeUncheckedSNATPeer, fw.identifyRemoteNetworkType(h, fp))
	})

	t.Run("v4 packet from v4 host is not snat peer", func(t *testing.T) {
		fw := &Firewall{snatAddr: snatAddr}
		h := &HostInfo{vpnAddrs: []netip.Addr{netip.MustParseAddr("10.0.0.1")}}
		fp := firewall.Packet{
			RemoteAddr: netip.MustParseAddr("10.0.0.1"),
			LocalAddr:  netip.MustParseAddr("192.168.1.1"),
		}
		assert.Equal(t, NetworkTypeVPN, fw.identifyRemoteNetworkType(h, fp))
	})

	t.Run("v6 packet from v6 host is VPN", func(t *testing.T) {
		fw := &Firewall{snatAddr: snatAddr}
		h := &HostInfo{vpnAddrs: []netip.Addr{netip.MustParseAddr("fd00::1")}}
		fp := firewall.Packet{
			RemoteAddr: netip.MustParseAddr("fd00::1"),
			LocalAddr:  netip.MustParseAddr("fd00::2"),
		}
		assert.Equal(t, NetworkTypeVPN, fw.identifyRemoteNetworkType(h, fp))
	})

	t.Run("mismatched v4 from v4 host is invalid", func(t *testing.T) {
		fw := &Firewall{snatAddr: snatAddr}
		h := &HostInfo{vpnAddrs: []netip.Addr{netip.MustParseAddr("10.0.0.1")}}
		fp := firewall.Packet{
			RemoteAddr: netip.MustParseAddr("10.0.0.99"),
			LocalAddr:  netip.MustParseAddr("192.168.1.1"),
		}
		assert.Equal(t, NetworkTypeInvalidPeer, fw.identifyRemoteNetworkType(h, fp))
	})
}

func TestFirewall_AllowNetworkType_SNAT(t *testing.T) {
	//todo fix!
	//t.Run("snat peer allowed with snat addr", func(t *testing.T) {
	//	fw := &Firewall{snatAddr: netip.MustParseAddr("169.254.55.96")}
	//	assert.NoError(t, fw.allowRemoteNetworkType(NetworkTypeUncheckedSNATPeer, fp))
	//})
	//
	//t.Run("snat peer rejected without snat addr", func(t *testing.T) {
	//	fw := &Firewall{}
	//	assert.ErrorIs(t, fw.allowRemoteNetworkType(NetworkTypeUncheckedSNATPeer, fp), ErrInvalidRemoteIP)
	//})

	t.Run("vpn always allowed", func(t *testing.T) {
		fw := &Firewall{}
		assert.NoError(t, fw.allowRemoteNetworkType(NetworkTypeVPN, firewall.Packet{}))
	})

	t.Run("unsafe always allowed", func(t *testing.T) {
		fw := &Firewall{}
		assert.NoError(t, fw.allowRemoteNetworkType(NetworkTypeUnsafe, firewall.Packet{}))
	})

	t.Run("invalid peer rejected", func(t *testing.T) {
		fw := &Firewall{}
		assert.ErrorIs(t, fw.allowRemoteNetworkType(NetworkTypeInvalidPeer, firewall.Packet{}), ErrInvalidRemoteIP)
	})

	t.Run("vpn peer rejected", func(t *testing.T) {
		fw := &Firewall{}
		assert.ErrorIs(t, fw.allowRemoteNetworkType(NetworkTypeVPNPeer, firewall.Packet{}), ErrPeerRejected)
	})
}

func TestFirewall_FindUsableSNATPort(t *testing.T) {
	l := logrus.New()
	l.SetLevel(logrus.PanicLevel)

	snatAddr := netip.MustParseAddr("169.254.55.96")

	t.Run("finds first available port", func(t *testing.T) {
		c := &dummyCert{
			networks:       []netip.Prefix{netip.MustParsePrefix("fd00::1/128")},
			unsafeNetworks: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
		}
		fw := NewFirewall(l, time.Second, time.Minute, time.Hour, c, snatAddr)

		fp := firewall.Packet{
			LocalAddr:  netip.MustParseAddr("192.168.1.1"),
			RemoteAddr: snatAddr,
			LocalPort:  80,
			RemotePort: 12345,
			Protocol:   firewall.ProtoUDP,
		}
		cn := &conn{}
		err := fw.findUsableSNATPort(&fp, cn)
		require.NoError(t, err)
		// Port should have been assigned
		assert.Equal(t, uint16(12345), fp.RemotePort, "should use original port if available")
	})

	t.Run("skips occupied port", func(t *testing.T) {
		c := &dummyCert{
			networks:       []netip.Prefix{netip.MustParsePrefix("fd00::1/128")},
			unsafeNetworks: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
		}
		fw := NewFirewall(l, time.Second, time.Minute, time.Hour, c, snatAddr)

		fp := firewall.Packet{
			LocalAddr:  netip.MustParseAddr("192.168.1.1"),
			RemoteAddr: snatAddr,
			LocalPort:  80,
			RemotePort: 12345,
			Protocol:   firewall.ProtoUDP,
		}
		// Occupy the port
		fw.Conntrack.Lock()
		fw.Conntrack.Conns[fp] = &conn{}
		fw.Conntrack.Unlock()

		cn := &conn{}
		err := fw.findUsableSNATPort(&fp, cn)
		require.NoError(t, err)
		assert.NotEqual(t, uint16(12345), fp.RemotePort, "should pick a different port")
	})

	t.Run("returns error on exhaustion", func(t *testing.T) {
		c := &dummyCert{
			networks:       []netip.Prefix{netip.MustParsePrefix("fd00::1/128")},
			unsafeNetworks: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
		}
		fw := NewFirewall(l, time.Second, time.Minute, time.Hour, c, snatAddr)

		// Fill all 0x7ff ports
		baseFP := firewall.Packet{
			LocalAddr:  netip.MustParseAddr("192.168.1.1"),
			RemoteAddr: snatAddr,
			LocalPort:  80,
			Protocol:   firewall.ProtoUDP,
		}
		fw.Conntrack.Lock()
		for i := 0; i < 0x7ff; i++ {
			fp := baseFP
			fp.RemotePort = uint16(0x7ff + i)
			fw.Conntrack.Conns[fp] = &conn{}
		}
		fw.Conntrack.Unlock()

		// Try to find a port starting from 0x7ff
		fp := baseFP
		fp.RemotePort = 0x7ff
		cn := &conn{}
		err := fw.findUsableSNATPort(&fp, cn)
		assert.ErrorIs(t, err, ErrCannotSNAT)
	})
}

func TestFirewall_ApplySnat(t *testing.T) {
	l := logrus.New()
	l.SetLevel(logrus.PanicLevel)

	snatAddr := netip.MustParseAddr("169.254.55.96")
	peerV6Addr := netip.MustParseAddr("fd00::1")
	dstIP := netip.MustParseAddr("192.168.1.1")

	t.Run("new flow from v6 host", func(t *testing.T) {
		c := &dummyCert{
			networks:       []netip.Prefix{netip.MustParsePrefix("fd00::1/128")},
			unsafeNetworks: []netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")},
		}
		fw := NewFirewall(l, time.Second, time.Minute, time.Hour, c, snatAddr)
		fw.snatAddr = snatAddr

		pkt := slices.Clone(canonicalUDPTest)
		fp := firewall.Packet{
			LocalAddr:  dstIP,
			RemoteAddr: netip.MustParseAddr("10.0.0.1"),
			LocalPort:  80,
			RemotePort: 12345,
			Protocol:   firewall.ProtoUDP,
		}
		cn := &conn{}
		h := &HostInfo{vpnAddrs: []netip.Addr{peerV6Addr}}

		err := fw.applySnat(pkt, &fp, cn, h)
		require.NoError(t, err)

		// Should have created snat info
		require.True(t, cn.snat.Valid())
		assert.Equal(t, peerV6Addr, cn.snat.SrcVpnIp)
		assert.Equal(t, netip.MustParseAddr("10.0.0.1"), cn.snat.Src.Addr())
		assert.Equal(t, uint16(12345), cn.snat.Src.Port())

		// Packet source should be rewritten to snatAddr
		gotSrcIP, _ := netip.AddrFromSlice(pkt[12:16])
		assert.Equal(t, snatAddr, gotSrcIP)
	})

	t.Run("existing flow with matching identity", func(t *testing.T) {
		c := &dummyCert{
			networks:       []netip.Prefix{netip.MustParsePrefix("fd00::1/128")},
			unsafeNetworks: []netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")},
		}
		fw := NewFirewall(l, time.Second, time.Minute, time.Hour, c, snatAddr)
		fw.snatAddr = snatAddr

		pkt := slices.Clone(canonicalUDPTest)
		fp := firewall.Packet{
			LocalAddr:  dstIP,
			RemoteAddr: netip.MustParseAddr("10.0.0.1"),
			LocalPort:  80,
			RemotePort: 12345,
			Protocol:   firewall.ProtoUDP,
		}
		cn := &conn{
			snat: &snatInfo{
				Src:      netip.AddrPortFrom(netip.MustParseAddr("10.0.0.1"), 12345),
				SrcVpnIp: peerV6Addr,
				SnatPort: 55555,
			},
		}
		h := &HostInfo{vpnAddrs: []netip.Addr{peerV6Addr}}

		err := fw.applySnat(pkt, &fp, cn, h)
		require.NoError(t, err)

		// Source should be rewritten
		gotSrcIP, _ := netip.AddrFromSlice(pkt[12:16])
		assert.Equal(t, snatAddr, gotSrcIP)
	})

	t.Run("identity mismatch rejected", func(t *testing.T) {
		c := &dummyCert{
			networks:       []netip.Prefix{netip.MustParsePrefix("fd00::1/128")},
			unsafeNetworks: []netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")},
		}
		fw := NewFirewall(l, time.Second, time.Minute, time.Hour, c, snatAddr)
		fw.snatAddr = snatAddr

		pkt := slices.Clone(canonicalUDPTest)
		fp := firewall.Packet{
			LocalAddr:  dstIP,
			RemoteAddr: netip.MustParseAddr("10.0.0.1"),
			LocalPort:  80,
			RemotePort: 12345,
			Protocol:   firewall.ProtoUDP,
		}
		cn := &conn{
			snat: &snatInfo{
				Src:      netip.AddrPortFrom(netip.MustParseAddr("10.0.0.1"), 12345),
				SrcVpnIp: netip.MustParseAddr("fd00::99"), // Different VPN IP
				SnatPort: 55555,
			},
		}
		// Attacker has a different VPN address
		h := &HostInfo{vpnAddrs: []netip.Addr{peerV6Addr}}

		err := fw.applySnat(pkt, &fp, cn, h)
		assert.ErrorIs(t, err, ErrSNATIdentityMismatch)
	})

	t.Run("no snat addr configured", func(t *testing.T) {
		c := &dummyCert{
			networks: []netip.Prefix{netip.MustParsePrefix("fd00::1/128")},
		}
		fw := NewFirewall(l, time.Second, time.Minute, time.Hour, c, netip.Addr{})

		pkt := slices.Clone(canonicalUDPTest)
		fp := firewall.Packet{
			LocalAddr:  dstIP,
			RemoteAddr: netip.MustParseAddr("10.0.0.1"),
			LocalPort:  80,
			RemotePort: 12345,
			Protocol:   firewall.ProtoUDP,
		}
		cn := &conn{}
		h := &HostInfo{vpnAddrs: []netip.Addr{peerV6Addr}}

		err := fw.applySnat(pkt, &fp, cn, h)
		assert.ErrorIs(t, err, ErrCannotSNAT)
	})

	t.Run("v4 host rejected for new flow", func(t *testing.T) {
		c := &dummyCert{
			networks:       []netip.Prefix{netip.MustParsePrefix("fd00::1/128")},
			unsafeNetworks: []netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")},
		}
		fw := NewFirewall(l, time.Second, time.Minute, time.Hour, c, snatAddr)
		fw.snatAddr = snatAddr

		pkt := slices.Clone(canonicalUDPTest)
		fp := firewall.Packet{
			LocalAddr:  dstIP,
			RemoteAddr: netip.MustParseAddr("10.0.0.1"),
			LocalPort:  80,
			RemotePort: 12345,
			Protocol:   firewall.ProtoUDP,
		}
		cn := &conn{}
		// This host has a v4 address - can't SNAT for it
		h := &HostInfo{vpnAddrs: []netip.Addr{netip.MustParseAddr("10.0.0.50")}}

		err := fw.applySnat(pkt, &fp, cn, h)
		assert.ErrorIs(t, err, ErrCannotSNAT)
	})
}

func TestFirewall_UnSnat(t *testing.T) {
	l := logrus.New()
	l.SetLevel(logrus.PanicLevel)

	snatAddr := netip.MustParseAddr("169.254.55.96")
	peerV6Addr := netip.MustParseAddr("fd00::1")
	origSrcIP := netip.MustParseAddr("10.0.0.1")

	t.Run("successful unsnat", func(t *testing.T) {
		c := &dummyCert{
			networks:       []netip.Prefix{netip.MustParsePrefix("fd00::1/128")},
			unsafeNetworks: []netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")},
		}
		fw := NewFirewall(l, time.Second, time.Minute, time.Hour, c, snatAddr)
		fw.snatAddr = snatAddr

		// Create a conntrack entry for the snatted flow
		snatFP := firewall.Packet{
			LocalAddr:  netip.MustParseAddr("192.168.1.1"),
			RemoteAddr: snatAddr,
			LocalPort:  80,
			RemotePort: 55555,
			Protocol:   firewall.ProtoUDP,
		}
		fw.Conntrack.Lock()
		fw.Conntrack.Conns[snatFP] = &conn{
			snat: &snatInfo{
				Src:      netip.AddrPortFrom(origSrcIP, 12345),
				SrcVpnIp: peerV6Addr,
				SnatPort: 55555,
			},
		}
		fw.Conntrack.Unlock()

		pkt := slices.Clone(canonicalUDPReply)

		fp := firewall.Packet{
			LocalAddr:  netip.MustParseAddr("192.168.1.1"),
			RemoteAddr: snatAddr,
			LocalPort:  80,
			RemotePort: 55555,
			Protocol:   firewall.ProtoUDP,
		}

		result := fw.unSnat(pkt, &fp)
		assert.True(t, result.IsValid())
		assert.Equal(t, peerV6Addr, result)

		// Destination should be rewritten to the original source
		gotDstIP, _ := netip.AddrFromSlice(pkt[16:20])
		assert.Equal(t, origSrcIP, gotDstIP)
	})

	t.Run("no conntrack entry", func(t *testing.T) {
		c := &dummyCert{
			networks:       []netip.Prefix{netip.MustParsePrefix("fd00::1/128")},
			unsafeNetworks: []netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")},
		}
		fw := NewFirewall(l, time.Second, time.Minute, time.Hour, c, snatAddr)
		fw.snatAddr = snatAddr

		pkt := slices.Clone(canonicalUDPReply)
		fp := firewall.Packet{
			LocalAddr:  netip.MustParseAddr("192.168.1.1"),
			RemoteAddr: snatAddr,
			LocalPort:  80,
			RemotePort: 55555,
			Protocol:   firewall.ProtoUDP,
		}

		result := fw.unSnat(pkt, &fp)
		assert.False(t, result.IsValid())
	})
}

func TestFirewall_Drop_SNATFullFlow(t *testing.T) {
	// Integration test: a complete SNAT flow through Drop
	l := logrus.New()
	l.SetLevel(logrus.PanicLevel)

	snatAddr := netip.MustParseAddr("169.254.55.96")
	myV6Prefix := netip.MustParsePrefix("fd00::1/128")
	unsafeNet := netip.MustParsePrefix("192.168.0.0/16")

	myCert := &dummyCert{
		name:           "me",
		networks:       []netip.Prefix{myV6Prefix},
		unsafeNetworks: []netip.Prefix{unsafeNet},
		groups:         []string{"default-group"},
		issuer:         "signer-shasum",
	}

	fw := NewFirewall(l, time.Second, time.Minute, time.Hour, myCert, snatAddr)
	fw.snatAddr = snatAddr
	require.NoError(t, fw.AddRule(true, firewall.ProtoAny, 0, 0, []string{"any"}, "", "", "any", "", ""))

	// Set up the peer: an IPv6-only host sending IPv4 traffic
	peerV6Addr := netip.MustParseAddr("fd00::2")
	peerCert := &dummyCert{
		name:     "peer",
		networks: []netip.Prefix{netip.MustParsePrefix("fd00::2/128")},
		groups:   []string{"default-group"},
		issuer:   "signer-shasum",
	}

	myVpnNetworksTable := new(bart.Lite)
	myVpnNetworksTable.Insert(myV6Prefix)

	h := &HostInfo{
		ConnectionState: &ConnectionState{
			peerCert: &cert.CachedCertificate{
				Certificate:    peerCert,
				InvertedGroups: map[string]struct{}{"default-group": {}},
			},
		},
		vpnAddrs: []netip.Addr{peerV6Addr},
	}
	h.buildNetworks(myVpnNetworksTable, peerCert)

	pkt := slices.Clone(canonicalUDPSnatMe)

	fp := firewall.Packet{
		LocalAddr:  netip.MustParseAddr("192.168.1.1"),
		RemoteAddr: netip.MustParseAddr("10.0.0.1"),
		LocalPort:  80,
		RemotePort: 12345,
		Protocol:   firewall.ProtoUDP,
	}
	cp := cert.NewCAPool()

	// Drop should succeed and SNAT the packet
	err := fw.Drop(fp, pkt, true, h, cp, nil)
	require.NoError(t, err)

	// After Drop, the source should be rewritten to the snat addr
	gotSrcIP, _ := netip.AddrFromSlice(pkt[12:16])
	assert.Equal(t, snatAddr, gotSrcIP)
}

func TestHasOnlyV6Addresses(t *testing.T) {
	t.Run("v6 only", func(t *testing.T) {
		h := &HostInfo{vpnAddrs: []netip.Addr{
			netip.MustParseAddr("fd00::1"),
			netip.MustParseAddr("fd00::2"),
		}}
		assert.True(t, h.HasOnlyV6Addresses())
	})

	t.Run("v4 only", func(t *testing.T) {
		h := &HostInfo{vpnAddrs: []netip.Addr{
			netip.MustParseAddr("10.0.0.1"),
		}}
		assert.False(t, h.HasOnlyV6Addresses())
	})

	t.Run("mixed v4 and v6", func(t *testing.T) {
		h := &HostInfo{vpnAddrs: []netip.Addr{
			netip.MustParseAddr("fd00::1"),
			netip.MustParseAddr("10.0.0.1"),
		}}
		assert.False(t, h.HasOnlyV6Addresses())
	})
}

// --- Adversarial SNAT Tests ---

func TestFirewall_ApplySnat_CrossHostHijack(t *testing.T) {
	// Host A (fd00::1) establishes SNAT flow. Host B (fd00::2) sends a packet
	// matching the same conntrack key but with a different identity.
	// applySnat must reject with ErrSNATIdentityMismatch and leave the packet unmodified.
	l := logrus.New()
	l.SetLevel(logrus.PanicLevel)

	snatAddr := netip.MustParseAddr("169.254.55.96")
	hostA := netip.MustParseAddr("fd00::1")
	hostB := netip.MustParseAddr("fd00::2")

	c := &dummyCert{
		networks:       []netip.Prefix{netip.MustParsePrefix("fd00::1/128")},
		unsafeNetworks: []netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")},
	}
	fw := NewFirewall(l, time.Second, time.Minute, time.Hour, c, snatAddr)
	fw.snatAddr = snatAddr

	// Simulate Host A having established a flow
	cn := &conn{
		snat: &snatInfo{
			Src:      netip.AddrPortFrom(netip.MustParseAddr("10.0.0.1"), 12345),
			SrcVpnIp: hostA,
			SnatPort: 55555,
		},
	}

	// Host B tries to reuse the same conntrack entry
	pkt := slices.Clone(canonicalUDPHijack)

	fp := firewall.Packet{
		LocalAddr:  netip.MustParseAddr("192.168.1.1"),
		RemoteAddr: netip.MustParseAddr("10.0.0.1"),
		LocalPort:  80,
		RemotePort: 12345,
		Protocol:   firewall.ProtoUDP,
	}
	hB := &HostInfo{vpnAddrs: []netip.Addr{hostB}}

	err := fw.applySnat(pkt, &fp, cn, hB)
	require.ErrorIs(t, err, ErrSNATIdentityMismatch)
	assert.Equal(t, canonicalUDPHijack, pkt, "packet bytes must be unmodified after identity mismatch")
}

func TestFirewall_ApplySnat_MixedStackRejected(t *testing.T) {
	// A host with both v4 and v6 VPN addresses should never get SNAT treatment.
	// Test both orderings of vpnAddrs to verify behavior.
	l := logrus.New()
	l.SetLevel(logrus.PanicLevel)

	snatAddr := netip.MustParseAddr("169.254.55.96")
	dstIP := netip.MustParseAddr("192.168.1.1")

	c := &dummyCert{
		networks:       []netip.Prefix{netip.MustParsePrefix("fd00::1/128")},
		unsafeNetworks: []netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")},
	}

	t.Run("v6 first then v4", func(t *testing.T) {
		fw := NewFirewall(l, time.Second, time.Minute, time.Hour, c, snatAddr)
		fw.snatAddr = snatAddr

		pkt := slices.Clone(canonicalUDPTest)
		fp := firewall.Packet{
			LocalAddr:  dstIP,
			RemoteAddr: netip.MustParseAddr("10.0.0.1"),
			LocalPort:  80,
			RemotePort: 12345,
			Protocol:   firewall.ProtoUDP,
		}
		cn := &conn{}
		// Mixed-stack: v6 first. applySnat checks vpnAddrs[0].Is6() which is true,
		// so it would create a flow. But the caller (Drop) guards with HasOnlyV6Addresses().
		// This test documents that applySnat alone doesn't prevent mixed-stack SNAT.
		h := &HostInfo{vpnAddrs: []netip.Addr{
			netip.MustParseAddr("fd00::1"),
			netip.MustParseAddr("10.0.0.50"),
		}}

		err := fw.applySnat(pkt, &fp, cn, h)
		// applySnat only checks vpnAddrs[0].Is6(), so this succeeds.
		// The real guard is in Drop() via HasOnlyV6Addresses().
		assert.NoError(t, err, "applySnat alone allows v6-first mixed-stack (guarded by Drop)")
	})

	t.Run("v4 first then v6", func(t *testing.T) {
		fw := NewFirewall(l, time.Second, time.Minute, time.Hour, c, snatAddr)
		fw.snatAddr = snatAddr

		pkt := slices.Clone(canonicalUDPTest)

		fp := firewall.Packet{
			LocalAddr:  dstIP,
			RemoteAddr: netip.MustParseAddr("10.0.0.1"),
			LocalPort:  80,
			RemotePort: 12345,
			Protocol:   firewall.ProtoUDP,
		}
		cn := &conn{}
		// Mixed-stack: v4 first. vpnAddrs[0].Is6() is false -> ErrCannotSNAT.
		h := &HostInfo{vpnAddrs: []netip.Addr{
			netip.MustParseAddr("10.0.0.50"),
			netip.MustParseAddr("fd00::1"),
		}}

		err := fw.applySnat(pkt, &fp, cn, h)
		require.ErrorIs(t, err, ErrCannotSNAT)
		assert.Equal(t, canonicalUDPTest, pkt, "packet bytes must be unmodified on error")
	})
}

func TestFirewall_ApplySnat_PacketUnmodifiedOnError(t *testing.T) {
	// When applySnat returns an error, the packet must not be partially rewritten.
	l := logrus.New()
	l.SetLevel(logrus.PanicLevel)

	dstIP := netip.MustParseAddr("192.168.1.1")

	t.Run("no snatAddr configured", func(t *testing.T) {
		c := &dummyCert{
			networks: []netip.Prefix{netip.MustParsePrefix("fd00::1/128")},
		}
		fw := NewFirewall(l, time.Second, time.Minute, time.Hour, c, netip.Addr{})

		pkt := slices.Clone(canonicalUDPTest)

		fp := firewall.Packet{
			LocalAddr:  dstIP,
			RemoteAddr: netip.MustParseAddr("10.0.0.1"),
			LocalPort:  80,
			RemotePort: 12345,
			Protocol:   firewall.ProtoUDP,
		}
		cn := &conn{}
		h := &HostInfo{vpnAddrs: []netip.Addr{netip.MustParseAddr("fd00::1")}}

		err := fw.applySnat(pkt, &fp, cn, h)
		require.Error(t, err)
		assert.Equal(t, canonicalUDPTest, pkt, "packet must be byte-for-byte identical after error")
	})

	t.Run("identity mismatch", func(t *testing.T) {
		snatAddr := netip.MustParseAddr("169.254.55.96")
		c := &dummyCert{
			networks:       []netip.Prefix{netip.MustParsePrefix("fd00::1/128")},
			unsafeNetworks: []netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")},
		}
		fw := NewFirewall(l, time.Second, time.Minute, time.Hour, c, snatAddr)
		fw.snatAddr = snatAddr

		pkt := slices.Clone(canonicalUDPTest)

		fp := firewall.Packet{
			LocalAddr:  dstIP,
			RemoteAddr: netip.MustParseAddr("10.0.0.1"),
			LocalPort:  80,
			RemotePort: 12345,
			Protocol:   firewall.ProtoUDP,
		}
		cn := &conn{
			snat: &snatInfo{
				Src:      netip.AddrPortFrom(netip.MustParseAddr("10.0.0.1"), 12345),
				SrcVpnIp: netip.MustParseAddr("fd00::99"),
				SnatPort: 55555,
			},
		}
		h := &HostInfo{vpnAddrs: []netip.Addr{netip.MustParseAddr("fd00::1")}}

		err := fw.applySnat(pkt, &fp, cn, h)
		require.ErrorIs(t, err, ErrSNATIdentityMismatch)
		assert.Equal(t, canonicalUDPTest, pkt, "packet must be byte-for-byte identical after identity mismatch")
	})

	t.Run("v4 host rejected", func(t *testing.T) {
		snatAddr := netip.MustParseAddr("169.254.55.96")
		c := &dummyCert{
			networks:       []netip.Prefix{netip.MustParsePrefix("fd00::1/128")},
			unsafeNetworks: []netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")},
		}
		fw := NewFirewall(l, time.Second, time.Minute, time.Hour, c, snatAddr)
		fw.snatAddr = snatAddr

		pkt := slices.Clone(canonicalUDPTest)

		fp := firewall.Packet{
			LocalAddr:  dstIP,
			RemoteAddr: netip.MustParseAddr("10.0.0.1"),
			LocalPort:  80,
			RemotePort: 12345,
			Protocol:   firewall.ProtoUDP,
		}
		cn := &conn{}
		h := &HostInfo{vpnAddrs: []netip.Addr{netip.MustParseAddr("10.0.0.50")}}

		err := fw.applySnat(pkt, &fp, cn, h)
		require.ErrorIs(t, err, ErrCannotSNAT)
		assert.Equal(t, canonicalUDPTest, pkt, "packet must be byte-for-byte identical after v4 host rejection")
	})
}

func TestFirewall_UnSnat_NonSNATConntrack(t *testing.T) {
	// A conntrack entry exists but has snat=nil. unSnat should return an invalid addr
	// and not rewrite the packet.
	l := logrus.New()
	l.SetLevel(logrus.PanicLevel)

	snatAddr := netip.MustParseAddr("169.254.55.96")

	c := &dummyCert{
		networks:       []netip.Prefix{netip.MustParsePrefix("fd00::1/128")},
		unsafeNetworks: []netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")},
	}
	fw := NewFirewall(l, time.Second, time.Minute, time.Hour, c, snatAddr)
	fw.snatAddr = snatAddr

	// Create a conntrack entry with snat=nil (a normal non-SNAT connection)
	snatFP := firewall.Packet{
		LocalAddr:  netip.MustParseAddr("192.168.1.1"),
		RemoteAddr: snatAddr,
		LocalPort:  80,
		RemotePort: 55555,
		Protocol:   firewall.ProtoUDP,
	}
	fw.Conntrack.Lock()
	fw.Conntrack.Conns[snatFP] = &conn{
		snat: nil, // deliberately nil
	}
	fw.Conntrack.Unlock()

	pkt := slices.Clone(canonicalUDPReply)

	fp := firewall.Packet{
		LocalAddr:  netip.MustParseAddr("192.168.1.1"),
		RemoteAddr: snatAddr,
		LocalPort:  80,
		RemotePort: 55555,
		Protocol:   firewall.ProtoUDP,
	}

	result := fw.unSnat(pkt, &fp)
	assert.False(t, result.IsValid(), "unSnat should return invalid addr for non-SNAT conntrack entry")
	assert.Equal(t, canonicalUDPReply, pkt, "packet must not be rewritten when conntrack has no snat info")
}

func TestFirewall_Drop_FirewallBlocksSNAT(t *testing.T) {
	// Firewall rules only allow port 80. An SNAT-eligible packet to port 443
	// must be rejected with ErrNoMatchingRule BEFORE any SNAT rewriting occurs.
	l := logrus.New()
	l.SetLevel(logrus.PanicLevel)

	snatAddr := netip.MustParseAddr("169.254.55.96")

	myCert := &dummyCert{
		name:           "me",
		networks:       []netip.Prefix{netip.MustParsePrefix("fd00::1/128")},
		unsafeNetworks: []netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")},
		groups:         []string{"default-group"},
		issuer:         "signer-shasum",
	}

	fw := NewFirewall(l, time.Second, time.Minute, time.Hour, myCert, snatAddr)
	fw.snatAddr = snatAddr
	// Only allow port 80 inbound
	require.NoError(t, fw.AddRule(true, firewall.ProtoAny, 80, 80, []string{"any"}, "", "", "any", "", ""))

	peerV6Addr := netip.MustParseAddr("fd00::2")
	peerCert := &dummyCert{
		name:     "peer",
		networks: []netip.Prefix{netip.MustParsePrefix("fd00::2/128")},
		groups:   []string{"default-group"},
		issuer:   "signer-shasum",
	}

	myVpnNetworksTable := new(bart.Lite)
	myVpnNetworksTable.Insert(netip.MustParsePrefix("fd00::1/128"))

	h := &HostInfo{
		ConnectionState: &ConnectionState{
			peerCert: &cert.CachedCertificate{
				Certificate:    peerCert,
				InvertedGroups: map[string]struct{}{"default-group": {}},
			},
		},
		vpnAddrs: []netip.Addr{peerV6Addr},
	}
	h.buildNetworks(myVpnNetworksTable, peerCert)

	// Send to port 443 (not allowed)
	pkt := slices.Clone(canonicalUDPBlocked)

	fp := firewall.Packet{
		LocalAddr:  netip.MustParseAddr("192.168.1.1"),
		RemoteAddr: netip.MustParseAddr("10.0.0.1"),
		LocalPort:  443,
		RemotePort: 12345,
		Protocol:   firewall.ProtoUDP,
	}
	cp := cert.NewCAPool()

	err := fw.Drop(fp, pkt, true, h, cp, nil)
	require.ErrorIs(t, err, ErrNoMatchingRule, "firewall should block SNAT-eligible traffic that doesn't match rules")
	assert.Equal(t, canonicalUDPBlocked, pkt, "packet must not be rewritten when firewall blocks it")
}

func TestFirewall_Drop_SNATLocalAddrNotRoutable(t *testing.T) {
	// An SNAT peer sends IPv4 traffic to an address NOT in routableNetworks.
	// willingToHandleLocalAddr should reject with ErrInvalidLocalIP.
	l := logrus.New()
	l.SetLevel(logrus.PanicLevel)

	snatAddr := netip.MustParseAddr("169.254.55.96")

	myCert := &dummyCert{
		name:           "me",
		networks:       []netip.Prefix{netip.MustParsePrefix("fd00::1/128")},
		unsafeNetworks: []netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")},
		groups:         []string{"default-group"},
		issuer:         "signer-shasum",
	}

	fw := NewFirewall(l, time.Second, time.Minute, time.Hour, myCert, snatAddr)
	fw.snatAddr = snatAddr
	require.NoError(t, fw.AddRule(true, firewall.ProtoAny, 0, 0, []string{"any"}, "", "", "any", "", ""))

	peerV6Addr := netip.MustParseAddr("fd00::2")
	peerCert := &dummyCert{
		name:     "peer",
		networks: []netip.Prefix{netip.MustParsePrefix("fd00::2/128")},
		groups:   []string{"default-group"},
		issuer:   "signer-shasum",
	}

	myVpnNetworksTable := new(bart.Lite)
	myVpnNetworksTable.Insert(netip.MustParsePrefix("fd00::1/128"))

	h := &HostInfo{
		ConnectionState: &ConnectionState{
			peerCert: &cert.CachedCertificate{
				Certificate:    peerCert,
				InvertedGroups: map[string]struct{}{"default-group": {}},
			},
		},
		vpnAddrs: []netip.Addr{peerV6Addr},
	}
	h.buildNetworks(myVpnNetworksTable, peerCert)

	// Dest 172.16.0.1 is NOT in our routableNetworks (which only has fd00::1/128 and 192.168.0.0/16)
	pkt := slices.Clone(canonicalUDPWrongDest)

	fp := firewall.Packet{
		LocalAddr:  netip.MustParseAddr("172.16.0.1"),
		RemoteAddr: netip.MustParseAddr("10.0.0.1"),
		LocalPort:  80,
		RemotePort: 12345,
		Protocol:   firewall.ProtoUDP,
	}
	cp := cert.NewCAPool()

	err := fw.Drop(fp, pkt, true, h, cp, nil)
	assert.ErrorIs(t, err, ErrInvalidLocalIP, "traffic to non-routable local address should be rejected")
}

func TestFirewall_Drop_NoSnatAddrRejectsV6Peer(t *testing.T) {
	// Firewall has no snatAddr configured. An IPv6-only peer sends IPv4 traffic.
	// allowRemoteNetworkType(UncheckedSNATPeer) should reject with ErrInvalidRemoteIP.
	l := logrus.New()
	l.SetLevel(logrus.PanicLevel)

	myCert := &dummyCert{
		name:     "me",
		networks: []netip.Prefix{netip.MustParsePrefix("fd00::1/128")},
		groups:   []string{"default-group"},
		issuer:   "signer-shasum",
	}

	fw := NewFirewall(l, time.Second, time.Minute, time.Hour, myCert, netip.Addr{})
	require.NoError(t, fw.AddRule(true, firewall.ProtoAny, 0, 0, []string{"any"}, "", "", "any", "", ""))

	peerV6Addr := netip.MustParseAddr("fd00::2")
	peerCert := &dummyCert{
		name:     "peer",
		networks: []netip.Prefix{netip.MustParsePrefix("fd00::2/128")},
		groups:   []string{"default-group"},
		issuer:   "signer-shasum",
	}

	myVpnNetworksTable := new(bart.Lite)
	myVpnNetworksTable.Insert(netip.MustParsePrefix("fd00::1/128"))

	h := &HostInfo{
		ConnectionState: &ConnectionState{
			peerCert: &cert.CachedCertificate{
				Certificate:    peerCert,
				InvertedGroups: map[string]struct{}{"default-group": {}},
			},
		},
		vpnAddrs: []netip.Addr{peerV6Addr},
	}
	h.buildNetworks(myVpnNetworksTable, peerCert)

	pkt := slices.Clone(canonicalUDPNoSnat)

	fp := firewall.Packet{
		LocalAddr:  netip.MustParseAddr("192.168.1.1"),
		RemoteAddr: netip.MustParseAddr("10.0.0.1"),
		LocalPort:  80,
		RemotePort: 12345,
		Protocol:   firewall.ProtoUDP,
	}
	cp := cert.NewCAPool()

	err := fw.Drop(fp, pkt, true, h, cp, nil)
	assert.ErrorIs(t, err, ErrInvalidRemoteIP, "v6 peer with no snatAddr should be rejected")
}

func TestFirewall_Drop_IPv4HostNotSNATted(t *testing.T) {
	// An IPv4 VPN host sends IPv4 traffic. Even though the router has snatAddr
	// configured and the traffic is IPv4, the firewall must NOT treat this as
	// UncheckedSNATPeer. The packet must not be SNAT-rewritten.
	l := logrus.New()
	l.SetLevel(logrus.PanicLevel)

	snatAddr := netip.MustParseAddr("169.254.55.96")

	t.Run("v6-only router rejects v4 peer as VPNPeer", func(t *testing.T) {
		// When the router is v6-only, the v4 peer's address is outside our VPN
		// networks -> classified as NetworkTypeVPNPeer -> rejected (not SNATted).
		myCert := &dummyCert{
			name:           "me",
			networks:       []netip.Prefix{netip.MustParsePrefix("fd00::1/128")},
			unsafeNetworks: []netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")},
			groups:         []string{"default-group"},
			issuer:         "signer-shasum",
		}

		fw := NewFirewall(l, time.Second, time.Minute, time.Hour, myCert, snatAddr)
		fw.snatAddr = snatAddr
		require.NoError(t, fw.AddRule(true, firewall.ProtoAny, 0, 0, []string{"any"}, "", "", "any", "", ""))

		peerV4Addr := netip.MustParseAddr("10.128.0.2")
		peerCert := &dummyCert{
			name:     "v4peer",
			networks: []netip.Prefix{netip.MustParsePrefix("10.128.0.2/24")},
			groups:   []string{"default-group"},
			issuer:   "signer-shasum",
		}

		myVpnNetworksTable := new(bart.Lite)
		myVpnNetworksTable.Insert(netip.MustParsePrefix("fd00::1/128"))

		h := &HostInfo{
			ConnectionState: &ConnectionState{
				peerCert: &cert.CachedCertificate{
					Certificate:    peerCert,
					InvertedGroups: map[string]struct{}{"default-group": {}},
				},
			},
			vpnAddrs: []netip.Addr{peerV4Addr},
		}
		h.buildNetworks(myVpnNetworksTable, peerCert)

		pkt := slices.Clone(canonicalUDPV4Traffic)

		fp := firewall.Packet{
			LocalAddr:  netip.MustParseAddr("192.168.1.1"),
			RemoteAddr: netip.MustParseAddr("10.128.0.2"),
			LocalPort:  80,
			RemotePort: 12345,
			Protocol:   firewall.ProtoUDP,
		}
		cp := cert.NewCAPool()

		err := fw.Drop(fp, pkt, true, h, cp, nil)
		require.Error(t, err, ErrPeerRejected, "IPv4 peer should be rejected as VPNPeer, not treated as SNAT")
		assert.Equal(t, canonicalUDPV4Traffic, pkt, "packet must not be rewritten when peer is rejected")
	})

	t.Run("identifyRemoteNetworkType classifies v4 peer correctly", func(t *testing.T) {
		// Directly verify that identifyRemoteNetworkType returns the right type for
		// an IPv4 peer (not UncheckedSNATPeer).
		fw := &Firewall{snatAddr: snatAddr}

		// Simple case: v4 host, no networks table
		h := &HostInfo{vpnAddrs: []netip.Addr{netip.MustParseAddr("10.128.0.2")}}
		fp := firewall.Packet{
			RemoteAddr: netip.MustParseAddr("10.128.0.2"),
			LocalAddr:  netip.MustParseAddr("192.168.1.1"),
		}
		nwType := fw.identifyRemoteNetworkType(h, fp)
		assert.Equal(t, NetworkTypeVPN, nwType, "v4 peer using its own VPN addr should be NetworkTypeVPN")
		assert.NotEqual(t, NetworkTypeUncheckedSNATPeer, nwType, "must NOT be classified as SNAT peer")
	})

	t.Run("identifyRemoteNetworkType v4 peer with mismatched source", func(t *testing.T) {
		// v4 host sends with a source IP that doesn't match its VPN addr
		fw := &Firewall{snatAddr: snatAddr}

		h := &HostInfo{vpnAddrs: []netip.Addr{netip.MustParseAddr("10.128.0.2")}}
		fp := firewall.Packet{
			RemoteAddr: netip.MustParseAddr("10.0.0.99"), // Not the peer's VPN addr
			LocalAddr:  netip.MustParseAddr("192.168.1.1"),
		}
		nwType := fw.identifyRemoteNetworkType(h, fp)
		assert.Equal(t, NetworkTypeInvalidPeer, nwType, "v4 peer with mismatched source should be InvalidPeer")
		assert.NotEqual(t, NetworkTypeUncheckedSNATPeer, nwType, "must NOT be classified as SNAT peer")
	})
}
