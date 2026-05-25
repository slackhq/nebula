//go:build linux && !android && !e2e_testing && iouring

package udp

import (
	"encoding/binary"
	"log/slog"
	"net/netip"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func testLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

// writeCmsgHdr writes a Cmsghdr at buf[off] with the supplied level/type/
// payload length and returns the data offset (where the payload should be
// written) and the aligned-up next-header offset (where the next cmsg, if
// any, would start). Test-only helper; keeps the test cases readable.
func writeCmsgHdr(buf []byte, off int, level, ctype int32, payloadLen int) (dataOff, nextOff int) {
	ch := (*unix.Cmsghdr)(unsafe.Pointer(&buf[off]))
	ch.Level = level
	ch.Type = ctype
	ch.SetLen(unix.CmsgLen(payloadLen))
	return off + unix.CmsgLen(0), off + unix.CmsgSpace(payloadLen)
}

func TestParseSockaddrFromRaw_v4(t *testing.T) {
	var name [unix.SizeofSockaddrInet6]byte
	binary.NativeEndian.PutUint16(name[0:2], unix.AF_INET)
	binary.BigEndian.PutUint16(name[2:4], 4242)
	name[4], name[5], name[6], name[7] = 192, 168, 1, 1

	ap, err := parseSockaddrFromRaw(name[:], unix.SizeofSockaddrInet4, true)
	require.NoError(t, err)
	assert.Equal(t, netip.MustParseAddrPort("192.168.1.1:4242"), ap)
}

func TestParseSockaddrFromRaw_v6(t *testing.T) {
	var name [unix.SizeofSockaddrInet6]byte
	binary.NativeEndian.PutUint16(name[0:2], unix.AF_INET6)
	binary.BigEndian.PutUint16(name[2:4], 1234)
	// 2001:db8::1
	name[8] = 0x20
	name[9] = 0x01
	name[10] = 0x0d
	name[11] = 0xb8
	name[23] = 0x01

	ap, err := parseSockaddrFromRaw(name[:], unix.SizeofSockaddrInet6, false)
	require.NoError(t, err)
	assert.Equal(t, netip.MustParseAddrPort("[2001:db8::1]:1234"), ap)
}

func TestParseSockaddrFromRaw_v4_short(t *testing.T) {
	var name [unix.SizeofSockaddrInet6]byte
	_, err := parseSockaddrFromRaw(name[:], unix.SizeofSockaddrInet4-1, true)
	assert.Error(t, err)
}

func TestParseSockaddrFromRaw_v6_short(t *testing.T) {
	var name [unix.SizeofSockaddrInet6]byte
	_, err := parseSockaddrFromRaw(name[:], unix.SizeofSockaddrInet6-1, false)
	assert.Error(t, err)
}

func TestParseRecvCmsgRaw_GRO_only(t *testing.T) {
	buf := make([]byte, unix.CmsgSpace(4))
	dataOff, _ := writeCmsgHdr(buf, 0, unix.SOL_UDP, unix.UDP_GRO, 4)
	binary.NativeEndian.PutUint32(buf[dataOff:dataOff+4], 1200)

	gso, ecn := parseRecvCmsgRaw(&buf[0], len(buf), true, false, true)
	assert.Equal(t, 1200, gso)
	assert.Equal(t, byte(0), ecn)
}

func TestParseRecvCmsgRaw_ECN_v4(t *testing.T) {
	buf := make([]byte, unix.CmsgSpace(4))
	dataOff, _ := writeCmsgHdr(buf, 0, unix.IPPROTO_IP, unix.IP_TOS, 1)
	buf[dataOff] = 0x03 // CE (Congestion Experienced)

	gso, ecn := parseRecvCmsgRaw(&buf[0], len(buf), false, true, true)
	assert.Equal(t, 0, gso)
	assert.Equal(t, byte(0x03), ecn)
}

func TestParseRecvCmsgRaw_ECN_v6(t *testing.T) {
	buf := make([]byte, unix.CmsgSpace(4))
	dataOff, _ := writeCmsgHdr(buf, 0, unix.IPPROTO_IPV6, unix.IPV6_TCLASS, 4)
	// Traffic class 0xfe = DSCP 0x3f + ECN bits 0x02 (ECT(0)).
	binary.NativeEndian.PutUint32(buf[dataOff:dataOff+4], 0xfe)

	gso, ecn := parseRecvCmsgRaw(&buf[0], len(buf), false, true, false)
	assert.Equal(t, 0, gso)
	assert.Equal(t, byte(0x02), ecn)
}

func TestParseRecvCmsgRaw_GRO_and_ECN_v4(t *testing.T) {
	buf := make([]byte, unix.CmsgSpace(4)+unix.CmsgSpace(4))

	groDataOff, groNext := writeCmsgHdr(buf, 0, unix.SOL_UDP, unix.UDP_GRO, 4)
	binary.NativeEndian.PutUint32(buf[groDataOff:groDataOff+4], 1500)

	ecnDataOff, _ := writeCmsgHdr(buf, groNext, unix.IPPROTO_IP, unix.IP_TOS, 1)
	buf[ecnDataOff] = 0x01 // ECT(1)

	gso, ecn := parseRecvCmsgRaw(&buf[0], len(buf), true, true, true)
	assert.Equal(t, 1500, gso)
	assert.Equal(t, byte(0x01), ecn)
}

func TestParseRecvCmsgRaw_empty(t *testing.T) {
	gso, ecn := parseRecvCmsgRaw(nil, 0, true, true, true)
	assert.Equal(t, 0, gso)
	assert.Equal(t, byte(0), ecn)
}

func TestParseRecvCmsgRaw_truncated(t *testing.T) {
	// Header claims a longer payload than the buffer can hold; parser must
	// not read out-of-bounds and should return zeros (i.e. stop walking).
	buf := make([]byte, unix.SizeofCmsghdr+1)
	ch := (*unix.Cmsghdr)(unsafe.Pointer(&buf[0]))
	ch.Level = unix.SOL_UDP
	ch.Type = unix.UDP_GRO
	ch.SetLen(unix.CmsgLen(4)) // claims 4 payload bytes; only 1 available

	gso, ecn := parseRecvCmsgRaw(&buf[0], len(buf), true, true, true)
	assert.Equal(t, 0, gso)
	assert.Equal(t, byte(0), ecn)
}

func TestParseRecvCmsgRaw_wantECN_false_v4(t *testing.T) {
	// IP_TOS cmsg present but caller didn't ask for ECN — should be ignored.
	buf := make([]byte, unix.CmsgSpace(4))
	dataOff, _ := writeCmsgHdr(buf, 0, unix.IPPROTO_IP, unix.IP_TOS, 1)
	buf[dataOff] = 0x03

	gso, ecn := parseRecvCmsgRaw(&buf[0], len(buf), true, false, true)
	assert.Equal(t, 0, gso)
	assert.Equal(t, byte(0), ecn)
}

func TestCmsgAlignLen(t *testing.T) {
	align := int(unsafe.Sizeof(uintptr(0)))
	assert.Equal(t, align, cmsgAlignLen(1))
	assert.Equal(t, align, cmsgAlignLen(align))
	assert.Equal(t, 2*align, cmsgAlignLen(align+1))
	assert.Equal(t, 2*align, cmsgAlignLen(2*align))
	assert.Equal(t, 3*align, cmsgAlignLen(2*align+1))
}

func TestClampAndRoundRing(t *testing.T) {
	l := testLogger()
	assert.Equal(t, 512, clampAndRoundRing(0, 512, "k", l), "zero -> default")
	assert.Equal(t, 512, clampAndRoundRing(-1, 512, "k", l), "negative -> default")
	assert.Equal(t, 512, clampAndRoundRing(512, 256, "k", l), "already pow2")
	assert.Equal(t, 512, clampAndRoundRing(500, 256, "k", l), "round 500 -> 512")
	assert.Equal(t, 1024, clampAndRoundRing(513, 256, "k", l), "round 513 -> 1024")
	assert.Equal(t, ioUringMaxRingEntries, clampAndRoundRing(40000, 256, "k", l), "clamp to max")
	assert.Equal(t, ioUringMaxRingEntries, clampAndRoundRing(ioUringMaxRingEntries, 256, "k", l), "max is itself pow2")
}

func TestClampSendRings(t *testing.T) {
	l := testLogger()
	d := DefaultIoUringOptions()
	assert.Equal(t, d.SendRings, clampSendRings(0, d.SendRings, l), "zero -> default")
	assert.Equal(t, d.SendRings, clampSendRings(-1, d.SendRings, l), "negative -> default")
	assert.Equal(t, 1, clampSendRings(1, d.SendRings, l), "minimum 1 is allowed")
	assert.Equal(t, 8, clampSendRings(8, d.SendRings, l), "in range")
	assert.Equal(t, MaxSendRings, clampSendRings(MaxSendRings, d.SendRings, l), "at the cap")
	assert.Equal(t, MaxSendRings, clampSendRings(100, d.SendRings, l), "above cap -> clamped")
}

func TestClampSlots(t *testing.T) {
	l := testLogger()
	assert.Equal(t, 256, clampSlots(0, 512, 256, "k", l), "zero -> default")
	assert.Equal(t, 256, clampSlots(-1, 512, 256, "k", l), "negative -> default")
	assert.Equal(t, 200, clampSlots(200, 512, 256, "k", l), "in range")
	assert.Equal(t, 512, clampSlots(1000, 512, 256, "k", l), "cap to ring")
	assert.Equal(t, 512, clampSlots(512, 512, 256, "k", l), "equal to ring is ok")
}

func TestValidateIoUringOptions_normalizes(t *testing.T) {
	l := testLogger()
	opts := IoUringOptions{
		Enabled:      true,
		RecvRingSize: 500,  // not pow2
		SendRingSize: 0,    // default
		RecvSlots:    1000, // > ring size
		SendSlots:    -5,   // default
	}
	d := DefaultIoUringOptions()

	got := validateIoUringOptions(opts, l)
	assert.Equal(t, 512, got.RecvRingSize, "500 rounded to 512")
	assert.Equal(t, d.SendRingSize, got.SendRingSize, "0 -> default")
	assert.Equal(t, 512, got.RecvSlots, "1000 capped to RecvRingSize=512")
	assert.Equal(t, d.SendSlots, got.SendSlots, "-5 -> default")
	assert.True(t, got.Enabled)
}

// BenchmarkParseRecvCmsgRaw_GRO_ECN_v4 measures the hot-path parser used
// on every recv CQE. The two-cmsg layout matches what UDP_GRO + IP_TOS
// would deliver on a real socket; we expect parseRecvCmsgRaw to be cheap
// enough that it doesn't show up in flame graphs.
func BenchmarkParseRecvCmsgRaw_GRO_ECN_v4(b *testing.B) {
	buf := make([]byte, unix.CmsgSpace(4)+unix.CmsgSpace(4))
	groDataOff, groNext := writeCmsgHdr(buf, 0, unix.SOL_UDP, unix.UDP_GRO, 4)
	binary.NativeEndian.PutUint32(buf[groDataOff:groDataOff+4], 1500)
	ecnDataOff, _ := writeCmsgHdr(buf, groNext, unix.IPPROTO_IP, unix.IP_TOS, 1)
	buf[ecnDataOff] = 0x03

	b.ResetTimer()
	var gso int
	var ecn byte
	for range b.N {
		gso, ecn = parseRecvCmsgRaw(&buf[0], len(buf), true, true, true)
	}
	_ = gso
	_ = ecn
}

func BenchmarkParseSockaddrFromRaw_v4(b *testing.B) {
	var name [unix.SizeofSockaddrInet6]byte
	binary.NativeEndian.PutUint16(name[0:2], unix.AF_INET)
	binary.BigEndian.PutUint16(name[2:4], 4242)
	name[4], name[5], name[6], name[7] = 192, 168, 1, 1

	b.ResetTimer()
	var ap netip.AddrPort
	for range b.N {
		ap, _ = parseSockaddrFromRaw(name[:], unix.SizeofSockaddrInet4, true)
	}
	_ = ap
}
