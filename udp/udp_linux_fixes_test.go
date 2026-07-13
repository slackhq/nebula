//go:build linux && !android && !e2e_testing

package udp

import (
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// TestGSOMaxSegmentsKernelGate pins the corrected kernel-version gate: the
// 128-segment cap (127 usable) only lands in Linux v6.9 (commit 1382e3b6a350),
// not 5.5. Everything older stays at the conservative 63.
func TestGSOMaxSegmentsKernelGate(t *testing.T) {
	cases := []struct {
		release string
		want    int
	}{
		{"5.4.0", 63},
		{"5.5.0-generic", 63}, // the old bug bumped here — it must not now
		{"5.15.0", 63},
		{"6.1.0", 63},
		{"6.8.0-generic", 63},
		{"6.9.0", 127},
		{"6.10.1-arch1-1", 127},
		{"7.0.5-arch1-1", 127},
		{"garbage", 63},
		{"", 63},
	}
	for _, c := range cases {
		if got := gsoMaxSegments(c.release); got != c.want {
			t.Errorf("gsoMaxSegments(%q) = %d, want %d", c.release, got, c.want)
		}
	}
}

// buildCmsg lays out a single ancillary cmsg (header + data) in a fresh buffer
// the way the kernel would deliver it, so parseRecvCmsg can be exercised
// without a live socket.
func buildCmsg(level, typ int32, data []byte) []byte {
	buf := make([]byte, unix.CmsgSpace(len(data)))
	h := (*unix.Cmsghdr)(unsafe.Pointer(&buf[0]))
	h.Level = level
	h.Type = typ
	setCmsgLen(h, unix.CmsgLen(len(data)))
	copy(buf[unix.CmsgLen(0):], data)
	return buf
}

// TestParseRecvCmsgOuterECNFamily is the RX half of the dual-stack ECN fix:
// parseRecvCmsg must read the outer ECN from whichever family the kernel
// delivered, not from the socket family. On the default `::` dual-stack bind
// a v4 peer's outer ECN arrives as an IP_TOS cmsg, which the old socket-family
// gate ignored entirely.
func TestParseRecvCmsgOuterECNFamily(t *testing.T) {
	tc := make([]byte, 4)
	binary.NativeEndian.PutUint32(tc, 0x02)

	cases := []struct {
		name string
		ctrl []byte
		want byte
	}{
		{"ip_tos_ce", buildCmsg(int32(unix.IPPROTO_IP), int32(unix.IP_TOS), []byte{0x03}), 0x03},
		{"ip_tos_ect0", buildCmsg(int32(unix.IPPROTO_IP), int32(unix.IP_TOS), []byte{0x02}), 0x02},
		{"ipv6_tclass_ect0", buildCmsg(int32(unix.IPPROTO_IPV6), int32(unix.IPV6_TCLASS), tc), 0x02},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			hdr := &msghdr{Control: &c.ctrl[0]}
			setMsgControllen(hdr, len(c.ctrl))
			gso, ecn := parseRecvCmsg(hdr, false, true)
			if gso != 0 {
				t.Errorf("gso = %d, want 0 (no UDP_GRO cmsg present)", gso)
			}
			if ecn != c.want {
				t.Errorf("ecn = 0x%02x, want 0x%02x", ecn, c.want)
			}
		})
	}
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// TestWriteBatchBadFamilyDeliversOthers is the H3 regression: a batch that
// contains one destination the socket can't reach (an IPv6 remote on a
// v4-bound socket) must still deliver every other packet. Before the fix the
// writeSockaddr error returned early and dropped the whole chunk.
func TestWriteBatchBadFamilyDeliversOthers(t *testing.T) {
	rx, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Skipf("cannot open v4 receiver (sandbox?): %v", err)
	}
	defer rx.Close()
	rxPort := rx.LocalAddr().(*net.UDPAddr).Port

	// Bind a *non-wildcard* v4 address so Go gives us a genuine AF_INET
	// socket. A wildcard v4 bind (0.0.0.0) via network "udp" comes up as a
	// dual-stack AF_INET6 socket on Linux, for which a v6 dest is not a bad
	// family — which would defeat the point of this test.
	c, err := NewListener(testLogger(), netip.MustParseAddr("127.0.0.1"), 0, false, 1)
	if err != nil {
		t.Skipf("cannot open v4 sender (sandbox?): %v", err)
	}
	defer c.Close()
	sender := c.(*StdConn)
	if !sender.isV4 {
		t.Fatalf("expected a v4-bound sender socket, got isV4=false")
	}

	good := netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), uint16(rxPort))
	bad := netip.MustParseAddrPort("[2001:db8::1]:9999") // genuine v6, unreachable on v4 socket

	bufs := [][]byte{[]byte("AAA"), []byte("BBB"), []byte("CCC")}
	addrs := []netip.AddrPort{good, bad, good}

	if err := sender.WriteBatch(bufs, addrs, nil); err != nil {
		t.Fatalf("WriteBatch returned error, want nil (bad dest should be isolated): %v", err)
	}

	got := map[string]bool{}
	rx.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 64)
	for i := 0; i < 2; i++ {
		n, _, rerr := rx.ReadFromUDPAddrPort(buf)
		if rerr != nil {
			t.Fatalf("expected 2 delivered packets, read #%d failed: %v", i+1, rerr)
		}
		got[string(buf[:n])] = true
	}
	if !got["AAA"] || !got["CCC"] {
		t.Errorf("delivered set = %v, want AAA and CCC both present", got)
	}
	if got["BBB"] {
		t.Errorf("the bad-family packet BBB was somehow delivered")
	}
}

// TestWriteBatchOuterTOSToV4Mapped is the TX half of the dual-stack ECN fix,
// verified against a live kernel: WriteBatch on the default `::` dual-stack
// socket, sending to a v4-mapped destination, must stamp the outer ECN via an
// IP_TOS cmsg (not IPV6_TCLASS, which the kernel's v4 path ignores) so a v4
// receiver actually sees it.
func TestWriteBatchOuterTOSToV4Mapped(t *testing.T) {
	rx, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Skipf("cannot open v4 receiver (sandbox?): %v", err)
	}
	defer rx.Close()
	rxPort := rx.LocalAddr().(*net.UDPAddr).Port

	// Ask the kernel to deliver the received outer TOS as ancillary data.
	rxRaw, err := rx.SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn: %v", err)
	}
	var soErr error
	if err := rxRaw.Control(func(fd uintptr) {
		soErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_RECVTOS, 1)
	}); err != nil || soErr != nil {
		t.Skipf("cannot enable IP_RECVTOS (sandbox/kernel?): ctrl=%v so=%v", err, soErr)
	}

	c, err := NewListener(testLogger(), netip.IPv6Unspecified(), 0, false, 1)
	if err != nil {
		t.Skipf("cannot open dual-stack sender (sandbox?): %v", err)
	}
	defer c.Close()
	sender := c.(*StdConn)
	if sender.isV4 {
		t.Skipf("sender came up v4-only; need a dual-stack v6 socket for this test")
	}

	// v4-mapped-in-v6 destination: routed through the kernel's IPv4 path.
	dst := netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), uint16(rxPort))
	const wantECN = byte(0x02) // ECT(0)

	if err := sender.WriteBatch([][]byte{[]byte("tos-probe")}, []netip.AddrPort{dst}, []byte{wantECN}); err != nil {
		t.Fatalf("WriteBatch: %v", err)
	}

	// Read the datagram plus its ancillary TOS.
	rx.SetReadDeadline(time.Now().Add(3 * time.Second))
	payload := make([]byte, 128)
	oob := make([]byte, 512)
	var n, oobn int
	var rerr error
	if err := rxRaw.Read(func(fd uintptr) bool {
		n, oobn, _, _, rerr = unix.Recvmsg(int(fd), payload, oob, 0)
		if rerr == syscall.EAGAIN || rerr == syscall.EWOULDBLOCK {
			return false
		}
		return true
	}); err != nil {
		t.Fatalf("waiting for datagram failed (no delivery?): %v", err)
	}
	if rerr != nil {
		t.Fatalf("Recvmsg: %v", rerr)
	}
	if string(payload[:n]) != "tos-probe" {
		t.Fatalf("payload = %q, want %q", string(payload[:n]), "tos-probe")
	}

	cmsgs, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		t.Fatalf("ParseSocketControlMessage: %v", err)
	}
	found := false
	var gotTOS byte
	for _, m := range cmsgs {
		if m.Header.Level == unix.IPPROTO_IP && m.Header.Type == unix.IP_TOS && len(m.Data) >= 1 {
			found = true
			gotTOS = m.Data[0]
		}
	}
	if !found {
		t.Fatalf("no IP_TOS cmsg delivered to v4 receiver — outer ECN did not land (%d cmsgs)", len(cmsgs))
	}
	if gotTOS&0x03 != wantECN {
		t.Errorf("received outer TOS = 0x%02x, want low-2-bits = 0x%02x", gotTOS, wantECN)
	} else {
		t.Logf("verified: v4 receiver saw outer TOS 0x%02x (ECN=0x%02x) from dual-stack sender", gotTOS, gotTOS&0x03)
	}
}
