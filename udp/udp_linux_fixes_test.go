//go:build linux && !android && !e2e_testing

package udp

import (
	"encoding/binary"
	"fmt"
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
	return slog.New(slog.DiscardHandler)
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

	n, err := sender.WriteBatch(bufs, addrs, nil)
	if err != nil {
		t.Fatalf("WriteBatch returned error, want nil (bad dest should be isolated): %v", err)
	}
	if n != 2 {
		t.Errorf("WriteBatch wrote %d packets, want 2 of 3 (the bad-family dest is the only casualty)", n)
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

	if _, err := sender.WriteBatch([][]byte{[]byte("tos-probe")}, []netip.AddrPort{dst}, []byte{wantECN}); err != nil {
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

// TestWriteBatchUnreachableDestDeliversOthers is the sendmmsg-fallback twin of
// TestWriteBatchBadFamilyDeliversOthers. A destination the kernel refuses outright (240.0.0.0/4 is reserved, so
// sendto returns EINVAL) makes sendmmsg fail for the whole chunk; the per-packet replay must then still deliver
// every other packet rather than abandoning the batch at the first failure.
func TestWriteBatchUnreachableDestDeliversOthers(t *testing.T) {
	rx, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Skipf("cannot open v4 receiver (sandbox?): %v", err)
	}
	defer rx.Close()
	rxPort := rx.LocalAddr().(*net.UDPAddr).Port

	c, err := NewListener(testLogger(), netip.MustParseAddr("127.0.0.1"), 0, false, 1)
	if err != nil {
		t.Skipf("cannot open v4 sender (sandbox?): %v", err)
	}
	defer c.Close()
	sender := c.(*StdConn)

	good := netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), uint16(rxPort))
	bad := netip.MustParseAddrPort("240.0.0.1:9999") // reserved space, the kernel refuses it

	bufs := [][]byte{[]byte("P0"), []byte("P1"), []byte("BAD"), []byte("P3"), []byte("P4")}
	addrs := []netip.AddrPort{good, good, bad, good, good}

	// The bad destination is reported, but only after every other packet has been attempted.
	if _, err := sender.WriteBatch(bufs, addrs, nil); err == nil {
		t.Log("WriteBatch returned nil; kernel accepted the reserved address, delivery assertions still apply")
	}

	got := map[string]bool{}
	rx.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 64)
	for i := 0; i < 4; i++ {
		n, _, rerr := rx.ReadFromUDPAddrPort(buf)
		if rerr != nil {
			t.Fatalf("expected 4 delivered packets, read #%d failed: %v (got so far: %v)", i+1, rerr, got)
		}
		got[string(buf[:n])] = true
	}
	for _, want := range []string{"P0", "P1", "P3", "P4"} {
		if !got[want] {
			t.Errorf("packet %s was not delivered; delivered set = %v", want, got)
		}
	}
}

// TestParseRecvCmsgCorruptLenNoPanic: a cmsg Len near max-int used to wrap
// off+clen negative, slip past the bounds check, and drive the walk offset
// negative -- a panic on the next ctrl[off]. The guard must compare Len
// against the remaining bytes instead. Also pins the plain truncated-Len
// cases (too small, larger than the buffer) to a clean early return.
func TestParseRecvCmsgCorruptLenNoPanic(t *testing.T) {
	// First cmsg: a valid empty one so the walk advances past off=0
	// (off+clen can't overflow while off is still zero).
	valid := buildCmsg(int32(unix.SOL_UDP), int32(unix.UDP_GRO), make([]byte, 4))

	corrupt := func(lenVal int) []byte {
		buf := make([]byte, len(valid)+unix.CmsgSpace(4))
		copy(buf, valid)
		h := (*unix.Cmsghdr)(unsafe.Pointer(&buf[len(valid)]))
		h.Level = int32(unix.IPPROTO_IP)
		h.Type = int32(unix.IP_TOS)
		setCmsgLen(h, lenVal)
		return buf
	}

	cases := []struct {
		name string
		ctrl []byte
	}{
		{"len_near_max_int", corrupt(int(^uint(0)>>1) - 8)},
		{"len_too_small", corrupt(unix.SizeofCmsghdr - 1)},
		{"len_past_buffer", corrupt(1 << 20)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			hdr := &msghdr{Control: &c.ctrl[0]}
			setMsgControllen(hdr, len(c.ctrl))
			gso, ecn := parseRecvCmsg(hdr, true, true)
			// The valid leading UDP_GRO cmsg (payload 0) must still parse;
			// the corrupt trailer just ends the walk.
			if gso != 0 || ecn != 0 {
				t.Errorf("parseRecvCmsg = (%d, %#x), want (0, 0)", gso, ecn)
			}
		})
	}
}

// TestDeliverSegments pins the GRO RX splitting: a kernel-coalesced buffer
// must come back out as the exact pre-coalesce packets -- every boundary
// error here shreds encrypted packets and every decrypt downstream fails.
func TestDeliverSegments(t *testing.T) {
	from := netip.MustParseAddrPort("192.0.2.1:4242")
	pay := func(n int) []byte {
		b := make([]byte, n)
		for i := range b {
			b[i] = byte(i)
		}
		return b
	}

	cases := []struct {
		name     string
		payload  []byte
		segSize  int
		wantLens []int
	}{
		{"no-gro", pay(1400), 0, []int{1400}},
		{"negative-segsize", pay(1400), -5, []int{1400}},
		{"segsize-equals-payload", pay(1400), 1400, []int{1400}},
		{"segsize-past-payload", pay(1400), 2000, []int{1400}},
		{"even-split", pay(4200), 1400, []int{1400, 1400, 1400}},
		{"short-tail", pay(3000), 1400, []int{1400, 1400, 200}},
		{"single-byte-tail", pay(2801), 1400, []int{1400, 1400, 1}},
		{"segsize-one", pay(3), 1, []int{1, 1, 1}},
		{"empty-payload", pay(0), 1400, []int{0}},
		{"max-coalesce", pay(65500), 1372, nil}, // lens derived below
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			wantLens := c.wantLens
			if wantLens == nil {
				for rem := len(c.payload); rem > 0; rem -= c.segSize {
					wantLens = append(wantLens, min(c.segSize, rem))
				}
			}

			var got [][]byte
			meta := RxMeta{OuterECN: 0x2}
			deliverSegments(func(a netip.AddrPort, seg []byte, m RxMeta) {
				if a != from {
					t.Errorf("from = %v, want %v", a, from)
				}
				if m != meta {
					t.Errorf("meta = %+v, want %+v", m, meta)
				}
				got = append(got, seg)
			}, from, c.payload, c.segSize, meta)

			if len(got) != len(wantLens) {
				t.Fatalf("delivered %d segments, want %d", len(got), len(wantLens))
			}
			// Segments must tile the payload in order with no gap, overlap,
			// or copy: each must alias the payload at the right offset.
			off := 0
			for i, seg := range got {
				if len(seg) != wantLens[i] {
					t.Fatalf("segment %d len=%d want %d", i, len(seg), wantLens[i])
				}
				if len(seg) > 0 && &seg[0] != &c.payload[off] {
					t.Errorf("segment %d does not alias payload at offset %d", i, off)
				}
				off += len(seg)
			}
			if off != len(c.payload) {
				t.Errorf("segments cover %d bytes, payload has %d", off, len(c.payload))
			}
		})
	}
}

// newRewindTestWriter builds a batchWriter with no socket: GSO planning on,
// sendFn left for the test to script. fd is invalid on purpose -- any path
// that actually hits the kernel (sendto fallback) fails loudly.
func newRewindTestWriter() *batchWriter {
	w := &batchWriter{fd: -1, isV4: true, l: testLogger()}
	w.prepareWriteMessages(MaxWriteBatch)
	w.gsoSupported = true
	w.maxGSOSegments = 63
	return w
}

// capturePrepared decodes the first n prepared mmsghdr entries straight
// from their iovecs -- ground truth, deliberately not the entryEnd
// bookkeeping the rewind logic itself relies on. Returns one []byte per
// packed packet, in entry order.
func capturePrepared(w *batchWriter, n int) [][]byte {
	var out [][]byte
	for e := 0; e < n; e++ {
		hdr := &w.msgs[e].Hdr
		iovs := unsafe.Slice(hdr.Iov, int(hdr.Iovlen))
		for _, iov := range iovs {
			b := make([]byte, int(iov.Len))
			if iov.Len > 0 {
				copy(b, unsafe.Slice(iov.Base, int(iov.Len)))
			}
			out = append(out, b)
		}
	}
	return out
}

// TestWriteBatchPartialSendRewind drives WriteBatch through scripted
// partial sendmmsg results and asserts the rewind resumes exactly where
// the kernel stopped: every packet on the wire exactly once, in order,
// no duplicate, no loss. This is the hairiest logic in the write path
// and a rewind bug means silent packet duplication or loss under EAGAIN-
// style backpressure.
func TestWriteBatchPartialSendRewind(t *testing.T) {
	dstA := netip.MustParseAddrPort("127.0.0.1:4242")
	dstB := netip.MustParseAddrPort("127.0.0.2:4242")

	mkBuf := func(tag byte, n int) []byte {
		b := make([]byte, n)
		for i := range b {
			b[i] = tag
		}
		b[0] = tag // tag identifies the packet uniquely below
		return b
	}

	// Mixed shape: a 3-packet GSO run to A, a lone short packet to A (run
	// tail), then two to B. The planner packs this as multiple entries with
	// multi-iovec runs, which is what makes the rewind arithmetic hairy.
	bufs := [][]byte{
		mkBuf(1, 1200), mkBuf(2, 1200), mkBuf(3, 1200), // run to A
		mkBuf(4, 600),                // short tail to A
		mkBuf(5, 900), mkBuf(6, 900), // run to B
	}
	addrs := []netip.AddrPort{dstA, dstA, dstA, dstA, dstB, dstB}

	scripts := [][]int{
		{99},          // accept everything first call
		{1, 99},       // one entry per call, then the rest
		{1, 1, 1, 99}, // strictly one entry per call
		{2, 99},       // two entries, then the rest
	}
	for si, script := range scripts {
		t.Run(fmt.Sprintf("script_%d", si), func(t *testing.T) {
			w := newRewindTestWriter()
			var wire [][]byte
			call := 0
			w.sendFn = func(n int) (int, error) {
				accept := n
				if call < len(script) && script[call] < n {
					accept = script[call]
				}
				call++
				wire = append(wire, capturePrepared(w, accept)...)
				return accept, nil
			}

			written, err := w.WriteBatch(bufs, addrs, nil)
			if err != nil {
				t.Fatalf("WriteBatch: %v", err)
			}
			if written != len(bufs) {
				t.Errorf("written = %d, want %d", written, len(bufs))
			}
			if len(wire) != len(bufs) {
				t.Fatalf("wire got %d packets, want %d (dup or loss in rewind)", len(wire), len(bufs))
			}
			for i, b := range wire {
				if len(b) != len(bufs[i]) || b[0] != bufs[i][0] {
					t.Errorf("wire[%d] = tag %d len %d, want tag %d len %d (reorder/dup)",
						i, b[0], len(b), bufs[i][0], len(bufs[i]))
				}
			}
		})
	}
}

// TestWriteBatchZeroProgress: sent == 0 with no error must abort with an
// error rather than spin forever replaying the same chunk.
func TestWriteBatchZeroProgress(t *testing.T) {
	w := newRewindTestWriter()
	w.sendFn = func(n int) (int, error) { return 0, nil }
	bufs := [][]byte{make([]byte, 100)}
	addrs := []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:4242")}
	if _, err := w.WriteBatch(bufs, addrs, nil); err == nil {
		t.Fatal("WriteBatch = nil error on zero progress, want error")
	}
}

// TestWriteBatchEIODisablesGSOAndReplays pins the runtime GSO give-up: a
// sendmmsg rejected with EIO on a GSO superpacket entry must clear
// gsoSupported and replay the same packets as per-packet entries through
// sendmmsg (keeping batching), not fall back to per-packet sendto.
func TestWriteBatchEIODisablesGSOAndReplays(t *testing.T) {
	dst := netip.MustParseAddrPort("127.0.0.1:4242")
	bufs := [][]byte{make([]byte, 1200), make([]byte, 1200), make([]byte, 1200)}
	addrs := []netip.AddrPort{dst, dst, dst}

	w := newRewindTestWriter()
	var entryCounts []int
	call := 0
	w.sendFn = func(n int) (int, error) {
		entryCounts = append(entryCounts, n)
		call++
		if call == 1 {
			return -1, &net.OpError{Op: "sendmmsg", Err: unix.EIO}
		}
		return n, nil
	}

	written, err := w.WriteBatch(bufs, addrs, nil)
	if err != nil {
		t.Fatalf("WriteBatch: %v", err)
	}
	if w.gsoSupported {
		t.Error("gsoSupported still true after EIO on a GSO entry")
	}
	if written != len(bufs) {
		t.Errorf("written = %d, want %d", written, len(bufs))
	}
	// First call: one GSO entry carrying the whole run. Replay: one entry
	// per packet, still via sendmmsg.
	want := []int{1, 3}
	if len(entryCounts) != len(want) || entryCounts[0] != want[0] || entryCounts[1] != want[1] {
		t.Errorf("sendmmsg entry counts = %v, want %v", entryCounts, want)
	}
}

// TestGSOEngagesOnLoopback is the offload smoke test: real sockets, real
// UDP_SEGMENT cmsg, real kernel segmentation over loopback. It asserts
// both that GSO *engaged* (the whole batch left in a single sendmmsg
// entry -- a silent fallback to per-packet entries fails the test) and
// that the kernel carved the superpacket back into the exact original
// datagrams on the receive side. Runs in CI (make test on ubuntu-latest),
// which is what guards against the offload path silently degrading.
func TestGSOEngagesOnLoopback(t *testing.T) {
	rx, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen rx: %v", err)
	}
	defer rx.Close()
	dst := rx.LocalAddr().(*net.UDPAddr).AddrPort()

	uc, err := NewListener(testLogger(), netip.MustParseAddr("127.0.0.1"), 0, false, 8)
	if err != nil {
		t.Fatalf("NewListener: %v", err)
	}
	sc := uc.(*StdConn)
	defer sc.Close()

	if !sc.bw.gsoSupported {
		var un unix.Utsname
		_ = unix.Uname(&un)
		release := string(un.Release[:])
		if major, minor := parseRelease(release); major > 4 || (major == 4 && minor >= 18) {
			t.Fatalf("kernel %q supports UDP_SEGMENT but the GSO probe failed", release)
		}
		t.Skipf("kernel %q predates UDP_SEGMENT (4.18)", release)
	}

	// Spy on the real syscall to count entries per sendmmsg without
	// changing what hits the kernel.
	var entryCounts []int
	real := sc.bw.sendFn
	sc.bw.sendFn = func(n int) (int, error) {
		entryCounts = append(entryCounts, n)
		return real(n)
	}

	const numPkts = 8
	const pktLen = 1200
	bufs := make([][]byte, numPkts)
	addrs := make([]netip.AddrPort, numPkts)
	for i := range bufs {
		bufs[i] = make([]byte, pktLen)
		for j := range bufs[i] {
			bufs[i][j] = byte(i)
		}
		addrs[i] = dst
	}

	written, err := sc.WriteBatch(bufs, addrs, nil)
	if err != nil {
		t.Fatalf("WriteBatch: %v", err)
	}
	if written != numPkts {
		t.Fatalf("written = %d, want %d", written, numPkts)
	}
	// GSO engaged means the run went out as ONE sendmmsg entry carrying a
	// UDP_SEGMENT superpacket. Per-packet entries mean it silently fell
	// back -- exactly the regression this test exists to catch.
	if len(entryCounts) != 1 || entryCounts[0] != 1 {
		t.Fatalf("sendmmsg entry counts = %v, want [1]: GSO did not engage", entryCounts)
	}

	// The kernel must deliver the original datagram boundaries and bytes.
	_ = rx.SetReadDeadline(time.Now().Add(5 * time.Second))
	got := make([]byte, pktLen+1)
	for i := 0; i < numPkts; i++ {
		n, _, err := rx.ReadFromUDP(got)
		if err != nil {
			t.Fatalf("rx read %d: %v", i, err)
		}
		if n != pktLen {
			t.Fatalf("rx read %d: len=%d want %d (kernel segmented at wrong boundary)", i, n, pktLen)
		}
		for j := 0; j < n; j++ {
			if got[j] != byte(i) {
				t.Fatalf("rx read %d: byte %d = %#x, want %#x", i, j, got[j], byte(i))
			}
		}
	}
}
