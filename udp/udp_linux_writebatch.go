//go:build linux && !android && !e2e_testing

package udp

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

// batchWriter owns the sendmmsg(2)/UDP-GSO transmit path for a StdConn: the
// scratch WriteBatch packs mmsghdr entries into, plus the GSO capability
// state probed at socket creation. Each queue has its own StdConn and
// batchWriter, so no locking is needed.
//
// Terminology, smallest to largest:
//
//	packet   one element of bufs: a single UDP datagram. The unit of the
//	         returned written count.
//	run      consecutive packets planRun groups into one entry: same
//	         destination and outer ECN, equal sizes (a shorter packet only
//	         last), within maxGSOBytes and maxGSOSegments. Without GSO a run
//	         is always one packet. Runs are atomic: packed whole into one
//	         entry, or skipped whole if the socket cannot address their
//	         destination, leaving a hole (bufs indices covered by no entry).
//	entry    one mmsghdr slot of the sendmmsg array; the kernel's unit of
//	         success and failure. A multi-packet entry carries a UDP_SEGMENT
//	         cmsg and is sent as one superpacket the kernel segments into
//	         gso_size-byte datagrams. Entries never split.
//	chunk    the entries packed for one sendmmsg call, at most MaxWriteBatch.
//	batch    the caller's whole bufs/addrs/ecns triple, processed as one or
//	         more chunks.
type batchWriter struct {
	fd   int
	isV4 bool
	l    *slog.Logger

	// UDP GSO (sendmsg with UDP_SEGMENT cmsg) support, probed once at
	// socket creation and cleared by WriteBatch if the kernel later rejects
	// a GSO send (the setsockopt probe cannot see per-route limitations).
	// When true, WriteBatch coalesces runs into UDP_SEGMENT entries;
	// otherwise each packet is its own entry.
	gsoSupported   bool
	maxGSOSegments int

	// sendmmsg scratch, sized to MaxWriteBatch at construction; WriteBatch
	// chunks larger inputs.
	msgs  []rawMessage
	iovs  []iovec
	names [][]byte

	// Per-entry cmsg scratch: one contiguous slab of
	// MaxWriteBatch * cmsgSpace bytes holding two cmsg headers per entry
	// (UDP_SEGMENT, then IP_TOS / IPV6_TCLASS). Layout in
	// prepareWriteMessages.
	cmsg         []byte
	cmsgSpace    int
	cmsgSegSpace int
	cmsgEcnSpace int

	// entryEnd[e] is the bufs index after the last packet packed into entry
	// e. Used to rewind i on partial sendmmsg success.
	entryEnd []int

	// entryPkts[e] is the number of packets packed into entry e. Not
	// derivable from entryEnd: skipped runs leave holes in the bufs index space.
	entryPkts []int

	// sendFn sends the first n prepared entries. The real syscall in
	// production; tests inject partial-success and error scripts.
	sendFn func(n int) (int, error)
}

func newBatchWriter(fd int, isV4 bool, l *slog.Logger) *batchWriter {
	w := &batchWriter{fd: fd, isV4: isV4, l: l}
	w.sendFn = w.sendmmsg
	w.prepareWriteMessages(MaxWriteBatch)
	w.prepareGSO()
	return w
}

// prepareWriteMessages allocates the per-entry mmsghdr/iovec/sockaddr/cmsg
// scratch. Hdr.Iov/Iovlen/Control/Controllen are wired per call, since an
// entry spans a variable number of iovecs and may or may not carry cmsgs.
//
// Each entry's cmsg slot holds up to two headers at fixed offsets:
//
//	[0 .. cmsgSegSpace)          UDP_SEGMENT (gso_size, uint16)
//	[cmsgSegSpace .. cmsgSpace)  IP_TOS or IPV6_TCLASS (int32)
//
// The UDP_SEGMENT header is pre-filled here; only its payload is rewritten
// per call. The ECN header is written per entry by writeEntryCmsg because
// its Level/Type follow the destination's family. Hdr.Control/Controllen
// select whichever subset applies (none / segment / ecn / both).
func (w *batchWriter) prepareWriteMessages(n int) {
	w.msgs = make([]rawMessage, n)
	w.iovs = make([]iovec, n)
	w.names = make([][]byte, n)
	w.entryEnd = make([]int, n)
	w.entryPkts = make([]int, n)

	w.cmsgSegSpace = unix.CmsgSpace(2)
	w.cmsgEcnSpace = unix.CmsgSpace(4)
	w.cmsgSpace = w.cmsgSegSpace + w.cmsgEcnSpace
	w.cmsg = make([]byte, n*w.cmsgSpace)

	for k := 0; k < n; k++ {
		base := k * w.cmsgSpace
		seg := (*unix.Cmsghdr)(unsafe.Pointer(&w.cmsg[base]))
		seg.Level = unix.SOL_UDP
		seg.Type = unix.UDP_SEGMENT
		setCmsgLen(seg, unix.CmsgLen(2))
	}

	for i := range w.msgs {
		w.names[i] = make([]byte, unix.SizeofSockaddrInet6)
		w.msgs[i].Hdr.Name = &w.names[i][0]
	}
}

// maxGSOBytes bounds the total payload of one UDP_SEGMENT send. The kernel
// builds a single skb, which must fit the 16-bit UDP length field and
// sk_gso_max_size (65536 on most devices); 65000 leaves headroom for headers.
const maxGSOBytes = 65000

// prepareGSO probes UDP_SEGMENT support and sets w.gsoSupported on success.
// Best-effort; failure leaves it false.
func (w *batchWriter) prepareGSO() {
	w.maxGSOSegments = 63 // pre-6.9 cap; see gsoMaxSegments

	if err := unix.SetsockoptInt(w.fd, unix.IPPROTO_UDP, unix.UDP_SEGMENT, 0); err != nil {
		w.l.Info("udp: GSO disabled", "reason", "rawconn control failed", "error", err)
		recordCapability("udp.gso.enabled", false)
		return
	}

	var un unix.Utsname
	if err := unix.Uname(&un); err != nil {
		w.l.Warn("udp: kernel version probe failed, capping GSO at 63 segments", "error", err)
	} else {
		w.maxGSOSegments = gsoMaxSegments(string(un.Release[:]))
	}

	w.gsoSupported = true
	w.l.Info("udp: GSO enabled", "maxGSOSegments", w.maxGSOSegments)
	recordCapability("udp.gso.enabled", true)
}

// gsoMaxSegments returns the most segments one UDP_SEGMENT send may carry:
// the kernel cap (UDP_MAX_SEGMENTS: 64 before 6.9, 128 after) minus one,
// because the kernel counts the 8-byte UDP header against the gso_size * UDP_MAX_SEGMENTS budget.
func gsoMaxSegments(release string) int {
	major, minor := parseRelease(release)
	if major > 6 || (major == 6 && minor >= 9) {
		return 127
	}
	return 63
}

func parseRelease(r string) (major, minor int) {
	// strip anything after the second dot or any non-digit
	parts := strings.SplitN(r, ".", 3)
	if len(parts) < 2 {
		return 0, 0
	}
	major, _ = strconv.Atoi(parts[0])
	// minor may have trailing junk like "15-generic"
	mp := parts[1]
	for i, c := range mp {
		if c < '0' || c > '9' {
			mp = mp[:i]
			break
		}
	}
	minor, _ = strconv.Atoi(mp)
	return
}

// WriteBatch sends bufs via sendmmsg(2), coalescing runs into UDP_SEGMENT
// entries, so one syscall can mix GSO superpackets and plain datagrams.
// Without GSO support every packet is its own entry.
//
// Batches larger than the scratch take one sendmmsg per chunk. A zero-sent
// error means the kernel rejected entry 0: its packets are dropped and the
// rest of the chunk is replayed. A partial success replays the remainder.
//
// Returns the number of packets sent. An error means the call itself
// failed; a short count means some destinations were undeliverable.
func (w *batchWriter) WriteBatch(bufs [][]byte, addrs []netip.AddrPort, ecns []byte) (int, error) {
	if len(bufs) != len(addrs) {
		return 0, fmt.Errorf("WriteBatch: len(bufs)=%d != len(addrs)=%d", len(bufs), len(addrs))
	}
	if ecns != nil && len(ecns) != len(bufs) {
		return 0, fmt.Errorf("WriteBatch: len(ecns)=%d != len(bufs)=%d", len(ecns), len(bufs))
	}

	// Callers deliver same-destination packets contiguously and in counter order, so we run the GSO planner directly without a pre-sort.
	// A sorting pass measurably hurt throughput in microbenchmarks while providing no observed reordering benefit.

	// A destination the kernel rejects results in us dropping that entry (one packet, or one same-destination GSO run).
	// We count what actually made it out rather than returning an error.
	written := 0

	i := 0
	for i < len(bufs) {
		baseI := i
		entry := 0
		iovIdx := 0
		for entry < len(w.msgs) && i < len(bufs) {
			iovBudget := len(w.iovs) - iovIdx
			if iovBudget < 1 {
				break
			}
			runLen, segSize := w.planRun(bufs, addrs, ecns, i, iovBudget)
			if runLen == 0 {
				break
			}

			for k := 0; k < runLen; k++ {
				b := bufs[i+k]
				if len(b) == 0 {
					w.iovs[iovIdx+k].Base = nil
					setIovLen(&w.iovs[iovIdx+k], 0)
				} else {
					w.iovs[iovIdx+k].Base = &b[0]
					setIovLen(&w.iovs[iovIdx+k], len(b))
				}
			}

			nlen, err := writeSockaddr(w.names[entry], addrs[i], w.isV4)
			if err != nil {
				// The destination's address family does not match the socket
				// (e.g. an IPv6 remote on a v4-bound socket). The packets are
				// undeliverable and no entry is committed yet: skip the run.
				if w.l.Enabled(context.Background(), slog.LevelDebug) {
					w.l.Debug("skipping unroutable batch destination", "udpAddr", addrs[i], "packets", runLen, "error", err)
				}
				i += runLen
				continue
			}

			hdr := &w.msgs[entry].Hdr
			hdr.Iov = &w.iovs[iovIdx]
			setMsgIovlen(hdr, runLen)
			hdr.Namelen = uint32(nlen)

			var ecn byte
			if ecns != nil {
				ecn = ecns[i]
			}
			// ECN cmsg family follows the destination, not the socket
			dstIsV4 := addrs[i].Addr().Unmap().Is4()
			w.writeEntryCmsg(entry, runLen, segSize, ecn, dstIsV4)

			i += runLen
			iovIdx += runLen
			w.entryEnd[entry] = i
			w.entryPkts[entry] = runLen
			entry++
		}

		if entry == 0 {
			// Every remaining packet was skipped; i reached len(bufs).
			break
		}

		sent, serr := w.sendFn(entry)
		if serr != nil && sent <= 0 {
			// sent<=0 means entry 0 itself failed. EIO on a superpacket
			// means the route cannot carry a GSO send even though the
			// setsockopt probe passed: udp_send_skb() returns EIO when the
			// egress device lacks TX checksum offload (kernels through
			// 6.10) or when an xfrm policy covers the route. Persistent, so
			// disable GSO (socket-wide, though the kernel condition is
			// per-route) and replay the chunk as one-packet entries, still batched.
			if w.gsoSupported && w.entryPkts[0] >= 2 && errors.Is(serr, unix.EIO) {
				w.gsoSupported = false
				w.l.Warn("udp: kernel rejected GSO send, disabling GSO", "error", serr)
				recordCapability("udp.gso.enabled", false)
				i = baseI
				continue
			}
			// Any other zero-sent error is a per-entry failure:
			// an unreachable destination, a firewall EPERM, or a PMTU shrink after a roam
			// (EINVAL, or EMSGSIZE since kernel 6.14, once gso_size no longer fits the path).
			// Retrying the packets individually cannot succeed where the entry did not, and
			// disabling GSO cannot make oversized segments fit, so drop the entry and replay whatever was packed after it.
			// Small-segment entries still pass, so the tunnel stays up while full-size packets drop.
			w.l.Debug("sendmmsg rejected entry",
				"error", serr,
				"udpAddr", addrs[w.entryEnd[0]-w.entryPkts[0]],
				"packets", w.entryPkts[0],
				"gso", w.gsoSupported,
			)
			i = w.entryEnd[0]
			continue
		}
		if sent == 0 {
			return written, fmt.Errorf("sendmmsg made no progress")
		}
		// Rewind i to the end of the last sent entry: a no-op on full
		// success, a replay of the remainder on partial success. Count
		// packets per entry; the bufs index span would overcount across holes.
		for e := 0; e < sent; e++ {
			written += w.entryPkts[e]
		}
		i = w.entryEnd[sent-1]
	}
	return written, nil
}

// planRun returns the length of the run starting at start and its segment
// size (len(bufs[start])). A run of length 1 carries no UDP_SEGMENT cmsg
// and is sent as a plain datagram; without GSO support planRun always
// returns 1. Outer ECN is a run boundary: the kernel stamps one codepoint per entry.
func (w *batchWriter) planRun(bufs [][]byte, addrs []netip.AddrPort, ecns []byte, start, iovBudget int) (int, int) {
	if start >= len(bufs) || iovBudget < 1 {
		return 0, 0
	}
	segSize := len(bufs[start])
	if !w.gsoSupported || segSize == 0 || segSize > maxGSOBytes {
		return 1, segSize
	}
	dst := addrs[start]
	var ecn byte
	if ecns != nil {
		ecn = ecns[start]
	}
	maxLen := w.maxGSOSegments
	if iovBudget < maxLen {
		maxLen = iovBudget
	}
	runLen := 1
	total := segSize
	for runLen < maxLen && start+runLen < len(bufs) {
		nextLen := len(bufs[start+runLen])
		if nextLen == 0 || nextLen > segSize {
			break
		}
		if addrs[start+runLen] != dst {
			break
		}
		if ecns != nil && ecns[start+runLen] != ecn {
			break
		}
		if total+nextLen > maxGSOBytes {
			break
		}
		total += nextLen
		runLen++
		if nextLen < segSize {
			// A short packet must be the last in the run.
			break
		}
	}
	return runLen, segSize
}

// writeEntryCmsg writes one entry's cmsgs: the UDP_SEGMENT payload when
// runLen >= 2, the IP_TOS/IPV6_TCLASS cmsg when ecn != 0, then points
// Hdr.Control at the smallest span covering the cmsgs in use.
//
// The ECN cmsg family must match the destination, not the socket: on the
// default dual-stack v6 bind, a v4-mapped destination takes the kernel's
// IPv4 path, which reads IP_TOS and ignores IPV6_TCLASS. The payload is a
// 4-byte int for both families, so the cmsg space is the same.
func (w *batchWriter) writeEntryCmsg(entry, runLen, segSize int, ecn byte, dstIsV4 bool) {
	hdr := &w.msgs[entry].Hdr
	useSeg := runLen >= 2
	useEcn := ecn != 0
	base := entry * w.cmsgSpace

	if useSeg {
		dataOff := base + unix.CmsgLen(0)
		binary.NativeEndian.PutUint16(w.cmsg[dataOff:dataOff+2], uint16(segSize))
	}
	if useEcn {
		ecnHdr := (*unix.Cmsghdr)(unsafe.Pointer(&w.cmsg[base+w.cmsgSegSpace]))
		if dstIsV4 {
			ecnHdr.Level = int32(unix.IPPROTO_IP)
			ecnHdr.Type = int32(unix.IP_TOS)
		} else {
			ecnHdr.Level = int32(unix.IPPROTO_IPV6)
			ecnHdr.Type = int32(unix.IPV6_TCLASS)
		}
		setCmsgLen(ecnHdr, unix.CmsgLen(4))
		dataOff := base + w.cmsgSegSpace + unix.CmsgLen(0)
		binary.NativeEndian.PutUint32(w.cmsg[dataOff:dataOff+4], uint32(ecn))
	}

	switch {
	case useSeg && useEcn:
		hdr.Control = &w.cmsg[base]
		setMsgControllen(hdr, w.cmsgSpace)
	case useSeg:
		hdr.Control = &w.cmsg[base]
		setMsgControllen(hdr, w.cmsgSegSpace)
	case useEcn:
		hdr.Control = &w.cmsg[base+w.cmsgSegSpace]
		setMsgControllen(hdr, w.cmsgEcnSpace)
	default:
		hdr.Control = nil
		setMsgControllen(hdr, 0)
	}
}

// sendmmsg issues sendmmsg(2) against the first n entries of w.msgs.
func (w *batchWriter) sendmmsg(n int) (int, error) {
	r1, _, errno := unix.Syscall6(unix.SYS_SENDMMSG, uintptr(w.fd),
		uintptr(unsafe.Pointer(&w.msgs[0])), uintptr(n),
		0, 0, 0,
	)
	sent := int(r1)

	if errno != 0 {
		return sent, &net.OpError{Op: "sendmmsg", Err: errno}
	}
	return sent, nil
}
