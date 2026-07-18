//go:build linux && !android && !e2e_testing

package udp

import (
	"encoding/binary"
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
// per-queue scratch WriteBatch packs mmsghdr entries into, plus the GSO
// capability state probed once at socket creation. Each queue has its own
// StdConn and therefore its own batchWriter, so no locking is needed.
type batchWriter struct {
	fd   int
	isV4 bool
	l    *slog.Logger

	// UDP GSO (sendmsg with UDP_SEGMENT cmsg) support. gsoSupported is
	// probed once at socket creation. When true, WriteBatch packs same-
	// destination consecutive packets into a single sendmmsg entry with a
	// UDP_SEGMENT cmsg; otherwise each packet is its own entry.
	gsoSupported   bool
	maxGSOSegments int

	// sendmmsg scratch, sized to MaxWriteBatch at construction; WriteBatch
	// chunks larger inputs.
	msgs  []rawMessage
	iovs  []iovec
	names [][]byte

	// Per-entry cmsg scratch. cmsg is one contiguous slab of
	// MaxWriteBatch * cmsgSpace bytes; each entry holds two cmsg headers
	// (UDP_SEGMENT then IP_TOS / IPV6_TCLASS) pre-filled once in
	// prepareWriteMessages. WriteBatch only rewrites the per-call data
	// payloads and toggles Hdr.Control / Hdr.Controllen to point at
	// whichever subset of the two cmsgs applies.
	cmsg         []byte
	cmsgSpace    int
	cmsgSegSpace int
	cmsgEcnSpace int

	// entryEnd[e] is the bufs index *after* the last packet packed into
	// mmsghdr entry e. Used to rewind `i` on partial sendmmsg success.
	entryEnd []int
}

func newBatchWriter(fd int, isV4 bool, l *slog.Logger) *batchWriter {
	w := &batchWriter{fd: fd, isV4: isV4, l: l}
	w.prepareWriteMessages(MaxWriteBatch)
	w.prepareGSO()
	return w
}

// prepareWriteMessages allocates one mmsghdr/iovec/sockaddr/cmsg scratch
// slot per sendmmsg entry. The iovec slab is sized to n so all entries'
// iovecs share one allocation; per-entry fan-out is further capped at
// maxGSOSegments. Hdr.Iov / Hdr.Iovlen / Hdr.Control / Hdr.Controllen are
// wired per call since each entry can span a variable number of iovecs
// and may or may not carry a cmsg.
//
// Per-mmsghdr cmsg layout. Each entry's slot of length cmsgSpace holds
// up to two cmsg headers placed at fixed offsets:
//
//	[0 .. cmsgSegSpace)          UDP_SEGMENT (gso_size, uint16)
//	[cmsgSegSpace .. cmsgSpace)  IP_TOS or IPV6_TCLASS (int32)
//
// Both headers are pre-filled once here; per-call we only rewrite the data
// payload and toggle Hdr.Control / Hdr.Controllen to point at whichever
// subset applies (none / segment-only / ecn-only / both).
func (w *batchWriter) prepareWriteMessages(n int) {
	w.msgs = make([]rawMessage, n)
	w.iovs = make([]iovec, n)
	w.names = make([][]byte, n)
	w.entryEnd = make([]int, n)

	w.cmsgSegSpace = unix.CmsgSpace(2)
	w.cmsgEcnSpace = unix.CmsgSpace(4)
	w.cmsgSpace = w.cmsgSegSpace + w.cmsgEcnSpace
	w.cmsg = make([]byte, n*w.cmsgSpace)

	// Default the ECN header to the socket's own family. writeEntryCmsg
	// finalizes Level/Type per entry from the destination address (a v4-mapped
	// dst on a dual-stack v6 socket needs IP_TOS, not IPV6_TCLASS), so this is
	// only the value used before the first per-entry rewrite.
	ecnLevel := int32(unix.IPPROTO_IP)
	ecnType := int32(unix.IP_TOS)
	if !w.isV4 {
		ecnLevel = unix.IPPROTO_IPV6
		ecnType = unix.IPV6_TCLASS
	}

	for k := 0; k < n; k++ {
		base := k * w.cmsgSpace
		seg := (*unix.Cmsghdr)(unsafe.Pointer(&w.cmsg[base]))
		seg.Level = unix.SOL_UDP
		seg.Type = unix.UDP_SEGMENT
		setCmsgLen(seg, unix.CmsgLen(2))

		ecn := (*unix.Cmsghdr)(unsafe.Pointer(&w.cmsg[base+w.cmsgSegSpace]))
		ecn.Level = ecnLevel
		ecn.Type = ecnType
		setCmsgLen(ecn, unix.CmsgLen(4))
	}

	for i := range w.msgs {
		w.names[i] = make([]byte, unix.SizeofSockaddrInet6)
		w.msgs[i].Hdr.Name = &w.names[i][0]
	}
}

// maxGSOBytes bounds the total payload per sendmsg() when UDP_SEGMENT is
// set. The kernel stitches all iovecs into a single skb whose length the
// UDP length field can represent, and also enforces sk_gso_max_size (which
// on most devices is 65536). We use 65000 to leave headroom under the
// 65535 UDP-length cap, avoiding EMSGSIZE on large TSO superpackets.
const maxGSOBytes = 65000

// prepareGSO probes UDP_SEGMENT support and sets w.gsoSupported on success.
// Best-effort; failure leaves it false.
func (w *batchWriter) prepareGSO() {
	w.maxGSOSegments = 63 //gotta be one less than the max so we can still attach a header

	if err := unix.SetsockoptInt(w.fd, unix.IPPROTO_UDP, unix.UDP_SEGMENT, 0); err != nil {
		w.l.Info("udp: GSO disabled", "reason", "rawconn control failed", "error", err)
		recordCapability("udp.gso.enabled", false)
		return
	}

	var un unix.Utsname
	if err := unix.Uname(&un); err != nil {
		w.l.Info("udp: GSO disabled", "reason", "kernel uname probe failed", "error", err)
		recordCapability("udp.gso.enabled", false)
		return
	}
	w.maxGSOSegments = gsoMaxSegments(string(un.Release[:]))

	w.gsoSupported = true
	w.l.Info("udp: GSO enabled", "maxGSOSegments", w.maxGSOSegments)
	recordCapability("udp.gso.enabled", true)
}

// gsoMaxSegments returns the largest number of UDP_SEGMENT segments a single
// sendmsg may carry on the running kernel, reserving one segment for the
// header. UDP_MAX_SEGMENTS was 64 until Linux v6.9 (commit 1382e3b6a350,
// "udp: change maximum number of UDP segments to 128") raised it to 128;
// nothing about this changed in 5.5. On kernels older than 6.9 packing more
// than 64 segments gets the sendmsg rejected with EINVAL, so cap at 63 there
// and only use 127 from 6.9 on. (Maintainer stance: update your kernel if you
// want to go fast — this is a plain version gate, not a runtime probe.)
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

// WriteBatch sends bufs via sendmmsg(2) using the preallocated scratch on
// batchWriter. Consecutive packets to the same destination with matching
// segment sizes (all but possibly the last) are coalesced into a single
// mmsghdr entry carrying a UDP_SEGMENT cmsg, so one syscall can mix runs of
// GSO superpackets with plain one-off datagrams. Without GSO support every
// packet is its own entry, matching the prior behaviour.
//
// Chunks larger than the scratch are processed across multiple syscalls. If
// sendmmsg returns an error AND zero entries went out we fall back to
// per-packet sendto for that chunk so the caller still gets best-effort
// delivery; on a partial-success error we just replay the remainder.
func (w *batchWriter) WriteBatch(bufs [][]byte, addrs []netip.AddrPort, ecns []byte) error {
	if len(bufs) != len(addrs) {
		return fmt.Errorf("WriteBatch: len(bufs)=%d != len(addrs)=%d", len(bufs), len(addrs))
	}
	if ecns != nil && len(ecns) != len(bufs) {
		return fmt.Errorf("WriteBatch: len(ecns)=%d != len(bufs)=%d", len(ecns), len(bufs))
	}

	// Callers deliver same-destination packets contiguously and in counter
	// order, so we run the GSO planner directly without a pre-sort. A
	// sorting pass measurably hurt throughput in microbenchmarks while
	// providing no observed reordering benefit.

	i := 0
sendChunks:
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
				// One destination in this chunk has an address family the
				// socket can't send to (e.g. an IPv6 remote on a v4-bound
				// socket → ErrInvalidIPv6RemoteForSocket). Abandoning the whole
				// sendmmsg here would drop every packet already packed for this
				// chunk plus every packet still ahead of us in bufs. Instead
				// fall back to per-packet sendto for the packets packed so far
				// in this chunk and the offending one: sendto delivers each
				// good destination and only errors on the bad one, which we
				// drop and keep going. One bad destination costs one packet,
				// never the batch. (Same fallback the zero-sent sendmmsg path
				// below uses, extended to cover the misaddressed packet.)
				for k := baseI; k <= i; k++ {
					if werr := sendto(w.fd, bufs[k], addrs[k], w.isV4); werr != nil && k != i {
						return werr
					}
				}
				i++
				continue sendChunks
			}

			hdr := &w.msgs[entry].Hdr
			hdr.Iov = &w.iovs[iovIdx]
			setMsgIovlen(hdr, runLen)
			hdr.Namelen = uint32(nlen)

			var ecn byte
			if ecns != nil {
				ecn = ecns[i]
			}
			// ECN cmsg family follows the destination, not the socket: a
			// v4-mapped dst on a dual-stack v6 socket must be stamped via
			// IP_TOS. addrs[i] is this run's destination (i advances below).
			dstIsV4 := addrs[i].Addr().Unmap().Is4()
			w.writeEntryCmsg(entry, runLen, segSize, ecn, dstIsV4)

			i += runLen
			iovIdx += runLen
			w.entryEnd[entry] = i
			entry++
		}

		if entry == 0 {
			return fmt.Errorf("sendmmsg: no progress")
		}

		sent, serr := w.sendmmsg(entry)
		if serr != nil && sent <= 0 {
			// Nothing went out for this chunk; fall back to sendto for each
			// packet that was queued this iteration. We only enter this path
			// when sendmmsg returned an error AND zero entries succeeded —
			// otherwise the partial-success advance below replays only the
			// remainder, avoiding duplicates of already-sent packets.
			//
			// sent=-1 from sendmmsg means message 0 itself failed (partial
			// success returns the count instead), so log entry 0's parameters
			// — that's the entry the kernel rejected.
			hdr0 := &w.msgs[0].Hdr
			runLen0 := w.entryEnd[0] - baseI
			seg0 := len(bufs[baseI])
			ecn0 := byte(0)
			if ecns != nil {
				ecn0 = ecns[baseI]
			}
			w.l.Warn("sendmmsg had problem",
				"sent", sent, "err", serr,
				"entries", entry,
				"entry0_runLen", runLen0,
				"entry0_segSize", seg0,
				"entry0_iovlen", hdr0.Iovlen,
				"entry0_controllen", hdr0.Controllen,
				"entry0_namelen", hdr0.Namelen,
				"entry0_ecn", ecn0,
				"entry0_dst", addrs[baseI],
				"isV4", w.isV4,
				"gso", w.gsoSupported,
			)
			for k := baseI; k < i; k++ {
				if werr := sendto(w.fd, bufs[k], addrs[k], w.isV4); werr != nil {
					return werr
				}
			}
			continue
		}
		if sent == 0 {
			return fmt.Errorf("sendmmsg made no progress")
		}
		// Rewind i to the end of the last successfully sent entry. For a
		// full-success send this leaves i unchanged; for a partial send it
		// replays the remainder on the next outer-loop iteration.
		i = w.entryEnd[sent-1]
	}
	return nil
}

// planRun groups consecutive packets starting at `start` that can be sent as
// a single UDP GSO superpacket (one sendmmsg entry with UDP_SEGMENT cmsg).
// A run of length 1 means the entry carries no UDP_SEGMENT cmsg and the
// kernel treats it as a plain datagram. Returns the run length and the
// per-segment size (which equals len(bufs[start])). Without GSO support
// every call returns runLen=1. Outer ECN (when ecns != nil) is also a run
// boundary — the kernel stamps one outer codepoint per sendmsg entry, so
// mixing values inside a run would lose information.
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

// writeEntryCmsg sets up the per-mmsghdr Hdr.Control / Hdr.Controllen for one
// entry. It writes the UDP_SEGMENT payload when runLen >= 2 and the
// IP_TOS/IPV6_TCLASS payload when ecn != 0, then points hdr.Control at the
// smallest contiguous span that covers whichever cmsg(s) actually apply.
//
// The outer-ECN cmsg family must match the *destination*, not the socket: on
// the default dual-stack v6 bind, a v4-mapped destination is routed through
// the kernel's IPv4 path, which parses IP_TOS (IPPROTO_IP) and ignores an
// IPV6_TCLASS cmsg. prepareWriteMessages pre-fills a default header; here we
// rewrite its Level/Type (and Len) per entry from dstIsV4 so v4 peers get
// IP_TOS and v6 peers get IPV6_TCLASS. The data payload is a 4-byte int for
// both families, so the pre-computed cmsg space is unchanged.
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
