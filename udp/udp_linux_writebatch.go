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
//	         destination, equal sizes (a shorter packet only last), within
//	         maxGSOBytes and maxGSOSegments. Without GSO a run is always one
//	         packet. Runs are atomic: packed whole into one entry, or
//	         skipped whole if the socket cannot address their destination,
//	         leaving a hole (bufs indices covered by no entry).
//	entry    one mmsghdr slot of the sendmmsg array; the kernel's unit of
//	         success and failure. A multi-packet entry carries a UDP_SEGMENT
//	         cmsg and is sent as one superpacket the kernel segments into
//	         gso_size-byte datagrams. Entries never split.
//	chunk    the entries packed for one sendmmsg call, at most MaxWriteBatch.
//	batch    the caller's whole bufs/addrs pair, processed as one or more chunks.
type batchWriter struct {
	fd   int
	isV4 bool

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
	l     *slog.Logger

	// sendFn sends n prepared entries beginning at w.msgs[start]
	// This is a function pointer to facilitate testing.
	sendFn func(start, n int) (int, error)

	// Per-entry cmsg scratch: one contiguous slab of
	// MaxWriteBatch * cmsgSpace bytes holding one UDP_SEGMENT cmsg per entry.
	cmsg      []byte
	cmsgSpace int

	// entryEnd[e] is the bufs index after the last packet packed into entry e.
	// entryEnd[e]-entryPkts[e] recovers the bufs index the entry's run started at,
	// used to rewind i for the GSO-disable replay.
	entryEnd []int

	// entryPkts[e] is the number of packets packed into entry e.
	entryPkts []int
}

func newBatchWriter(fd int, isV4 bool, l *slog.Logger, offloadsEnabled bool) *batchWriter {
	w := &batchWriter{fd: fd, isV4: isV4, l: l}
	w.sendFn = w.sendmmsg
	if offloadsEnabled {
		w.prepareGSO()
	}
	w.prepareWriteMessages(MaxWriteBatch, offloadsEnabled)
	return w
}

// prepareWriteMessages allocates the per-entry mmsghdr/iovec/sockaddr/cmsg
// scratch. Hdr.Iov/Iovlen/Control/Controllen are wired per call, since an
// entry spans a variable number of iovecs and may or may not carry a cmsg.
//
// Each entry's cmsg slot holds one UDP_SEGMENT (gso_size, uint16) header,
// pre-filled here; only its payload is rewritten per call.
// Hdr.Control/Controllen select whether it applies (none / segment).
func (w *batchWriter) prepareWriteMessages(n int, offloadsEnabled bool) {
	w.msgs = make([]rawMessage, n)
	w.iovs = make([]iovec, n)
	w.names = make([][]byte, n)
	w.entryEnd = make([]int, n)
	w.entryPkts = make([]int, n)

	w.cmsgSpace = unix.CmsgSpace(2)

	for i := range w.msgs {
		w.names[i] = make([]byte, unix.SizeofSockaddrInet6)
		w.msgs[i].Hdr.Name = &w.names[i][0]
	}

	if !offloadsEnabled || !w.gsoSupported {
		return //avoid allocating cmsg space if we will never use it
	}

	w.cmsg = make([]byte, n*w.cmsgSpace)

	for k := range n {
		base := k * w.cmsgSpace
		seg := (*unix.Cmsghdr)(unsafe.Pointer(&w.cmsg[base]))
		seg.Level = unix.SOL_UDP
		seg.Type = unix.UDP_SEGMENT
		setCmsgLen(seg, unix.CmsgLen(2))
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
// Callers shall deliver same-destination packets contiguously and in counter order
//
// Batches larger than the scratch take one sendmmsg per chunk.
// A partial success resumes the same prepared entries at the first unsent entry.
// A zero-sent error means the kernel rejected the first remaining entry:
// its packets are dropped and the rest of the chunk resumes in place.
//
// Returns the number of packets sent. An error means the call itself failed.
// A short count means some destinations were undeliverable.
func (w *batchWriter) WriteBatch(bufs [][]byte, addrs []netip.AddrPort) (int, error) {
	if len(bufs) != len(addrs) {
		return 0, fmt.Errorf("WriteBatch: len(bufs)=%d != len(addrs)=%d", len(bufs), len(addrs))
	}

	// A destination the kernel rejects results in us dropping that entry (one packet, or one same-destination GSO run).
	// We count what actually made it out rather than returning an error.
	written := 0

	i := 0
	for i < len(bufs) {
		entry := 0
		iovIdx := 0
		for entry < len(w.msgs) && i < len(bufs) {
			iovBudget := len(w.iovs) - iovIdx
			if iovBudget < 1 {
				break
			}
			runLen, segSize := w.planRun(bufs, addrs, i, iovBudget)
			if runLen == 0 {
				break
			}

			for k := range runLen {
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

			w.writeEntryCmsg(entry, runLen, segSize)

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

		// Drain the packed entries without repacking: everything the packing
		// loop wired (iovecs, names, cmsgs) stays intact until the next chunk
		// overwrites it, so a partial success resumes the same sendmmsg array
		// at the first unsent entry, and a rejected entry is skipped in place.
		// Only the GSO-disable path replans, since its entries change shape.
		done := 0
		for done < entry {
			sent, serr := w.sendFn(done, entry-done)
			if sent > 0 {
				// Count packets per entry; the bufs index span would
				// overcount across holes left by skipped runs.
				for e := done; e < done+sent; e++ {
					written += w.entryPkts[e]
				}
				done += sent
				continue
			}
			if serr == nil {
				return written, fmt.Errorf("sendmmsg made no progress")
			}
			// sent<=0 means the first remaining entry itself failed.
			// EIO on a superpacket means the route cannot carry a GSO send even though the setsockopt probe passed:
			// udp_send_skb() returns EIO when:
			//   * the egress device lacks TX checksum offload (kernels through 6.10)
			//   * or when an xfrm policy covers the route.
			// Persistent, so disable GSO and replay from the failed run as one-packet entries.
			if w.gsoSupported && w.entryPkts[done] >= 2 && errors.Is(serr, unix.EIO) {
				w.gsoSupported = false
				w.l.Warn("udp: kernel rejected GSO send, disabling GSO", "error", serr)
				recordCapability("udp.gso.enabled", false)
				i = w.entryEnd[done] - w.entryPkts[done]
				break
			}
			// Any other zero-sent error is a per-entry failure.
			// Transient errnos (EINTR, ENOBUFS) were already retried inside sendFn.
			// These packets are doomed. Log them and move on.
			if w.l.Enabled(context.Background(), slog.LevelDebug) {
				w.l.Debug("sendmmsg rejected entry",
					"error", serr,
					"udpAddr", addrs[w.entryEnd[done]-w.entryPkts[done]],
					"packets", w.entryPkts[done],
					"gso", w.gsoSupported,
				)
			}
			done++
		}
	}
	return written, nil
}

// planRun returns the length of the run starting at start and its segment
// size (len(bufs[start])). A run of length 1 carries no UDP_SEGMENT cmsg
// and is sent as a plain datagram; without GSO support planRun always returns 1.
func (w *batchWriter) planRun(bufs [][]byte, addrs []netip.AddrPort, start, iovBudget int) (int, int) {
	if start >= len(bufs) || iovBudget < 1 {
		return 0, 0
	}
	segSize := len(bufs[start])
	if !w.gsoSupported || segSize == 0 || segSize > maxGSOBytes {
		return 1, segSize
	}
	dst := addrs[start]
	maxLen := min(iovBudget, w.maxGSOSegments)
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

// writeEntryCmsg writes one entry's UDP_SEGMENT payload when runLen >= 2 and
// points Hdr.Control at it; a single-packet entry carries no cmsg.
func (w *batchWriter) writeEntryCmsg(entry, runLen, segSize int) {
	hdr := &w.msgs[entry].Hdr
	base := entry * w.cmsgSpace

	if runLen >= 2 {
		dataOff := base + unix.CmsgLen(0)
		binary.NativeEndian.PutUint16(w.cmsg[dataOff:dataOff+2], uint16(segSize))
		hdr.Control = &w.cmsg[base]
		setMsgControllen(hdr, w.cmsgSpace)
	} else {
		hdr.Control = nil
		setMsgControllen(hdr, 0)
	}
}

// sendmmsg issues sendmmsg(2) against n entries of w.msgs starting at start.
//
// EINTR is automatically retried and will never be returned.
// ENOBUFS is retried enobufsRetries times, and should be treated like any other error
func (w *batchWriter) sendmmsg(start, n int) (int, error) {
	const enobufsRetries = 3
	for enobufs := 0; ; {
		r1, _, errno := unix.Syscall6(unix.SYS_SENDMMSG, uintptr(w.fd),
			uintptr(unsafe.Pointer(&w.msgs[start])), uintptr(n),
			0, 0, 0,
		)
		switch {
		case errno == unix.EINTR: //similar to stdlib's ignoringEINTRIO
			continue
		case errno == unix.ENOBUFS && enobufs < enobufsRetries:
			enobufs++ //worth a retry or three
			continue
		case errno != 0:
			return int(r1), &net.OpError{Op: "sendmmsg", Err: errno}
		}
		return int(r1), nil
	}
}
