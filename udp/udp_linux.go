//go:build !android && !e2e_testing
// +build !android,!e2e_testing

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
	"syscall"
	"unsafe"

	"github.com/rcrowley/go-metrics"
	"github.com/slackhq/nebula/config"
	"golang.org/x/sys/unix"
)

type StdConn struct {
	udpConn *net.UDPConn
	rawConn syscall.RawConn
	isV4    bool
	l       *slog.Logger
	batch   int

	// sendmmsg scratch. Each queue has its own StdConn, so no locking is
	// needed. Sized to MaxWriteBatch at construction; WriteBatch chunks
	// larger inputs.
	writeMsgs  []rawMessage
	writeIovs  []iovec
	writeNames [][]byte

	// Per-entry cmsg scratch. writeCmsg is one contiguous slab of
	// MaxWriteBatch * writeCmsgSpace bytes; each entry holds two cmsg
	// headers (UDP_SEGMENT then IP_TOS / IPV6_TCLASS) pre-filled once in
	// prepareWriteMessages. WriteBatch only rewrites the per-call data
	// payloads and toggles Hdr.Control / Hdr.Controllen to point at
	// whichever subset of the two cmsgs applies.
	writeCmsg         []byte
	writeCmsgSpace    int
	writeCmsgSegSpace int
	writeCmsgEcnSpace int

	// writeEntryEnd[e] is the bufs index *after* the last packet packed
	// into mmsghdr entry e. Used to rewind `i` on partial sendmmsg success.
	writeEntryEnd []int

	// rawSend wraps the sendmmsg(2) callback in a closure-free helper so
	// the hot path doesn't heap-allocate a fresh closure per call.
	rawSend rawSendmmsg

	// UDP GSO (sendmsg with UDP_SEGMENT cmsg) support. gsoSupported is
	// probed once at socket creation. When true, WriteBatch packs same-
	// destination consecutive packets into a single sendmmsg entry with a
	// UDP_SEGMENT cmsg; otherwise each packet is its own entry.
	gsoSupported   bool
	maxGSOSegments int

	// UDP GRO (recvmsg with UDP_GRO cmsg) support. groSupported is probed
	// once at socket creation. When true, listenOutBatch allocates larger
	// RX buffers and a per-entry cmsg slot so the kernel can coalesce
	// consecutive same-flow datagrams into a single recvmmsg entry; the
	// delivered cmsg carries the gso_size used to split them back apart.
	groSupported bool

	// ecnRecvSupported is true when IP_RECVTOS / IPV6_RECVTCLASS was
	// successfully enabled — the kernel will deliver the outer IP-ECN of
	// each arriving datagram as a per-slot cmsg, and listenOutBatch passes
	// the parsed value to the EncReader callback for RFC 6040 combine.
	ecnRecvSupported bool
}

func setReusePort(network, address string, c syscall.RawConn) error {
	var opErr error
	err := c.Control(func(fd uintptr) {
		opErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
		//CloseOnExec already set by the runtime
	})
	if err != nil {
		return err
	}
	return opErr
}

func NewListener(l *slog.Logger, ip netip.Addr, port int, multi bool, batch int) (Conn, error) {
	listen := netip.AddrPortFrom(ip, uint16(port))
	lc := net.ListenConfig{}
	if multi {
		lc.Control = setReusePort
	}
	//this context is only used during the bind operation, you can't cancel it to kill the socket
	pc, err := lc.ListenPacket(context.Background(), "udp", listen.String())
	if err != nil {
		return nil, fmt.Errorf("unable to open socket: %s", err)
	}
	udpConn := pc.(*net.UDPConn)
	rawConn, err := udpConn.SyscallConn()
	if err != nil {
		_ = udpConn.Close()
		return nil, err
	}
	//gotta find out if we got an AF_INET6 socket or not:
	out := &StdConn{
		udpConn:        udpConn,
		rawConn:        rawConn,
		l:              l,
		batch:          batch,
		maxGSOSegments: 1,
	}

	af, err := out.getSockOptInt(unix.SO_DOMAIN)
	if err != nil {
		_ = out.Close()
		return nil, err
	}
	out.isV4 = af == unix.AF_INET

	out.prepareWriteMessages(MaxWriteBatch)
	out.rawSend.msgs = out.writeMsgs
	out.rawSend.bind()

	out.prepareGSO()
	// GRO delivers coalesced superpackets that need a cmsg to split back
	// into segments. The single-packet RX path uses ReadFromUDPAddrPort
	// and cannot see that cmsg, so only enable GRO for the batch path.
	if batch > 1 {
		out.prepareGRO()
	}
	// Best-effort: ask the kernel to deliver outer IP-ECN as ancillary data
	// on every recvmmsg slot so the decap side can apply RFC 6040 combine.
	// On older kernels these may not exist; failing here just means we get
	// 0 (Not-ECT) on every slot, which is the same as ecn_mode=disable.
	out.prepareECNRecv()

	return out, nil
}

// prepareWriteMessages allocates one mmsghdr/iovec/sockaddr/cmsg scratch
// slot per sendmmsg entry. The iovec slab is sized to n so all entries'
// iovecs share one allocation; per-entry fan-out is further capped at
// maxGSOSegments. Hdr.Iov / Hdr.Iovlen / Hdr.Control / Hdr.Controllen are
// wired per call since each entry can span a variable number of iovecs
// and may or may not carry a cmsg.
//
// Per-mmsghdr cmsg layout. Each entry's slot of length writeCmsgSpace holds
// up to two cmsg headers placed at fixed offsets:
//
//	[0 .. writeCmsgSegSpace)              UDP_SEGMENT (gso_size, uint16)
//	[writeCmsgSegSpace .. writeCmsgSpace) IP_TOS or IPV6_TCLASS (int32)
//
// Both headers are pre-filled once here; per-call we only rewrite the data
// payload and toggle Hdr.Control / Hdr.Controllen to point at whichever
// subset applies (none / segment-only / ecn-only / both).
func (u *StdConn) prepareWriteMessages(n int) {
	u.writeMsgs = make([]rawMessage, n)
	u.writeIovs = make([]iovec, n)
	u.writeNames = make([][]byte, n)
	u.writeEntryEnd = make([]int, n)

	u.writeCmsgSegSpace = unix.CmsgSpace(2)
	u.writeCmsgEcnSpace = unix.CmsgSpace(4)
	u.writeCmsgSpace = u.writeCmsgSegSpace + u.writeCmsgEcnSpace
	u.writeCmsg = make([]byte, n*u.writeCmsgSpace)

	ecnLevel := int32(unix.IPPROTO_IP)
	ecnType := int32(unix.IP_TOS)
	if !u.isV4 {
		ecnLevel = unix.IPPROTO_IPV6
		ecnType = unix.IPV6_TCLASS
	}

	for k := 0; k < n; k++ {
		base := k * u.writeCmsgSpace
		seg := (*unix.Cmsghdr)(unsafe.Pointer(&u.writeCmsg[base]))
		seg.Level = unix.SOL_UDP
		seg.Type = unix.UDP_SEGMENT
		setCmsgLen(seg, unix.CmsgLen(2))

		ecn := (*unix.Cmsghdr)(unsafe.Pointer(&u.writeCmsg[base+u.writeCmsgSegSpace]))
		ecn.Level = ecnLevel
		ecn.Type = ecnType
		setCmsgLen(ecn, unix.CmsgLen(4))
	}

	for i := range u.writeMsgs {
		u.writeNames[i] = make([]byte, unix.SizeofSockaddrInet6)
		u.writeMsgs[i].Hdr.Name = &u.writeNames[i][0]
	}
}

// maxGSOBytes bounds the total payload per sendmsg() when UDP_SEGMENT is
// set. The kernel stitches all iovecs into a single skb whose length the
// UDP length field can represent, and also enforces sk_gso_max_size (which
// on most devices is 65536). We use 65000 to leave headroom under the
// 65535 UDP-length cap, avoiding EMSGSIZE on large TSO superpackets.
const maxGSOBytes = 65000

// prepareGSO probes UDP_SEGMENT support and sets u.gsoSupported on success.
// Best-effort; failure leaves it false.
func (u *StdConn) prepareGSO() {
	u.maxGSOSegments = 63 //gotta be one less than the max so we can still attach a header

	var probeErr error
	if err := u.rawConn.Control(func(fd uintptr) {
		probeErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_UDP, unix.UDP_SEGMENT, 0)
	}); err != nil {
		u.l.Info("udp: GSO disabled", "reason", "rawconn control failed", "error", err)
		recordCapability("udp.gso.enabled", false)
		return
	}
	if probeErr != nil {
		u.l.Info("udp: GSO disabled", "reason", "kernel rejected probe", "error", probeErr)
		recordCapability("udp.gso.enabled", false)
		return
	}

	var un unix.Utsname
	if err := unix.Uname(&un); err != nil {
		u.l.Info("udp: GSO disabled", "reason", "kernel uname probe failed", "error", err)
		recordCapability("udp.gso.enabled", false)
		return
	}
	major, minor := parseRelease(string(un.Release[:]))
	if major > 5 || (major == 5 && minor >= 5) {
		u.maxGSOSegments = 127
	}

	u.gsoSupported = true
	u.l.Info("udp: GSO enabled", "maxGSOSegments", u.maxGSOSegments)
	recordCapability("udp.gso.enabled", true)
}

// udpGROBufferSize sizes the per-entry recvmmsg buffer when UDP_GRO is on.
// The kernel stitches a run of same-flow datagrams into a single skb whose
// length is bounded by sk_gso_max_size (typically 65535); anything larger
// would be MSG_TRUNCed. We use the maximum representable UDP length so a
// full superpacket always lands intact.
const udpGROBufferSize = 65535

// udpGROCmsgPayload is the size of the UDP_GRO cmsg data delivered by the
// kernel: a single int (gso_size in bytes). See udp_cmsg_recv() in
// net/ipv4/udp.c.
const udpGROCmsgPayload = 4

// prepareGRO turns on UDP_GRO so the kernel coalesces consecutive same-flow
// datagrams into one recvmmsg entry, with a cmsg carrying the gso_size used
// to split them back apart on the application side.
func (u *StdConn) prepareGRO() {
	var probeErr error
	if err := u.rawConn.Control(func(fd uintptr) {
		probeErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_UDP, unix.UDP_GRO, 1)
	}); err != nil {
		u.l.Info("udp: GRO disabled", "reason", "rawconn control failed", "error", err)
		recordCapability("udp.gro.enabled", false)
		return
	}
	if probeErr != nil {
		u.l.Info("udp: GRO disabled", "reason", "kernel rejected probe", "error", probeErr)
		recordCapability("udp.gro.enabled", false)
		return
	}
	u.groSupported = true
	u.l.Info("udp: GRO enabled")
	recordCapability("udp.gro.enabled", true)
}

// prepareECNRecv turns on IP_RECVTOS / IPV6_RECVTCLASS so the outer IP-ECN
// field of each arriving datagram is delivered as ancillary data alongside
// the payload. listenOutBatch reads it via parseRecvCmsg and passes the
// codepoint through the EncReader for RFC 6040 combine on the decap side.
// Best-effort: we keep going on failure.
func (u *StdConn) prepareECNRecv() {
	var v4err, v6err error
	if err := u.rawConn.Control(func(fd uintptr) {
		v4err = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_RECVTOS, 1)
		if !u.isV4 {
			v6err = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_RECVTCLASS, 1)
		}
	}); err != nil {
		u.l.Info("udp: outer-ECN RX disabled", "reason", "rawconn control failed", "error", err)
		recordCapability("udp.ecn_rx.enabled", false)
		return
	}
	if u.isV4 { //only check the V4 attempt
		if v4err != nil {
			u.l.Info("udp: outer-ECN RX disabled", "reason", "kernel rejected probe", "error", v4err)
			recordCapability("udp.ecn_rx.enabled", false)
		} else {
			u.ecnRecvSupported = true
			u.l.Info("udp: outer-ECN RX enabled")
			recordCapability("udp.ecn_rx.enabled", true)
		}
		return
	} else {
		if v6err != nil { //no V6 ECN? disable it.
			u.l.Info("udp: outer-ECN RX disabled", "reason", "kernel rejected probe", "error", errors.Join(v4err, v6err))
			recordCapability("udp.ecn_rx.enabled", false)
			return
		} else if v4err != nil { //no V4, but yes V6? Low level warning. Could be a V6-specific bind.
			u.l.Debug("udp: outer-ECN RX degraded", "reason", "kernel rejected probe on IPv4", "error", v4err)
		}
		// all good
		u.ecnRecvSupported = true
		u.l.Info("udp: outer-ECN RX enabled")
		recordCapability("udp.ecn_rx.enabled", true)
		return
	}
}

// recordCapability registers (or updates) a boolean gauge for one of the
// kernel-feature probes. Gauges go to 1 when the feature is enabled, 0 when
// it is not — dashboards can show degraded state on partially-supported
// kernels at a glance. Calling repeatedly with the same name updates the
// existing gauge rather than registering a duplicate.
func recordCapability(name string, enabled bool) {
	g := metrics.GetOrRegisterGauge(name, nil)
	if enabled {
		g.Update(1)
	} else {
		g.Update(0)
	}
}

func (u *StdConn) SupportsMultipleReaders() bool {
	return true
}

func (u *StdConn) Rebind() error {
	return nil
}

func (u *StdConn) getSockOptInt(opt int) (int, error) {
	if u.rawConn == nil {
		return 0, fmt.Errorf("no UDP connection")
	}
	var out int
	var opErr error
	err := u.rawConn.Control(func(fd uintptr) {
		out, opErr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, opt)
	})
	if err != nil {
		return 0, err
	}
	return out, opErr
}

func (u *StdConn) setSockOptInt(opt int, n int) error {
	if u.rawConn == nil {
		return fmt.Errorf("no UDP connection")
	}
	var opErr error
	err := u.rawConn.Control(func(fd uintptr) {
		opErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, opt, n)
	})
	if err != nil {
		return err
	}
	return opErr
}

func (u *StdConn) SetRecvBuffer(n int) error {
	return u.setSockOptInt(unix.SO_RCVBUFFORCE, n)
}

func (u *StdConn) SetSendBuffer(n int) error {
	return u.setSockOptInt(unix.SO_SNDBUFFORCE, n)
}

func (u *StdConn) SetSoMark(mark int) error {
	return u.setSockOptInt(unix.SO_MARK, mark)
}

func (u *StdConn) GetRecvBuffer() (int, error) {
	return u.getSockOptInt(unix.SO_RCVBUF)
}

func (u *StdConn) GetSendBuffer() (int, error) {
	return u.getSockOptInt(unix.SO_SNDBUF)
}

func (u *StdConn) GetSoMark() (int, error) {
	return u.getSockOptInt(unix.SO_MARK)
}

func (u *StdConn) LocalAddr() (netip.AddrPort, error) {
	a := u.udpConn.LocalAddr()

	switch v := a.(type) {
	case *net.UDPAddr:
		addr, ok := netip.AddrFromSlice(v.IP)
		if !ok {
			return netip.AddrPort{}, fmt.Errorf("LocalAddr returned invalid IP address: %s", v.IP)
		}
		return netip.AddrPortFrom(addr, uint16(v.Port)), nil

	default:
		return netip.AddrPort{}, fmt.Errorf("LocalAddr returned: %#v", a)
	}
}

func recvmmsg(fd uintptr, msgs []rawMessage) (int, bool, error) {
	var errno syscall.Errno
	n, _, errno := unix.Syscall6(
		unix.SYS_RECVMMSG,
		fd,
		uintptr(unsafe.Pointer(&msgs[0])),
		uintptr(len(msgs)),
		unix.MSG_WAITFORONE,
		0,
		0,
	)
	if errno == syscall.EAGAIN || errno == syscall.EWOULDBLOCK {
		// No data available, block for I/O and try again.
		return int(n), false, nil
	}
	if errno != 0 {
		return int(n), true, &net.OpError{Op: "recvmmsg", Err: errno}
	}
	return int(n), true, nil
}

func (u *StdConn) listenOutSingle(r EncReader, flush func()) error {
	var err error
	var n int
	var from netip.AddrPort
	buffer := make([]byte, MTU)

	for {
		n, from, err = u.udpConn.ReadFromUDPAddrPort(buffer)
		if err != nil {
			return err
		}
		from = netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
		// listenOutSingle uses ReadFromUDPAddrPort which discards cmsgs,
		// so the outer ECN field is not visible on this path. Zero RxMeta
		// (Not-ECT) means RFC 6040 combine is a no-op.
		r(from, buffer[:n], RxMeta{})
		flush()
	}
}

func getFrom(names [][]byte, i int, isV4 bool) netip.AddrPort {
	var ip netip.Addr
	// Its ok to skip the ok check here, the slicing is the only error that can occur and it will panic
	if isV4 {
		ip, _ = netip.AddrFromSlice(names[i][4:8])
	} else {
		ip, _ = netip.AddrFromSlice(names[i][8:24])
	}
	return netip.AddrPortFrom(ip.Unmap(), binary.BigEndian.Uint16(names[i][2:4]))
}

func (u *StdConn) listenOutBatch(r EncReader, flush func()) error {
	var n int
	var operr error

	bufSize := MTU
	cmsgSpace := 0
	if u.groSupported {
		bufSize = udpGROBufferSize
		cmsgSpace = unix.CmsgSpace(udpGROCmsgPayload)
	}
	if u.ecnRecvSupported {
		// IP_TOS arrives as 1 byte; IPV6_TCLASS arrives as a 4-byte int.
		// Reserve enough for the wider of the two so the same buffer fits
		// either family alongside any UDP_GRO cmsg.
		cmsgSpace += unix.CmsgSpace(4)
	}
	msgs, buffers, names, _ := u.PrepareRawMessages(u.batch, bufSize, cmsgSpace)

	//reader needs to capture variables from this function, since it's used as a lambda with rawConn.Read
	//defining it outside the loop so it gets re-used
	reader := func(fd uintptr) (done bool) {
		n, done, operr = recvmmsg(fd, msgs)
		return done
	}

	for {
		if cmsgSpace > 0 {
			for i := range msgs {
				setMsgControllen(&msgs[i].Hdr, cmsgSpace)
			}
		}
		err := u.rawConn.Read(reader)
		if err != nil {
			return err
		}
		if operr != nil {
			return operr
		}

		for i := 0; i < n; i++ {
			from := getFrom(names, i, u.isV4)
			payload := buffers[i][:msgs[i].Len]

			segSize := 0
			outerECN := byte(0)
			if cmsgSpace > 0 {
				segSize, outerECN = parseRecvCmsg(&msgs[i].Hdr, u.groSupported, u.ecnRecvSupported, u.isV4)
			}

			if segSize <= 0 || segSize >= len(payload) {
				r(from, payload, RxMeta{OuterECN: outerECN})
			} else {
				for off := 0; off < len(payload); off += segSize {
					end := off + segSize
					if end > len(payload) {
						end = len(payload)
					}
					seg := payload[off:end]
					r(from, seg, RxMeta{OuterECN: outerECN})
				}
			}
		}

		flush()
	}
}

// parseRecvCmsg walks the per-slot ancillary buffer once and extracts up to
// two values of interest in a single pass: the UDP_GRO gso_size (when
// wantGRO is true) and the outer IP-level ECN codepoint stamped on the
// carrier (when wantECN is true). Returns zeros for whichever field is not
// requested or not present. isV4 selects between IP_TOS (1-byte) and
// IPV6_TCLASS (4-byte int) cmsg payloads.
func parseRecvCmsg(hdr *msghdr, wantGRO, wantECN bool, isV4 bool) (gso int, ecn byte) {
	controllen := int(hdr.Controllen)
	if controllen < unix.SizeofCmsghdr || hdr.Control == nil {
		return 0, 0
	}
	ctrl := unsafe.Slice(hdr.Control, controllen)
	off := 0
	for off+unix.SizeofCmsghdr <= len(ctrl) {
		ch := (*unix.Cmsghdr)(unsafe.Pointer(&ctrl[off]))
		clen := int(ch.Len)
		if clen < unix.SizeofCmsghdr || off+clen > len(ctrl) {
			return gso, ecn
		}
		dataOff := off + unix.CmsgLen(0)
		switch {
		case wantGRO && ch.Level == unix.SOL_UDP && ch.Type == unix.UDP_GRO:
			if dataOff+udpGROCmsgPayload <= len(ctrl) {
				gso = int(int32(binary.NativeEndian.Uint32(ctrl[dataOff : dataOff+udpGROCmsgPayload])))
			}
		case wantECN && isV4 && ch.Level == unix.IPPROTO_IP && ch.Type == unix.IP_TOS:
			// IP_TOS arrives as a single byte; only the low 2 bits are ECN.
			if dataOff+1 <= len(ctrl) {
				ecn = ctrl[dataOff] & 0x03
			}
		case wantECN && !isV4 && ch.Level == unix.IPPROTO_IPV6 && ch.Type == unix.IPV6_TCLASS:
			// IPV6_TCLASS arrives as a 4-byte int; ECN is the low 2 bits.
			if dataOff+4 <= len(ctrl) {
				ecn = byte(binary.NativeEndian.Uint32(ctrl[dataOff:dataOff+4])) & 0x03
			}
		}
		// Advance by the aligned cmsg space.
		off += unix.CmsgSpace(clen - unix.CmsgLen(0))
	}
	return gso, ecn
}

func (u *StdConn) ListenOut(r EncReader, flush func()) error {
	if u.batch == 1 {
		return u.listenOutSingle(r, flush)
	} else {
		return u.listenOutBatch(r, flush)
	}
}

func (u *StdConn) WriteTo(b []byte, ip netip.AddrPort) error {
	_, err := u.udpConn.WriteToUDPAddrPort(b, ip)
	return err
}

// WriteBatch sends bufs via sendmmsg(2) using the preallocated scratch on
// StdConn. Consecutive packets to the same destination with matching segment
// sizes (all but possibly the last) are coalesced into a single mmsghdr entry
// carrying a UDP_SEGMENT cmsg, so one syscall can mix runs of GSO superpackets
// with plain one-off datagrams. Without GSO support every packet is its own
// entry, matching the prior behaviour.
//
// Chunks larger than the scratch are processed across multiple syscalls. If
// sendmmsg returns an error AND zero entries went out we fall back to
// per-packet WriteTo for that chunk so the caller still gets best-effort
// delivery; on a partial-success error we just replay the remainder.
func (u *StdConn) WriteBatch(bufs [][]byte, addrs []netip.AddrPort, ecns []byte) error {
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
	for i < len(bufs) {
		baseI := i
		entry := 0
		iovIdx := 0
		for entry < len(u.writeMsgs) && i < len(bufs) {
			iovBudget := len(u.writeIovs) - iovIdx
			if iovBudget < 1 {
				break
			}
			runLen, segSize := u.planRun(bufs, addrs, ecns, i, iovBudget)
			if runLen == 0 {
				break
			}

			for k := 0; k < runLen; k++ {
				b := bufs[i+k]
				if len(b) == 0 {
					u.writeIovs[iovIdx+k].Base = nil
					setIovLen(&u.writeIovs[iovIdx+k], 0)
				} else {
					u.writeIovs[iovIdx+k].Base = &b[0]
					setIovLen(&u.writeIovs[iovIdx+k], len(b))
				}
			}

			nlen, err := writeSockaddr(u.writeNames[entry], addrs[i], u.isV4)
			if err != nil {
				return err
			}

			hdr := &u.writeMsgs[entry].Hdr
			hdr.Iov = &u.writeIovs[iovIdx]
			setMsgIovlen(hdr, runLen)
			hdr.Namelen = uint32(nlen)

			var ecn byte
			if ecns != nil {
				ecn = ecns[i]
			}
			u.writeEntryCmsg(entry, runLen, segSize, ecn)

			i += runLen
			iovIdx += runLen
			u.writeEntryEnd[entry] = i
			entry++
		}

		if entry == 0 {
			return fmt.Errorf("sendmmsg: no progress")
		}

		sent, serr := u.sendmmsg(entry)
		if serr != nil && sent <= 0 {
			// Nothing went out for this chunk; fall back to WriteTo for each
			// packet that was queued this iteration. We only enter this path
			// when sendmmsg returned an error AND zero entries succeeded —
			// otherwise the partial-success advance below replays only the
			// remainder, avoiding duplicates of already-sent packets.
			//
			// sent=-1 from sendmmsg means message 0 itself failed (partial
			// success returns the count instead), so log entry 0's parameters
			// — that's the entry the kernel rejected.
			hdr0 := &u.writeMsgs[0].Hdr
			runLen0 := u.writeEntryEnd[0] - baseI
			seg0 := len(bufs[baseI])
			ecn0 := byte(0)
			if ecns != nil {
				ecn0 = ecns[baseI]
			}
			u.l.Warn("sendmmsg had problem",
				"sent", sent, "err", serr,
				"entries", entry,
				"entry0_runLen", runLen0,
				"entry0_segSize", seg0,
				"entry0_iovlen", hdr0.Iovlen,
				"entry0_controllen", hdr0.Controllen,
				"entry0_namelen", hdr0.Namelen,
				"entry0_ecn", ecn0,
				"entry0_dst", addrs[baseI],
				"isV4", u.isV4,
				"gso", u.gsoSupported,
				"gro", u.groSupported,
			)
			for k := baseI; k < i; k++ {
				if werr := u.WriteTo(bufs[k], addrs[k]); werr != nil {
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
		i = u.writeEntryEnd[sent-1]
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
func (u *StdConn) planRun(bufs [][]byte, addrs []netip.AddrPort, ecns []byte, start, iovBudget int) (int, int) {
	if start >= len(bufs) || iovBudget < 1 {
		return 0, 0
	}
	segSize := len(bufs[start])
	if !u.gsoSupported || segSize == 0 || segSize > maxGSOBytes {
		return 1, segSize
	}
	dst := addrs[start]
	var ecn byte
	if ecns != nil {
		ecn = ecns[start]
	}
	maxLen := u.maxGSOSegments
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
func (u *StdConn) writeEntryCmsg(entry, runLen, segSize int, ecn byte) {
	hdr := &u.writeMsgs[entry].Hdr
	useSeg := runLen >= 2
	useEcn := ecn != 0
	base := entry * u.writeCmsgSpace

	if useSeg {
		dataOff := base + unix.CmsgLen(0)
		binary.NativeEndian.PutUint16(u.writeCmsg[dataOff:dataOff+2], uint16(segSize))
	}
	if useEcn {
		dataOff := base + u.writeCmsgSegSpace + unix.CmsgLen(0)
		binary.NativeEndian.PutUint32(u.writeCmsg[dataOff:dataOff+4], uint32(ecn))
	}

	switch {
	case useSeg && useEcn:
		hdr.Control = &u.writeCmsg[base]
		setMsgControllen(hdr, u.writeCmsgSpace)
	case useSeg:
		hdr.Control = &u.writeCmsg[base]
		setMsgControllen(hdr, u.writeCmsgSegSpace)
	case useEcn:
		hdr.Control = &u.writeCmsg[base+u.writeCmsgSegSpace]
		setMsgControllen(hdr, u.writeCmsgEcnSpace)
	default:
		hdr.Control = nil
		setMsgControllen(hdr, 0)
	}
}

// sendmmsg issues sendmmsg(2) over u.rawConn against the first n entries
// of u.writeMsgs. Routes through u.rawSend so the per-call kernel callback
// stays alloc-free.
func (u *StdConn) sendmmsg(n int) (int, error) {
	return u.rawSend.send(u.rawConn, n)
}

// writeSockaddr encodes addr into buf (which must be at least
// SizeofSockaddrInet6 bytes). Returns the number of bytes used. If isV4 is
// true and addr is not a v4 (or v4-in-v6) address, returns an error.
func writeSockaddr(buf []byte, addr netip.AddrPort, isV4 bool) (int, error) {
	ap := addr.Addr().Unmap()
	if isV4 {
		if !ap.Is4() {
			return 0, ErrInvalidIPv6RemoteForSocket
		}
		// struct sockaddr_in: { sa_family_t(2), in_port_t(2, BE), in_addr(4), zero(8) }
		// sa_family is host endian.
		binary.NativeEndian.PutUint16(buf[0:2], unix.AF_INET)
		binary.BigEndian.PutUint16(buf[2:4], addr.Port())
		ip4 := ap.As4()
		copy(buf[4:8], ip4[:])
		clear(buf[8:16])
		return unix.SizeofSockaddrInet4, nil
	}
	// struct sockaddr_in6: { sa_family_t(2), in_port_t(2, BE), flowinfo(4), in6_addr(16), scope_id(4) }
	binary.NativeEndian.PutUint16(buf[0:2], unix.AF_INET6)
	binary.BigEndian.PutUint16(buf[2:4], addr.Port())
	binary.NativeEndian.PutUint32(buf[4:8], 0)
	ip6 := addr.Addr().As16()
	copy(buf[8:24], ip6[:])
	binary.NativeEndian.PutUint32(buf[24:28], 0)
	return unix.SizeofSockaddrInet6, nil
}

func (u *StdConn) ReloadConfig(c *config.C) {
	b := c.GetInt("listen.read_buffer", 0)
	if b > 0 {
		err := u.SetRecvBuffer(b)
		if err == nil {
			s, err := u.GetRecvBuffer()
			if err == nil {
				u.l.Info("listen.read_buffer was set", "size", s)
			} else {
				u.l.Warn("Failed to get listen.read_buffer", "error", err)
			}
		} else {
			u.l.Error("Failed to set listen.read_buffer", "error", err)
		}
	}

	b = c.GetInt("listen.write_buffer", 0)
	if b > 0 {
		err := u.SetSendBuffer(b)
		if err == nil {
			s, err := u.GetSendBuffer()
			if err == nil {
				u.l.Info("listen.write_buffer was set", "size", s)
			} else {
				u.l.Warn("Failed to get listen.write_buffer", "error", err)
			}
		} else {
			u.l.Error("Failed to set listen.write_buffer", "error", err)
		}
	}

	b = c.GetInt("listen.so_mark", 0)
	s, err := u.GetSoMark()
	if b > 0 || (err == nil && s != 0) {
		err := u.SetSoMark(b)
		if err == nil {
			s, err := u.GetSoMark()
			if err == nil {
				u.l.Info("listen.so_mark was set", "mark", s)
			} else {
				u.l.Warn("Failed to get listen.so_mark", "error", err)
			}
		} else {
			u.l.Error("Failed to set listen.so_mark", "error", err)
		}
	}
}

func (u *StdConn) getMemInfo(meminfo *[unix.SK_MEMINFO_VARS]uint32) error {
	var vallen uint32 = 4 * unix.SK_MEMINFO_VARS

	if u.rawConn == nil {
		return fmt.Errorf("no UDP connection")
	}
	var opErr error
	err := u.rawConn.Control(func(fd uintptr) {
		_, _, syserr := unix.Syscall6(unix.SYS_GETSOCKOPT, fd, uintptr(unix.SOL_SOCKET), uintptr(unix.SO_MEMINFO), uintptr(unsafe.Pointer(meminfo)), uintptr(unsafe.Pointer(&vallen)), 0)
		if syserr != 0 {
			opErr = syserr
		}
	})
	if err != nil {
		return err
	}
	return opErr
}

func (u *StdConn) Close() error {
	if u.udpConn != nil {
		return u.udpConn.Close()
	}
	return nil
}

func NewUDPStatsEmitter(udpConns []Conn) func() {
	// Check if our kernel supports SO_MEMINFO before registering the gauges
	var udpGauges [][unix.SK_MEMINFO_VARS]metrics.Gauge
	var meminfo [unix.SK_MEMINFO_VARS]uint32
	if err := udpConns[0].(*StdConn).getMemInfo(&meminfo); err == nil {
		udpGauges = make([][unix.SK_MEMINFO_VARS]metrics.Gauge, len(udpConns))
		for i := range udpConns {
			udpGauges[i] = [unix.SK_MEMINFO_VARS]metrics.Gauge{
				metrics.GetOrRegisterGauge(fmt.Sprintf("udp.%d.rmem_alloc", i), nil),
				metrics.GetOrRegisterGauge(fmt.Sprintf("udp.%d.rcvbuf", i), nil),
				metrics.GetOrRegisterGauge(fmt.Sprintf("udp.%d.wmem_alloc", i), nil),
				metrics.GetOrRegisterGauge(fmt.Sprintf("udp.%d.sndbuf", i), nil),
				metrics.GetOrRegisterGauge(fmt.Sprintf("udp.%d.fwd_alloc", i), nil),
				metrics.GetOrRegisterGauge(fmt.Sprintf("udp.%d.wmem_queued", i), nil),
				metrics.GetOrRegisterGauge(fmt.Sprintf("udp.%d.optmem", i), nil),
				metrics.GetOrRegisterGauge(fmt.Sprintf("udp.%d.backlog", i), nil),
				metrics.GetOrRegisterGauge(fmt.Sprintf("udp.%d.drops", i), nil),
			}
		}
	}

	return func() {
		for i, gauges := range udpGauges {
			if err := udpConns[i].(*StdConn).getMemInfo(&meminfo); err == nil {
				for j := 0; j < unix.SK_MEMINFO_VARS; j++ {
					gauges[j].Update(int64(meminfo[j]))
				}
			}
		}
	}
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
