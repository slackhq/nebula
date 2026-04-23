//go:build !android && !e2e_testing
// +build !android,!e2e_testing

package udp

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"unsafe"

	"github.com/rcrowley/go-metrics"
	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/config"
	"golang.org/x/sys/unix"
)

type StdConn struct {
	udpConn *net.UDPConn
	rawConn syscall.RawConn
	isV4    bool
	l       *logrus.Logger
	batch   int

	// sendmmsg scratch. Each queue has its own StdConn, so no locking is
	// needed. Sized to MaxWriteBatch at construction; WriteBatch chunks
	// larger inputs.
	writeMsgs  []rawMessage
	writeIovs  []iovec
	writeNames [][]byte

	// Per-entry UDP_SEGMENT cmsg scratch. writeCmsg is one contiguous slab
	// of MaxWriteBatch * writeCmsgSpace bytes; each entry's cmsg header is
	// pre-filled once in prepareWriteMessages. WriteBatch only rewrites the
	// 2-byte gso_size payload (and toggles Hdr.Control on/off) per call.
	writeCmsg      []byte
	writeCmsgSpace int

	// writeEntryEnd[e] is the bufs index *after* the last packet packed
	// into mmsghdr entry e. Used to rewind `i` on partial sendmmsg success.
	writeEntryEnd []int

	// Preallocated closure + in/out slots for sendmmsg, so the hot path
	// does not heap-allocate a fresh closure per call.
	writeChunk int
	writeSent  int
	writeErrno syscall.Errno
	writeFunc  func(fd uintptr) bool

	// UDP GSO (sendmsg with UDP_SEGMENT cmsg) support. gsoSupported is
	// probed once at socket creation. When true, WriteSegmented takes a
	// single-syscall GSO path; otherwise it falls back to a WriteTo loop.
	gsoSupported bool

	// UDP GRO (recvmsg with UDP_GRO cmsg) support. groSupported is probed
	// once at socket creation. When true, listenOutBatch allocates larger
	// RX buffers and a per-entry cmsg slot so the kernel can coalesce
	// consecutive same-flow datagrams into a single recvmmsg entry; the
	// delivered cmsg carries the gso_size used to split them back apart.
	groSupported bool
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

func NewListener(l *logrus.Logger, ip netip.Addr, port int, multi bool, batch int) (Conn, error) {
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
		udpConn: udpConn,
		rawConn: rawConn,
		l:       l,
		batch:   batch,
	}

	af, err := out.getSockOptInt(unix.SO_DOMAIN)
	if err != nil {
		_ = out.Close()
		return nil, err
	}
	out.isV4 = af == unix.AF_INET

	out.prepareWriteMessages(MaxWriteBatch)
	out.writeFunc = out.sendmmsgRawWrite

	out.prepareGSO()
	// GRO delivers coalesced superpackets that need a cmsg to split back
	// into segments. The single-packet RX path uses ReadFromUDPAddrPort
	// and cannot see that cmsg, so only enable GRO for the batch path.
	if batch > 1 {
		out.prepareGRO()
	}

	return out, nil
}

// prepareWriteMessages allocates one mmsghdr/iovec/sockaddr/cmsg scratch
// slot per sendmmsg entry. The iovec slab is sized to the same n so a
// single entry can fan out to up to n iovecs (needed for UDP_SEGMENT runs
// that coalesce consecutive bufs into one entry). Hdr.Iov / Hdr.Iovlen /
// Hdr.Control / Hdr.Controllen are wired per call since each entry can
// span a variable number of iovecs and may or may not carry a cmsg.
func (u *StdConn) prepareWriteMessages(n int) {
	u.writeMsgs = make([]rawMessage, n)
	u.writeIovs = make([]iovec, n)
	u.writeNames = make([][]byte, n)
	u.writeEntryEnd = make([]int, n)

	u.writeCmsgSpace = unix.CmsgSpace(2)
	u.writeCmsg = make([]byte, n*u.writeCmsgSpace)
	for k := 0; k < n; k++ {
		off := k * u.writeCmsgSpace
		h := (*unix.Cmsghdr)(unsafe.Pointer(&u.writeCmsg[off]))
		h.Level = unix.SOL_UDP
		h.Type = unix.UDP_SEGMENT
		setCmsgLen(h, unix.CmsgLen(2))
	}

	for i := range u.writeMsgs {
		u.writeNames[i] = make([]byte, unix.SizeofSockaddrInet6)
		u.writeMsgs[i].Hdr.Name = &u.writeNames[i][0]
	}
}

// maxGSOSegments caps the per-sendmsg GSO fan-out. Linux kernels have
// historically capped UDP_MAX_SEGMENTS at 64; newer kernels raise it to 128
// but we stay conservative so the same code works everywhere.
const maxGSOSegments = 64

// maxGSOBytes bounds the total payload per sendmsg() when UDP_SEGMENT is
// set. The kernel stitches all iovecs into a single skb whose length the
// UDP length field can represent, and also enforces sk_gso_max_size (which
// on most devices is 65536). We use 65535 so ciphertext + headers always
// fits, avoiding EMSGSIZE on large TSO superpackets.
const maxGSOBytes = 65535

// prepareGSO probes UDP_SEGMENT support
func (u *StdConn) prepareGSO() {
	var probeErr error
	if err := u.rawConn.Control(func(fd uintptr) {
		probeErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_UDP, unix.UDP_SEGMENT, 0)
	}); err != nil {
		return
	}
	if probeErr != nil {
		return
	}
	u.gsoSupported = true
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
		return
	}
	if probeErr != nil {
		return
	}
	u.groSupported = true
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
		r(from, buffer[:n])
		flush()
	}
}

func (u *StdConn) listenOutBatch(r EncReader, flush func()) error {
	var ip netip.Addr
	var n int
	var operr error

	bufSize := MTU
	cmsgSpace := 0
	if u.groSupported {
		bufSize = udpGROBufferSize
		cmsgSpace = unix.CmsgSpace(udpGROCmsgPayload)
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
			// Its ok to skip the ok check here, the slicing is the only error that can occur and it will panic
			if u.isV4 {
				ip, _ = netip.AddrFromSlice(names[i][4:8])
			} else {
				ip, _ = netip.AddrFromSlice(names[i][8:24])
			}
			from := netip.AddrPortFrom(ip.Unmap(), binary.BigEndian.Uint16(names[i][2:4]))
			payload := buffers[i][:msgs[i].Len]

			segSize := 0
			if u.groSupported {
				segSize = parseUDPGRO(&msgs[i].Hdr)
			}
			if segSize <= 0 || segSize >= len(payload) {
				// No coalescing happened (or a lone datagram).
				r(from, payload)
				continue
			}
			// GRO superpacket: the kernel guarantees every segment is
			// exactly segSize bytes except for the final one, which may be
			// short.
			for off := 0; off < len(payload); off += segSize {
				end := off + segSize
				if end > len(payload) {
					end = len(payload)
				}
				r(from, payload[off:end])
			}
		}
		// End-of-batch: let callers (e.g. TUN write coalescer) flush any
		// state they accumulated across this batch.
		flush()
	}
}

// parseUDPGRO walks the control buffer on hdr looking for a SOL_UDP/UDP_GRO
// cmsg and returns the gso_size (bytes per coalesced segment) it carries.
// Returns 0 when no UDP_GRO cmsg is present, which is the normal case for
// lone datagrams that the kernel did not coalesce.
func parseUDPGRO(hdr *msghdr) int {
	controllen := int(hdr.Controllen)
	if controllen < unix.SizeofCmsghdr || hdr.Control == nil {
		return 0
	}
	ctrl := unsafe.Slice(hdr.Control, controllen)
	off := 0
	for off+unix.SizeofCmsghdr <= len(ctrl) {
		ch := (*unix.Cmsghdr)(unsafe.Pointer(&ctrl[off]))
		clen := int(ch.Len)
		if clen < unix.SizeofCmsghdr || off+clen > len(ctrl) {
			return 0
		}
		if ch.Level == unix.SOL_UDP && ch.Type == unix.UDP_GRO {
			dataOff := off + unix.CmsgLen(0)
			if dataOff+udpGROCmsgPayload <= len(ctrl) {
				return int(int32(binary.NativeEndian.Uint32(ctrl[dataOff : dataOff+udpGROCmsgPayload])))
			}
			return 0
		}
		// Advance by the aligned cmsg space. CmsgSpace(n) is the stride
		// from one header to the next (len aligned up to the platform's
		// cmsg alignment).
		off += unix.CmsgSpace(clen - unix.CmsgLen(0))
	}
	return 0
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
// sendmmsg returns a fatal error before any entry is sent we fall back to
// per-packet WriteTo for that chunk so the caller still gets best-effort
// delivery.
func (u *StdConn) WriteBatch(bufs [][]byte, addrs []netip.AddrPort) error {
	if len(bufs) != len(addrs) {
		return fmt.Errorf("WriteBatch: len(bufs)=%d != len(addrs)=%d", len(bufs), len(addrs))
	}

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
			runLen, segSize := u.planRun(bufs, addrs, i, iovBudget)
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

			if runLen >= 2 {
				off := entry * u.writeCmsgSpace
				dataOff := off + unix.CmsgLen(0)
				binary.NativeEndian.PutUint16(u.writeCmsg[dataOff:dataOff+2], uint16(segSize))
				hdr.Control = &u.writeCmsg[off]
				setMsgControllen(hdr, u.writeCmsgSpace)
			} else {
				hdr.Control = nil
				setMsgControllen(hdr, 0)
			}

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
			// packet that was queued this iteration.
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
// A run of length 1 means the entry carries no cmsg and the kernel treats
// it as a plain datagram. Returns the run length and the per-segment size
// (which equals len(bufs[start])). Without GSO support every call returns
// runLen=1.
func (u *StdConn) planRun(bufs [][]byte, addrs []netip.AddrPort, start, iovBudget int) (int, int) {
	if start >= len(bufs) || iovBudget < 1 {
		return 0, 0
	}
	segSize := len(bufs[start])
	if !u.gsoSupported || segSize == 0 || segSize > maxGSOBytes {
		return 1, segSize
	}
	dst := addrs[start]
	maxLen := maxGSOSegments
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

// sendmmsgRawWrite is the preallocated callback passed to rawConn.Write. It
// reads its input (u.writeChunk) and writes its outputs (u.writeSent,
// u.writeErrno) through StdConn fields so the closure itself does not
// capture per-call locals and therefore does not heap-allocate.
func (u *StdConn) sendmmsgRawWrite(fd uintptr) bool {
	r1, _, errno := unix.Syscall6(
		unix.SYS_SENDMMSG,
		fd,
		uintptr(unsafe.Pointer(&u.writeMsgs[0])),
		uintptr(u.writeChunk),
		0,
		0,
		0,
	)
	if errno == syscall.EAGAIN || errno == syscall.EWOULDBLOCK {
		return false
	}
	u.writeSent = int(r1)
	u.writeErrno = errno
	return true
}

func (u *StdConn) sendmmsg(n int) (int, error) {
	u.writeChunk = n
	u.writeSent = 0
	u.writeErrno = 0
	if err := u.rawConn.Write(u.writeFunc); err != nil {
		return u.writeSent, err
	}
	if u.writeErrno != 0 {
		return u.writeSent, &net.OpError{Op: "sendmmsg", Err: u.writeErrno}
	}
	return u.writeSent, nil
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
		for j := 8; j < 16; j++ {
			buf[j] = 0
		}
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
				u.l.WithField("size", s).Info("listen.read_buffer was set")
			} else {
				u.l.WithError(err).Warn("Failed to get listen.read_buffer")
			}
		} else {
			u.l.WithError(err).Error("Failed to set listen.read_buffer")
		}
	}

	b = c.GetInt("listen.write_buffer", 0)
	if b > 0 {
		err := u.SetSendBuffer(b)
		if err == nil {
			s, err := u.GetSendBuffer()
			if err == nil {
				u.l.WithField("size", s).Info("listen.write_buffer was set")
			} else {
				u.l.WithError(err).Warn("Failed to get listen.write_buffer")
			}
		} else {
			u.l.WithError(err).Error("Failed to set listen.write_buffer")
		}
	}

	b = c.GetInt("listen.so_mark", 0)
	s, err := u.GetSoMark()
	if b > 0 || (err == nil && s != 0) {
		err := u.SetSoMark(b)
		if err == nil {
			s, err := u.GetSoMark()
			if err == nil {
				u.l.WithField("mark", s).Info("listen.so_mark was set")
			} else {
				u.l.WithError(err).Warn("Failed to get listen.so_mark")
			}
		} else {
			u.l.WithError(err).Error("Failed to set listen.so_mark")
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
