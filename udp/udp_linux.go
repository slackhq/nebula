//go:build !android && !e2e_testing
// +build !android,!e2e_testing

package udp

import (
	"encoding/binary"
	"errors"
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
	sysFd        int
	isV4         bool
	l            *logrus.Logger
	batch        int
	gsoSupported bool
	groSupported bool
}

func maybeIPV4(ip net.IP) (net.IP, bool) {
	ip4 := ip.To4()
	if ip4 != nil {
		return ip4, true
	}
	return ip, false
}

// supportsUDPOffload checks if the kernel supports UDP GSO (Generic Segmentation Offload)
// by attempting to get the UDP_SEGMENT socket option.
func supportsUDPOffload(fd int) bool {
	_, err := unix.GetsockoptInt(fd, unix.IPPROTO_UDP, unix.UDP_SEGMENT)
	return err == nil
}

// supportsUDPGRO checks if the kernel supports UDP GRO (Generic Receive Offload)
// and attempts to enable it on the socket.
func supportsUDPGRO(fd int) bool {
	// Try to enable UDP_GRO
	err := unix.SetsockoptInt(fd, unix.IPPROTO_UDP, unix.UDP_GRO, 1)
	return err == nil
}

const (
	// Maximum number of datagrams that can be coalesced with GSO/GRO
	udpSegmentMaxDatagrams = 64

	// Maximum size of a GRO coalesced packet (64KB is the practical limit)
	// This is udpSegmentMaxDatagrams * MTU but capped at 65535
	groMaxPacketSize = 65535
)

// setGSOSize writes a UDP_SEGMENT control message to the provided buffer
// with the given segment size. Returns the actual control message length.
func setGSOSize(control []byte, gsoSize uint16) int {
	// Build the cmsghdr structure
	cmsgLen := unix.CmsgLen(2) // 2 bytes for uint16 segment size
	cmsg := (*unix.Cmsghdr)(unsafe.Pointer(&control[0]))
	cmsg.Level = unix.IPPROTO_UDP
	cmsg.Type = unix.UDP_SEGMENT
	cmsg.SetLen(cmsgLen)

	// Write the segment size after the header (after cmsghdr)
	binary.NativeEndian.PutUint16(control[unix.SizeofCmsghdr:], gsoSize)

	return unix.CmsgSpace(2) // aligned size
}

// getGROSize parses a control message buffer to extract the UDP_GRO segment size.
// Returns 0 if no GRO control message is present (meaning the packet is not coalesced).
func getGROSize(control []byte, controlLen int) uint16 {
	if controlLen < unix.SizeofCmsghdr {
		return 0
	}

	// Parse control messages
	for offset := 0; offset < controlLen; {
		if offset+unix.SizeofCmsghdr > controlLen {
			break
		}

		cmsg := (*unix.Cmsghdr)(unsafe.Pointer(&control[offset]))
		cmsgDataLen := int(cmsg.Len) - unix.SizeofCmsghdr
		if cmsgDataLen < 0 {
			break
		}

		if cmsg.Level == unix.IPPROTO_UDP && cmsg.Type == unix.UDP_GRO {
			if cmsgDataLen >= 2 {
				return binary.NativeEndian.Uint16(control[offset+unix.SizeofCmsghdr:])
			}
		}

		// Move to next control message (aligned)
		offset += unix.CmsgSpace(cmsgDataLen)
	}

	return 0
}

func NewListener(l *logrus.Logger, ip netip.Addr, port int, multi bool, batch int) (Conn, error) {
	af := unix.AF_INET6
	if ip.Is4() {
		af = unix.AF_INET
	}
	syscall.ForkLock.RLock()
	fd, err := unix.Socket(af, unix.SOCK_DGRAM, unix.IPPROTO_UDP)
	if err == nil {
		unix.CloseOnExec(fd)
	}
	syscall.ForkLock.RUnlock()

	if err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("unable to open socket: %s", err)
	}

	if multi {
		if err = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEPORT, 1); err != nil {
			return nil, fmt.Errorf("unable to set SO_REUSEPORT: %s", err)
		}
	}

	var sa unix.Sockaddr
	if ip.Is4() {
		sa4 := &unix.SockaddrInet4{Port: port}
		sa4.Addr = ip.As4()
		sa = sa4
	} else {
		sa6 := &unix.SockaddrInet6{Port: port}
		sa6.Addr = ip.As16()
		sa = sa6
	}
	if err = unix.Bind(fd, sa); err != nil {
		return nil, fmt.Errorf("unable to bind to socket: %s", err)
	}

	gsoSupported := supportsUDPOffload(fd)
	if gsoSupported {
		l.Info("UDP GSO offload is supported")
	}

	groSupported := supportsUDPGRO(fd)
	if groSupported {
		l.Info("UDP GRO offload is supported and enabled")
	}

	return &StdConn{sysFd: fd, isV4: ip.Is4(), l: l, batch: batch, gsoSupported: gsoSupported, groSupported: groSupported}, err
}

func (u *StdConn) SupportsMultipleReaders() bool {
	return true
}

func (u *StdConn) SupportsGSO() bool {
	return u.gsoSupported
}

func (u *StdConn) SupportsGRO() bool {
	return u.groSupported
}

func (u *StdConn) Rebind() error {
	return nil
}

func (u *StdConn) SetRecvBuffer(n int) error {
	return unix.SetsockoptInt(u.sysFd, unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, n)
}

func (u *StdConn) SetSendBuffer(n int) error {
	return unix.SetsockoptInt(u.sysFd, unix.SOL_SOCKET, unix.SO_SNDBUFFORCE, n)
}

func (u *StdConn) SetSoMark(mark int) error {
	return unix.SetsockoptInt(u.sysFd, unix.SOL_SOCKET, unix.SO_MARK, mark)
}

func (u *StdConn) GetRecvBuffer() (int, error) {
	return unix.GetsockoptInt(int(u.sysFd), unix.SOL_SOCKET, unix.SO_RCVBUF)
}

func (u *StdConn) GetSendBuffer() (int, error) {
	return unix.GetsockoptInt(int(u.sysFd), unix.SOL_SOCKET, unix.SO_SNDBUF)
}

func (u *StdConn) GetSoMark() (int, error) {
	return unix.GetsockoptInt(int(u.sysFd), unix.SOL_SOCKET, unix.SO_MARK)
}

func (u *StdConn) LocalAddr() (netip.AddrPort, error) {
	sa, err := unix.Getsockname(u.sysFd)
	if err != nil {
		return netip.AddrPort{}, err
	}

	switch sa := sa.(type) {
	case *unix.SockaddrInet4:
		return netip.AddrPortFrom(netip.AddrFrom4(sa.Addr), uint16(sa.Port)), nil

	case *unix.SockaddrInet6:
		return netip.AddrPortFrom(netip.AddrFrom16(sa.Addr), uint16(sa.Port)), nil

	default:
		return netip.AddrPort{}, fmt.Errorf("unsupported sock type: %T", sa)
	}
}

func (u *StdConn) ListenOut(r EncReader) {
	var ip netip.Addr

	msgs, buffers, names, controls := u.PrepareRawMessages(u.batch)
	read := u.ReadMulti
	if u.batch == 1 {
		read = u.ReadSingle
	}

	// Store the original control buffer size for resetting after each read
	controlLen := 0
	if u.groSupported && len(controls) > 0 && len(controls[0]) > 0 {
		controlLen = len(controls[0])
	}

	for {
		// Reset Controllen before each read - the kernel updates this field
		// after recvmsg to indicate actual received control data length
		if controlLen > 0 {
			for i := range msgs {
				setMsghdrControllen(&msgs[i].Hdr, controlLen)
			}
		}

		n, err := read(msgs)
		if err != nil {
			u.l.WithError(err).Debug("udp socket is closed, exiting read loop")
			return
		}

		for i := 0; i < n; i++ {
			// Extract source address
			if u.isV4 {
				ip, _ = netip.AddrFromSlice(names[i][4:8])
			} else {
				ip, _ = netip.AddrFromSlice(names[i][8:24])
			}
			srcAddr := netip.AddrPortFrom(ip.Unmap(), binary.BigEndian.Uint16(names[i][2:4]))

			// Check for GRO coalesced packet
			totalLen := int(msgs[i].Len)
			segmentSize := uint16(0)
			if controlLen > 0 {
				segmentSize = getGROSize(controls[i], getMsghdrControllen(&msgs[i].Hdr))
			}

			if segmentSize > 0 && totalLen > int(segmentSize) {
				// This is a GRO coalesced packet - split it into individual datagrams
				for offset := 0; offset < totalLen; {
					packetLen := int(segmentSize)
					if offset+packetLen > totalLen {
						// Last packet may be smaller
						packetLen = totalLen - offset
					}
					r(srcAddr, buffers[i][offset:offset+packetLen])
					offset += packetLen
				}
			} else {
				// Single packet, no coalescing
				r(srcAddr, buffers[i][:totalLen])
			}
		}
	}
}

func (u *StdConn) ReadSingle(msgs []rawMessage) (int, error) {
	for {
		n, _, err := unix.Syscall6(
			unix.SYS_RECVMSG,
			uintptr(u.sysFd),
			uintptr(unsafe.Pointer(&(msgs[0].Hdr))),
			0,
			0,
			0,
			0,
		)

		if err != 0 {
			return 0, &net.OpError{Op: "recvmsg", Err: err}
		}

		msgs[0].Len = uint32(n)
		return 1, nil
	}
}

func (u *StdConn) ReadMulti(msgs []rawMessage) (int, error) {
	for {
		n, _, err := unix.Syscall6(
			unix.SYS_RECVMMSG,
			uintptr(u.sysFd),
			uintptr(unsafe.Pointer(&msgs[0])),
			uintptr(len(msgs)),
			unix.MSG_WAITFORONE,
			0,
			0,
		)

		if err != 0 {
			return 0, &net.OpError{Op: "recvmmsg", Err: err}
		}

		return int(n), nil
	}
}

func (u *StdConn) WriteTo(b []byte, ip netip.AddrPort) error {
	if u.isV4 {
		return u.writeTo4(b, ip)
	}
	return u.writeTo6(b, ip)
}

func (u *StdConn) writeTo6(b []byte, ip netip.AddrPort) error {
	var rsa unix.RawSockaddrInet6
	rsa.Family = unix.AF_INET6
	rsa.Addr = ip.Addr().As16()
	binary.BigEndian.PutUint16((*[2]byte)(unsafe.Pointer(&rsa.Port))[:], ip.Port())

	for {
		_, _, err := unix.Syscall6(
			unix.SYS_SENDTO,
			uintptr(u.sysFd),
			uintptr(unsafe.Pointer(&b[0])),
			uintptr(len(b)),
			uintptr(0),
			uintptr(unsafe.Pointer(&rsa)),
			uintptr(unix.SizeofSockaddrInet6),
		)

		if err != 0 {
			return &net.OpError{Op: "sendto", Err: err}
		}

		return nil
	}
}

func (u *StdConn) writeTo4(b []byte, ip netip.AddrPort) error {
	if !ip.Addr().Is4() {
		return ErrInvalidIPv6RemoteForSocket
	}

	var rsa unix.RawSockaddrInet4
	rsa.Family = unix.AF_INET
	rsa.Addr = ip.Addr().As4()
	binary.BigEndian.PutUint16((*[2]byte)(unsafe.Pointer(&rsa.Port))[:], ip.Port())

	for {
		_, _, err := unix.Syscall6(
			unix.SYS_SENDTO,
			uintptr(u.sysFd),
			uintptr(unsafe.Pointer(&b[0])),
			uintptr(len(b)),
			uintptr(0),
			uintptr(unsafe.Pointer(&rsa)),
			uintptr(unix.SizeofSockaddrInet4),
		)

		if err != 0 {
			return &net.OpError{Op: "sendto", Err: err}
		}

		return nil
	}
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
	_, _, err := unix.Syscall6(unix.SYS_GETSOCKOPT, uintptr(u.sysFd), uintptr(unix.SOL_SOCKET), uintptr(unix.SO_MEMINFO), uintptr(unsafe.Pointer(meminfo)), uintptr(unsafe.Pointer(&vallen)), 0)
	if err != 0 {
		return err
	}
	return nil
}

func (u *StdConn) Close() error {
	return syscall.Close(u.sysFd)
}

func (u *StdConn) WriteBatch(pkts []BatchPacket) (int, error) {
	if len(pkts) == 0 {
		return 0, nil
	}

	// If GSO is supported, try to coalesce packets to the same destination
	if u.gsoSupported {
		return u.writeBatchGSO(pkts)
	}

	return u.writeBatchSendmmsg(pkts)
}

// writeBatchSendmmsg sends packets using sendmmsg without GSO coalescing
func (u *StdConn) writeBatchSendmmsg(pkts []BatchPacket) (int, error) {
	msgs := make([]rawMessage, len(pkts))
	iovecs := make([]iovec, len(pkts))
	var names4 []unix.RawSockaddrInet4
	var names6 []unix.RawSockaddrInet6

	if u.isV4 {
		names4 = make([]unix.RawSockaddrInet4, len(pkts))
	} else {
		names6 = make([]unix.RawSockaddrInet6, len(pkts))
	}

	for i := range pkts {
		setIovecBase(&iovecs[i], &pkts[i].Payload[0])
		setIovecLen(&iovecs[i], len(pkts[i].Payload))
		msgs[i].Hdr.Iov = &iovecs[i]
		setMsghdrIovlen(&msgs[i].Hdr, 1)

		if u.isV4 {
			names4[i].Family = unix.AF_INET
			names4[i].Addr = pkts[i].Addr.Addr().As4()
			binary.BigEndian.PutUint16((*[2]byte)(unsafe.Pointer(&names4[i].Port))[:], pkts[i].Addr.Port())
			msgs[i].Hdr.Name = (*byte)(unsafe.Pointer(&names4[i]))
			msgs[i].Hdr.Namelen = unix.SizeofSockaddrInet4
		} else {
			names6[i].Family = unix.AF_INET6
			names6[i].Addr = pkts[i].Addr.Addr().As16()
			binary.BigEndian.PutUint16((*[2]byte)(unsafe.Pointer(&names6[i].Port))[:], pkts[i].Addr.Port())
			msgs[i].Hdr.Name = (*byte)(unsafe.Pointer(&names6[i]))
			msgs[i].Hdr.Namelen = unix.SizeofSockaddrInet6
		}
	}

	var sent int
	for sent < len(msgs) {
		n, _, errno := unix.Syscall6(
			unix.SYS_SENDMMSG,
			uintptr(u.sysFd),
			uintptr(unsafe.Pointer(&msgs[sent])),
			uintptr(len(msgs)-sent),
			0,
			0,
			0,
		)

		if errno == unix.EINTR {
			continue
		}

		if errno != 0 {
			return sent, &net.OpError{Op: "sendmmsg", Err: errno}
		}

		sent += int(n)
	}

	return sent, nil
}

// writeBatchGSO sends packets using GSO coalescing when possible.
// Packets to the same destination with the same size are coalesced into a single
// GSO message. Mixed destinations or sizes fall back to individual sendmmsg calls.
func (u *StdConn) writeBatchGSO(pkts []BatchPacket) (int, error) {
	// Group packets by destination and try to coalesce
	totalSent := 0
	i := 0

	for i < len(pkts) {
		// Find a run of packets to the same destination with compatible sizes
		startIdx := i
		dst := pkts[i].Addr
		segmentSize := len(pkts[i].Payload)

		// Count how many packets we can coalesce (same destination, same size except possibly last)
		coalescedCount := 1
		totalSize := segmentSize
		for i+coalescedCount < len(pkts) && coalescedCount < udpSegmentMaxDatagrams {
			next := pkts[i+coalescedCount]
			if next.Addr != dst {
				break
			}
			nextSize := len(next.Payload)
			// For GSO, all packets except the last must have the same size
			// The last packet can be smaller (but not larger)
			if nextSize != segmentSize {
				// Check if this could be the last packet (smaller is ok)
				if nextSize < segmentSize && i+coalescedCount == len(pkts)-1 {
					coalescedCount++
					totalSize += nextSize
				}
				break
			}
			coalescedCount++
			totalSize += nextSize
		}

		// If we have multiple packets to coalesce, use GSO
		if coalescedCount > 1 {
			err := u.sendGSO(pkts[startIdx:startIdx+coalescedCount], dst, segmentSize, totalSize)
			if err != nil {
				// If GSO fails (e.g., EIO due to NIC not supporting checksum offload),
				// disable GSO and fall back to sendmmsg for the rest
				if isGSOError(err) {
					u.l.WithError(err).Warn("GSO send failed, disabling GSO for this connection")
					u.gsoSupported = false
					// Send remaining packets with sendmmsg
					remaining, rerr := u.writeBatchSendmmsg(pkts[startIdx:])
					return totalSent + remaining, rerr
				}
				return totalSent, err
			}
			totalSent += coalescedCount
			i += coalescedCount
		} else {
			// Single packet, send without GSO overhead
			err := u.WriteTo(pkts[i].Payload, pkts[i].Addr)
			if err != nil {
				return totalSent, err
			}
			totalSent++
			i++
		}
	}

	return totalSent, nil
}

// sendGSO sends coalesced packets using UDP GSO
func (u *StdConn) sendGSO(pkts []BatchPacket, dst netip.AddrPort, segmentSize, totalSize int) error {
	// Allocate a buffer large enough for all packet payloads
	coalescedBuf := make([]byte, totalSize)
	offset := 0
	for _, pkt := range pkts {
		copy(coalescedBuf[offset:], pkt.Payload)
		offset += len(pkt.Payload)
	}

	// Prepare control message with GSO segment size
	control := make([]byte, unix.CmsgSpace(2))
	controlLen := setGSOSize(control, uint16(segmentSize))

	// Prepare the iovec
	iov := iovec{}
	setIovecBase(&iov, &coalescedBuf[0])
	setIovecLen(&iov, totalSize)

	// Prepare the msghdr
	var hdr msghdr
	hdr.Iov = &iov
	setMsghdrIovlen(&hdr, 1)
	hdr.Control = &control[0]
	setMsghdrControllen(&hdr, controlLen)

	// Declare sockaddr at function scope so it remains valid for the syscall
	// (must not go out of scope before the syscall is made)
	var rsa4 unix.RawSockaddrInet4
	var rsa6 unix.RawSockaddrInet6

	// Set destination address
	if u.isV4 {
		rsa4.Family = unix.AF_INET
		rsa4.Addr = dst.Addr().As4()
		binary.BigEndian.PutUint16((*[2]byte)(unsafe.Pointer(&rsa4.Port))[:], dst.Port())
		hdr.Name = (*byte)(unsafe.Pointer(&rsa4))
		hdr.Namelen = unix.SizeofSockaddrInet4
	} else {
		rsa6.Family = unix.AF_INET6
		rsa6.Addr = dst.Addr().As16()
		binary.BigEndian.PutUint16((*[2]byte)(unsafe.Pointer(&rsa6.Port))[:], dst.Port())
		hdr.Name = (*byte)(unsafe.Pointer(&rsa6))
		hdr.Namelen = unix.SizeofSockaddrInet6
	}

	for {
		_, _, errno := unix.Syscall6(
			unix.SYS_SENDMSG,
			uintptr(u.sysFd),
			uintptr(unsafe.Pointer(&hdr)),
			0,
			0,
			0,
			0,
		)

		if errno == unix.EINTR {
			continue
		}

		if errno != 0 {
			return &net.OpError{Op: "sendmsg", Err: errno}
		}

		return nil
	}
}

// isGSOError returns true if the error indicates GSO is not supported by the NIC
func isGSOError(err error) bool {
	var opErr *net.OpError
	if !errors.As(err, &opErr) {
		return false
	}
	// EIO typically means the NIC doesn't support checksum offload required for GSO
	return errors.Is(opErr.Err, unix.EIO)
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
