//go:build !e2e_testing
// +build !e2e_testing

package udp

import (
	"fmt"
	"net"
	"syscall"
	"unsafe"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/firewall"
	"github.com/slackhq/nebula/header"
	"golang.org/x/sys/windows"
)

// Assert we meet the standard conn interface
var _ Conn = &WsaConn{}

//TODO: make it support reload as best you can!

type WsaConn struct {
	sysFd   windows.Handle
	l       *logrus.Logger
	batch   int
	hevents []windows.Handle
}

type msghdr struct {
	Name    *windows.RawSockaddrAny
	Namelen *int32
	Buf     []byte
	WSABuf  *windows.WSABuf
	Overlap *windows.Overlapped
	Flags   *uint32
}

type wsaMessage struct {
	Len *uint32
	Hdr msghdr
}

var (
	modws2_32 = windows.NewLazySystemDLL("ws2_32.dll")

	procWSACreateEvent           = modws2_32.NewProc("WSACreateEvent")
	procWSAGetLastError          = modws2_32.NewProc("WSAGetLastError")
	procWSAWaitForMultipleEvents = modws2_32.NewProc("WSAWaitForMultipleEvents")
	procWSAResetEvent            = modws2_32.NewProc("WSAResetEvent")
)

func WSACreateEvent() (windows.Handle, error) {
	handlePtr, _, errNum := syscall.Syscall(procWSACreateEvent.Addr(), 0, 0, 0, 0)
	if handlePtr == 0 {
		return 0, errNum
	} else {
		return windows.Handle(handlePtr), nil
	}
}

func WSAGetLastError() error {
	r1, _, _ := syscall.Syscall(procWSAGetLastError.Addr(), 0, 0, 0, 0)
	return syscall.Errno(r1)
}

func WSAWaitForMultipleEvents(cEvents uint32, events *windows.Handle, waitAll bool, timeout uint32, alertable bool) (result int32, err error) {
	var waitAllInt uint32 = 0
	var alertableInt uint32 = 0

	if waitAll {
		waitAllInt = 1
	}

	if alertable {
		alertableInt = 1
	}

	r1, _, errNum := syscall.Syscall6(
		procWSAWaitForMultipleEvents.Addr(),
		5,
		uintptr(cEvents),
		uintptr(unsafe.Pointer(events)),
		uintptr(waitAllInt),
		uintptr(timeout),
		uintptr(alertableInt),
		0)

	result = int32(r1)

	if result == -1 {
		if errNum != 0 {
			err = errNum
		} else {
			err = syscall.EINVAL
		}
	}

	return
}

func WSAResetEvent(hevent windows.Handle) error {
	r1, _, errNum := syscall.Syscall(procWSAResetEvent.Addr(), uintptr(hevent), 0, 0, 0)
	if r1 == 0 {
		return errNum
	} else {
		return nil
	}
}

func MAKEWORD(low, high uint8) uint32 {
	var ret uint16 = uint16(high)<<8 + uint16(low)
	return uint32(ret)
}

func NewWsaListener(l *logrus.Logger, ip net.IP, port int, multi bool, batch int) (*WsaConn, error) {
	var wsaData windows.WSAData

	l.Debug("Library [ws2_32.dll] loaded at ", modws2_32.Handle())
	l.Debug("Symbol [WSACreateEvent] loaded at ", procWSACreateEvent.Addr())
	l.Debug("Symbol [WSAGetLastError] loaded at ", procWSAGetLastError.Addr())
	l.Debug("Symbol [WSAWaitForMultipleEvents] loaded at ", procWSAWaitForMultipleEvents.Addr())
	l.Debug("Symbol [WSAResetEvent] loaded at ", procWSAResetEvent.Addr())

	if err := windows.WSAStartup(MAKEWORD(2, 2), &wsaData); err != nil {
		windows.WSACleanup()
		return nil, fmt.Errorf("unable to startup WSA: %s", err)
	}

	fd, err := windows.WSASocket(
		windows.AF_INET6,
		windows.SOCK_DGRAM,
		windows.IPPROTO_UDP,
		nil, 0, windows.WSA_FLAG_OVERLAPPED)

	// make the socket a dual-stack IP socket to serve ipv4 and ipv6
	windows.SetsockoptInt(fd, windows.IPPROTO_IPV6, windows.IPV6_V6ONLY, 0)

	if err != nil {
		windows.Close(fd)
		windows.WSACleanup()
		return nil, fmt.Errorf("unable to open socket: %s", err)
	}

	var lip [16]byte
	copy(lip[:], ip[:])

	if multi {
		return nil, fmt.Errorf("unable to set SO_REUSEPORT on windows", err)
	}

	//TODO: support multiple listening IPs (for limiting ipv6)
	if err := windows.Bind(fd, &windows.SockaddrInet6{Addr: lip, Port: port}); err != nil {
		return nil, fmt.Errorf("unable to bind to socket: %s", err)
	}

	return &WsaConn{sysFd: fd, l: l, batch: batch}, err
}

func (u *WsaConn) Rebind() error {
	return nil
}

func (u *WsaConn) SetRecvBuffer(n int) error {
	return windows.SetsockoptInt(u.sysFd, windows.SOL_SOCKET, windows.SO_RCVBUF, n)
}

func (u *WsaConn) SetSendBuffer(n int) error {
	return windows.SetsockoptInt(u.sysFd, windows.SOL_SOCKET, windows.SO_SNDBUF, n)
}

func (u *WsaConn) GetRecvBuffer() (int, error) {
	return windows.GetsockoptInt(u.sysFd, windows.SOL_SOCKET, windows.SO_RCVBUF)
}

func (u *WsaConn) GetSendBuffer() (int, error) {
	return windows.GetsockoptInt(u.sysFd, windows.SOL_SOCKET, windows.SO_SNDBUF)
}

func (u *WsaConn) LocalAddr() (*Addr, error) {
	sa, err := windows.Getsockname(u.sysFd)
	if err != nil {
		return nil, err
	}

	addr := &Addr{}
	switch sa := sa.(type) {
	case *windows.SockaddrInet4:
		addr.IP = net.IP{sa.Addr[0], sa.Addr[1], sa.Addr[2], sa.Addr[3]}.To16()
		addr.Port = uint16(sa.Port)
	case *windows.SockaddrInet6:
		addr.IP = sa.Addr[0:]
		addr.Port = uint16(sa.Port)
	}

	return addr, nil
}

func (u *WsaConn) PrepareWsaMessages(n int) ([]wsaMessage, [][]byte, []windows.RawSockaddrAny) {
	msgs := make([]wsaMessage, n)

	// all require allocation to sequential memory addresses
	buffers := make([][]byte, n)
	names := make([]windows.RawSockaddrAny, n)
	namelen := make([]int32, n)
	wsaBufs := make([]windows.WSABuf, n)
	len := make([]uint32, n)
	flags := make([]uint32, n)
	overlap := make([]windows.Overlapped, n)

	// the array must be available to provide to WSAWaitForMultipleEvents
	u.hevents = make([]windows.Handle, n)

	for i := range msgs {
		namelen[i] = int32(unsafe.Sizeof(names[i]))

		buffers[i] = make([]byte, MTU)
		wsaBufs[i].Len = MTU
		wsaBufs[i].Buf = &buffers[i][0]

		hevent, err := WSACreateEvent()
		if err != nil {
			u.l.WithError(err).Error("WSACreateEvent failed")
		}
		u.hevents[i] = hevent
		overlap[i].HEvent = u.hevents[i]

		msgs[i].Len = &len[i]
		msgs[i].Hdr = msghdr{
			Name:    &names[i],
			Namelen: &namelen[i],
			Buf:     buffers[i],
			WSABuf:  &wsaBufs[i],
			Overlap: &overlap[i],
			Flags:   &flags[i],
		}
	}

	return msgs, buffers, names
}

func (u *WsaConn) ListenOut(r EncReader, lhf LightHouseHandlerFunc, cache *firewall.ConntrackCacheTicker, q int) {
	plaintext := make([]byte, MTU)
	h := &header.H{}
	fwPacket := &firewall.Packet{}
	udpAddr := &Addr{}
	nb := make([]byte, 12, 12)
	msgs, buffers, names := u.PrepareWsaMessages(u.batch)

	read := u.ReadMulti
	if u.batch == 1 {
		read = u.ReadSingle
	}

	for {
		index, err := read(msgs)

		if err != nil {
			u.l.WithError(err).Error("Failed to read packets")
			continue
		}

		ip, port, err := RawsockAddrToIPAndPort(&names[index])
		if err != nil {
			u.l.WithError(err).Error("Failed to read packets")
		}

		udpAddr.IP = ip
		udpAddr.Port = port

		r(udpAddr, plaintext[:0], buffers[index][:*msgs[index].Len], h, fwPacket, lhf, nb, q, cache.Get(u.l))
	}
}

func RawsockAddrToIPAndPort(rsa *windows.RawSockaddrAny) (net.IP, uint16, error) {
	if rsa == nil {
		return nil, 0, syscall.EINVAL
	}

	switch rsa.Addr.Family {
	case syscall.AF_INET:
	case syscall.AF_INET6:
		var port uint16
		pp := (*syscall.RawSockaddrInet6)(unsafe.Pointer(rsa))
		ip := net.IP(pp.Addr[:])
		p := (*[2]byte)(unsafe.Pointer(&port))
		p[0] = byte(pp.Port >> 8)
		p[1] = byte(pp.Port)

		return ip, port, nil
	}

	return nil, 0, syscall.EAFNOSUPPORT
}

func (u *WsaConn) ReadSingle(msgs []wsaMessage) (int, error) {
	for {
		len, sa, err := windows.Recvfrom(u.sysFd, msgs[0].Hdr.Buf, 0)

		if err != nil {
			return 0, &net.OpError{Op: "Recvfrom", Err: err}
		}

		*msgs[0].Len = uint32(len)

		switch sa := sa.(type) {
		case *windows.SockaddrInet4:
		case *windows.SockaddrInet6:
			name := windows.RawSockaddrInet6{Family: windows.AF_INET6}

			copy(name.Addr[:], sa.Addr[:])
			name.Scope_id = sa.ZoneId

			name.Port = uint16(sa.Port)
			p := (*[2]byte)(unsafe.Pointer(&name.Port))
			p[0] = byte(sa.Port >> 8)
			p[1] = byte(sa.Port)

			*msgs[0].Hdr.Name = *(*windows.RawSockaddrAny)(unsafe.Pointer(&name))
		}

		// unlike the linux implementation, we need the buffer index.
		// for a single read this is always 0.
		return 0, nil
	}
}

func (u *WsaConn) ReadMulti(msgs []wsaMessage) (int, error) {
	flags := uint32(0)
	err := windows.WSARecvFrom(
		u.sysFd,
		msgs[0].Hdr.WSABuf,
		uint32(len(msgs)),
		msgs[0].Len,
		msgs[0].Hdr.Flags,
		msgs[0].Hdr.Name,
		msgs[0].Hdr.Namelen,
		msgs[0].Hdr.Overlap,
		nil)

	if err != nil && err != windows.ERROR_IO_PENDING {
		return -1, &net.OpError{Op: "WSARecvFrom", Err: err}
	}

	index, waitErr := WSAWaitForMultipleEvents(uint32(len(msgs)), &u.hevents[0], false, windows.INFINITE, false)

	if waitErr != nil {
		return -1, &net.OpError{Op: "WSAWaitForMultipleEvents", Err: waitErr}
	}

	WSAResetEvent(msgs[index].Hdr.Overlap.HEvent)

	if err == windows.ERROR_IO_PENDING {
		err = windows.WSAGetOverlappedResult(u.sysFd, msgs[index].Hdr.Overlap, msgs[index].Len, false, &flags)
	}

	return int(index), err
}

func (u *WsaConn) WriteTo(b []byte, addr *Addr) error {
	var buf [16]byte
	copy(buf[:], addr.IP.To16())
	sa := &windows.SockaddrInet6{Addr: buf, Port: int(addr.Port)}
	flags := 0

	for {
		err := windows.Sendto(u.sysFd, b, flags, sa)

		if err != nil {
			return &net.OpError{Op: "Sendto", Err: err}
		}

		//TODO: handle incomplete writes

		return nil
	}
}

func (u *WsaConn) ReloadConfig(c *config.C) {
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
}

func (u *WsaConn) Close() error {
	windows.Close(u.sysFd)
	windows.WSACleanup()

	return nil
}
