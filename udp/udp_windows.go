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

//TODO: make it support reload as best you can!

type Conn struct {
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

type rawMessage struct {
	Len *uint32
	Hdr msghdr
}

var (
	modws2_32 = windows.NewLazySystemDLL("ws2_32.dll")

	procWSACreateEvent  = modws2_32.NewProc("WSACreateEvent")
	procWSAGetLastError = modws2_32.NewProc("WSAGetLastError")
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

func MAKEWORD(low, high uint8) uint32 {
	var ret uint16 = uint16(high)<<8 + uint16(low)
	return uint32(ret)
}

func NewListener(l *logrus.Logger, ip net.IP, port int, multi bool, batch int) (*Conn, error) {
	var wsaData windows.WSAData

	l.Debug("Library [ws2_32.dll] loaded at ", modws2_32.Handle())
	l.Debug("Symbol [WSACreateEvent] loaded at ", procWSACreateEvent.Addr())
	l.Debug("Symbol [WSAGetLastError] loaded at ", procWSAGetLastError.Addr())

	if err := windows.WSAStartup(MAKEWORD(2, 2), &wsaData); err != nil {
		windows.WSACleanup()
		return nil, fmt.Errorf("unable to startup WSA: %s", err)
	}

	fd, err := windows.WSASocket(
		windows.AF_INET,
		windows.SOCK_DGRAM,
		windows.IPPROTO_UDP,
		nil, 0, windows.WSA_FLAG_OVERLAPPED)

	if err != nil {
		windows.Close(fd)
		windows.WSACleanup()
		return nil, fmt.Errorf("unable to open socket: %s", err)
	}

	var lip [4]byte
	copy(lip[:], ip.To4())

	if multi {
		return nil, fmt.Errorf("unable to set SO_REUSEPORT on windows", err)
	}

	//TODO: support multiple listening IPs (for limiting ipv6)
	if err := windows.Bind(fd, &windows.SockaddrInet4{Addr: lip, Port: port}); err != nil {
		return nil, fmt.Errorf("unable to bind to socket: %s", err)
	}

	return &Conn{sysFd: fd, l: l, batch: batch}, err
}

func (u *Conn) Rebind() error {
	return nil
}

func (u *Conn) SetRecvBuffer(n int) error {
	return windows.SetsockoptInt(u.sysFd, windows.SOL_SOCKET, windows.SO_RCVBUF, n)
}

func (u *Conn) SetSendBuffer(n int) error {
	return windows.SetsockoptInt(u.sysFd, windows.SOL_SOCKET, windows.SO_SNDBUF, n)
}

func (u *Conn) GetRecvBuffer() (int, error) {
	return windows.GetsockoptInt(u.sysFd, windows.SOL_SOCKET, windows.SO_RCVBUF)
}

func (u *Conn) GetSendBuffer() (int, error) {
	return windows.GetsockoptInt(u.sysFd, windows.SOL_SOCKET, windows.SO_SNDBUF)
}

func (u *Conn) LocalAddr() (*Addr, error) {
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

func (u *Conn) PrepareRawMessages(n int) ([]rawMessage, [][]byte, []windows.RawSockaddrAny) {
	msgs := make([]rawMessage, n)

	// all require allocation to sequential memory addresses
	buffers := make([][]byte, n)
	names := make([]windows.RawSockaddrAny, n)
	namelen := make([]int32, n)
	wsaBufs := make([]windows.WSABuf, n)
	len := make([]uint32, n)
	flags := make([]uint32, n)
	overlap := make([]windows.Overlapped, n)

	// annoyingly and inconsistently, WaitForMultipleObjects needs an array of handles instead of a pointer to the first item
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
		overlap[i].HEvent = hevent

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

func (u *Conn) ListenOut(r EncReader, lhf LightHouseHandlerFunc, cache *firewall.ConntrackCacheTicker, q int) {
	plaintext := make([]byte, MTU)
	h := &header.H{}
	fwPacket := &firewall.Packet{}
	udpAddr := &Addr{}
	nb := make([]byte, 12, 12)
	msgs, buffers, names := u.PrepareRawMessages(u.batch)

	read := u.ReadMulti
	if u.batch == 1 {
		read = u.ReadSingle
	}

	for {
		n, err := read(msgs)
		if err != nil {
			u.l.WithError(err).Error("Failed to read packets")
			continue
		}

		for i := 0; i < n; i++ {
			ip, port, err := RawsockAddrToIPAndPort(&names[i])
			if err != nil {
				u.l.WithError(err).Error("Failed to read packets")
			}

			udpAddr.IP = ip
			udpAddr.Port = port

			r(udpAddr, plaintext[:0], buffers[i][:*msgs[i].Len], h, fwPacket, lhf, nb, q, cache.Get(u.l))
		}
	}
}

func RawsockAddrToIPAndPort(rsa *windows.RawSockaddrAny) (net.IP, uint16, error) {
	if rsa == nil {
		return nil, 0, syscall.EINVAL
	}

	switch rsa.Addr.Family {
	case syscall.AF_INET:
		var port uint16
		pp := (*syscall.RawSockaddrInet4)(unsafe.Pointer(rsa))
		ip := net.IP(pp.Addr[:])
		p := (*[2]byte)(unsafe.Pointer(&port))
		p[0] = byte(pp.Port >> 8)
		p[1] = byte(pp.Port)
		return ip, port, nil
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

func AddrToRawSockaddrAny(addr *Addr) (*windows.RawSockaddrAny, int32, error) {
	if addr == nil {
		return nil, 0, syscall.EINVAL
	}

	ip4 := addr.IP.To4()
	if ip4 != nil {
		if addr.Port < 0 || addr.Port > 0xFFFF {
			return nil, 0, syscall.EINVAL
		}

		var rsa windows.RawSockaddrInet4
		rsa.Family = windows.AF_INET
		p := (*[2]byte)(unsafe.Pointer(&rsa.Port))
		p[0] = byte(addr.Port >> 8)
		p[1] = byte(addr.Port)
		copy(rsa.Addr[:], ip4)

		return (*windows.RawSockaddrAny)(unsafe.Pointer(&rsa)), int32(unsafe.Sizeof(rsa)), nil

	} else {
		if addr.Port < 0 || addr.Port > 0xFFFF {
			return nil, 0, syscall.EINVAL
		}

		var rsa windows.RawSockaddrInet6
		rsa.Family = windows.AF_INET6
		p := (*[2]byte)(unsafe.Pointer(&rsa.Port))
		p[0] = byte(addr.Port >> 8)
		p[1] = byte(addr.Port)
		copy(rsa.Addr[:], addr.IP)

		return (*windows.RawSockaddrAny)(unsafe.Pointer(&rsa)), int32(unsafe.Sizeof(rsa)), nil
	}
}

func (u *Conn) ReadSingle(msgs []rawMessage) (int, error) {
	for {
		len, sa, err := windows.Recvfrom(u.sysFd, msgs[0].Hdr.Buf, 0)

		if err != nil {
			return 0, &net.OpError{Op: "Recvfrom", Err: err}
		}

		*msgs[0].Len = uint32(len)

		switch sa := sa.(type) {
		case *windows.SockaddrInet4:
			name := windows.RawSockaddrInet4{Family: windows.AF_INET}

			copy(name.Addr[:], sa.Addr[:])
			name.Port = uint16(sa.Port)

			p := (*[2]byte)(unsafe.Pointer(&name.Port))
			p[0] = byte(sa.Port >> 8)
			p[1] = byte(sa.Port)

			*msgs[0].Hdr.Name = *(*windows.RawSockaddrAny)(unsafe.Pointer(&name))
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

		return 1, nil
	}
}

func (u *Conn) ReadMulti(msgs []rawMessage) (int, error) {
	for {
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

		n := 0
		if err != nil {
			if err != windows.ERROR_IO_PENDING {
				return 0, &net.OpError{Op: "WSARecvFrom", Err: err}
			} else {
				rc, err := windows.WaitForMultipleObjects(
					u.hevents,
					false,
					windows.INFINITE)

				if rc == windows.WAIT_FAILED {
					return 0, &net.OpError{Op: "WaitForMultipleObjects", Err: err}
				}

				for i := 0; i < len(msgs); i++ {
					err := windows.GetOverlappedResult(msgs[i].Hdr.Overlap.HEvent, msgs[i].Hdr.Overlap, msgs[i].Len, false)
					if err != nil {
						return 0, &net.OpError{Op: "GetOverlappedResult", Err: err}
					} else if *msgs[i].Len == 0 {
						break
					}

					n++
				}
			}
		} else {
			for i := 0; i < len(msgs); i++ {
				if *msgs[i].Len > 0 {
					n++
				}
			}
		}

		return int(n), nil
	}
}

func (u *Conn) WriteTo(b []byte, addr *Addr) error {
	name, namelen, _ := AddrToRawSockaddrAny(addr)
	var wsaBuf = &windows.WSABuf{Buf: &b[0], Len: uint32(len(b))}
	var hevent, _ = WSACreateEvent()
	var overlapped = &windows.Overlapped{HEvent: hevent}
	var bytesSent uint32

	for {
		err := windows.WSASendTo(u.sysFd, wsaBuf, 1, &bytesSent, 0, name, namelen, overlapped, nil)
		if err == windows.ERROR_IO_PENDING {
			windows.WaitForSingleObject(hevent, 5000)
			windows.GetOverlappedResult(hevent, overlapped, &bytesSent, false)
			windows.CloseHandle(hevent)
		} else if err != nil {
			windows.CloseHandle(hevent)
			return &net.OpError{Op: "WSASendMsg", Err: err}
		}

		//TODO: handle incomplete writes

		return nil
	}
}

func (u *Conn) ReloadConfig(c *config.C) {
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

func NewUDPStatsEmitter(udpConns []*Conn) func() {
	// No UDP stats for non-linux
	return func() {}
}
