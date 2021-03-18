package udp

import (
	"fmt"
	"net"
	"os"
	"syscall"
	"unsafe"

	"github.com/sirupsen/logrus"
	c "github.com/slackhq/nebula/config"
	"golang.org/x/sys/unix"
)

type darwinConn struct {
	fd  int
	l   *logrus.Logger
	mtu int
}

type rawMessage struct {
	Len uint32
}

func NewConn(ip string, port int, multi bool, mtu int, l *logrus.Logger) (*darwinConn, error) {
	syscall.ForkLock.RLock()
	fd, err := syscall.Socket(unix.AF_INET6, unix.SOCK_DGRAM, unix.IPPROTO_UDP)
	if err == nil {
		syscall.CloseOnExec(fd)
	}
	syscall.ForkLock.RUnlock()

	if err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("unable to open socket: %s", err)
	}

	var lip [16]byte
	copy(lip[:], net.ParseIP(ip))

	if multi {
		l.Error("Darwin does not support multiple udp queues at this time")
	}

	//TODO: this should be in another stage?
	if err = unix.Bind(fd, &unix.SockaddrInet6{Addr: lip, Port: port}); err != nil {
		return nil, fmt.Errorf("unable to bind to socket: %s", err)
	}

	return &darwinConn{fd: fd, mtu: mtu, l: l}, nil
}

func (dc *darwinConn) WriteTo(b []byte, addr *Addr) error {
	var rsa unix.RawSockaddrInet6
	rsa.Family = unix.AF_INET6
	p := (*[2]byte)(unsafe.Pointer(&rsa.Port))
	p[0] = byte(addr.Port >> 8)
	p[1] = byte(addr.Port)
	copy(rsa.Addr[:], addr.IP)

	var msg unix.Msghdr
	msg.Name = (*byte)(unsafe.Pointer(&rsa))
	msg.Namelen = unix.SizeofSockaddrInet6
	var iov unix.Iovec
	if len(p) > 0 {
		iov.Base = (*byte)(unsafe.Pointer(&b[0]))
		iov.SetLen(len(b))
	}
	msg.Iov = &iov
	msg.Iovlen = 1

	for {
		//dc.l.Error("NATE WRITE START", msg)
		_, _, err := unix.Syscall(
			unix.SYS_SENDMSG,
			uintptr(dc.fd),
			uintptr(unsafe.Pointer(&msg)),
			0,
		)
		if err != 0 {
			dc.l.Error("NATE WRITE ERR", err)
			return os.NewSyscallError("sendmsg", err)
		}

		return nil
	}
}

func (dc *darwinConn) LocalAddr() (*Addr, error) {
	sa, err := unix.Getsockname(dc.fd)
	if err != nil {
		return nil, err
	}

	addr := &Addr{}
	switch sa := sa.(type) {
	case *unix.SockaddrInet4:
		addr.IP = sa.Addr[0:]
		addr.Port = uint16(sa.Port)
	case *unix.SockaddrInet6:
		addr.IP = sa.Addr[0:]
		addr.Port = uint16(sa.Port)
	}

	return addr, nil
}

func (dc *darwinConn) ReloadConfig(c *c.Config) {
	b := c.GetInt("listen.read_buffer", 0)
	if b > 0 {
		err := dc.setRecvBuffer(b)
		if err != nil {
			dc.l.WithError(err).Error("Failed to set listen.read_buffer")
		}
	}

	s, err := dc.getRecvBuffer()
	if err == nil {
		dc.l.WithField("size", s).Info("listen.read_buffer")
	} else {
		dc.l.WithError(err).Warn("Failed to get listen.read_buffer")
	}

	b = c.GetInt("listen.write_buffer", 0)
	if b > 0 {
		err := dc.setSendBuffer(b)
		if err != nil {
			dc.l.WithError(err).Error("Failed to set listen.write_buffer")
		}
	}

	s, err = dc.getSendBuffer()
	if err == nil {
		dc.l.WithField("size", s).Info("listen.write_buffer")
	} else {
		dc.l.WithError(err).Warn("Failed to get listen.write_buffer")
	}
}

func (dc *darwinConn) ListenOut(reader EncReader, lhh LightHouseHandlerFunc, cache *ConntrackCacheTicker, q int) error {
	plaintext := make([]byte, dc.mtu)
	buffer := make([]byte, dc.mtu)
	header := &Header{}
	fwPacket := &FirewallPacket{}
	udpAddr := &Addr{IP: make([]byte, 16)}
	//TODO we don't need this if we just copy below
	udpAddr.IP = udpAddr.IP.To16()
	nb := make([]byte, 12, 12)

	var msg syscall.Msghdr
	var rsa syscall.RawSockaddrAny
	msg.Name = (*byte)(unsafe.Pointer(&rsa))
	msg.Namelen = uint32(syscall.SizeofSockaddrAny)
	var iov syscall.Iovec
	iov.Base = &buffer[0]
	iov.SetLen(len(buffer))
	msg.Iov = &iov
	msg.Iovlen = 1

	for {
		n, err := dc.readFrom(&msg)
		if err != nil {
			dc.l.WithError(err).Error("Failed to read packets")
			continue
		}

		pp := (*syscall.RawSockaddrInet6)(unsafe.Pointer(&rsa))
		p := (*[2]byte)(unsafe.Pointer(&pp.Port))
		udpAddr.Port = uint16(p[0])<<8 + uint16(p[1])
		for i := 0; i < len(udpAddr.IP); i++ {
			udpAddr.IP[i] = pp.Addr[i]
		}

		reader(udpAddr, plaintext[:0], buffer[:n], header, fwPacket, lhh, nb, q, cache.Get())
	}
}

func (dc *darwinConn) readFrom(msg *syscall.Msghdr) (int, error) {
	for {
		n, _, err := unix.Syscall6(
			unix.SYS_RECVMSG,
			uintptr(dc.fd),
			uintptr(unsafe.Pointer(msg)),
			0,
			0,
			0,
			0,
		)

		if err != 0 {
			return 0, &net.OpError{Op: "recvmsg", Err: err}
		}
		return int(n), nil
	}
}

//TODO: It seems like we can use SYS_RECVMSG_X to do the same thing that recvmmsg does on linux
//func (dc *darwinConn) readMulti(msg *syscall.Msghdr) (int, error) {
//	unix.SYS_RECVMSG_X
//}

func (dc *darwinConn) Rebind() error {
	return syscall.SetsockoptInt(dc.fd, unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF, 0)
}

func (dc *darwinConn) EmitStats() error {
	//TODO
	return nil
}

func (dc *darwinConn) setRecvBuffer(n int) error {
	return unix.SetsockoptInt(dc.fd, unix.SOL_SOCKET, unix.SO_RCVBUF, n)
}

func (dc *darwinConn) setSendBuffer(n int) error {
	return unix.SetsockoptInt(dc.fd, unix.SOL_SOCKET, unix.SO_SNDBUF, n)
}

func (dc *darwinConn) getRecvBuffer() (int, error) {
	return unix.GetsockoptInt(dc.fd, unix.SOL_SOCKET, unix.SO_RCVBUF)
}

func (dc *darwinConn) getSendBuffer() (int, error) {
	return unix.GetsockoptInt(dc.fd, unix.SOL_SOCKET, unix.SO_SNDBUF)
}
