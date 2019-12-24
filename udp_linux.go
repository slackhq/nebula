// +build !android

package nebula

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

//TODO: make it support reload as best you can!

type udpConn struct {
	sysFd int
}

type udpAddr struct {
	IP   uint32
	Port uint16
}

func NewUDPAddr(ip uint32, port uint16) *udpAddr {
	return &udpAddr{IP: ip, Port: port}
}

func NewUDPAddrFromString(s string) *udpAddr {
	p := strings.Split(s, ":")
	if len(p) < 2 {
		return nil
	}

	port, _ := strconv.Atoi(p[1])
	return &udpAddr{
		IP:   ip2int(net.ParseIP(p[0])),
		Port: uint16(port),
	}
}

type rawSockaddr struct {
	Family uint16
	Data   [14]uint8
}

type rawSockaddrAny struct {
	Addr rawSockaddr
	Pad  [96]int8
}

var x int

func NewListener(ip string, port int, multi bool) (*udpConn, error) {
	syscall.ForkLock.RLock()
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_UDP)
	if err == nil {
		unix.CloseOnExec(fd)
	}
	syscall.ForkLock.RUnlock()

	if err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("unable to open socket: %s", err)
	}

	var lip [4]byte
	copy(lip[:], net.ParseIP(ip).To4())

	if err = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEPORT, 1); err != nil {
		return nil, fmt.Errorf("unable to set SO_REUSEPORT: %s", err)
	}

	if err = unix.Bind(fd, &unix.SockaddrInet4{Addr: lip, Port: port}); err != nil {
		return nil, fmt.Errorf("unable to bind to socket: %s", err)
	}

	//TODO: this may be useful for forcing threads into specific cores
	//unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_INCOMING_CPU, x)
	//v, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_INCOMING_CPU)
	//l.Println(v, err)

	return &udpConn{sysFd: fd}, err
}

func (u *udpConn) SetRecvBuffer(n int) error {
	return unix.SetsockoptInt(u.sysFd, unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, n)
}

func (u *udpConn) SetSendBuffer(n int) error {
	return unix.SetsockoptInt(u.sysFd, unix.SOL_SOCKET, unix.SO_SNDBUFFORCE, n)
}

func (u *udpConn) GetRecvBuffer() (int, error) {
	return unix.GetsockoptInt(int(u.sysFd), unix.SOL_SOCKET, unix.SO_RCVBUF)
}

func (u *udpConn) GetSendBuffer() (int, error) {
	return unix.GetsockoptInt(int(u.sysFd), unix.SOL_SOCKET, unix.SO_SNDBUF)
}

func (u *udpConn) LocalAddr() (*udpAddr, error) {
	var rsa rawSockaddrAny
	var rLen = unix.SizeofSockaddrAny

	_, _, err := unix.Syscall(
		unix.SYS_GETSOCKNAME,
		uintptr(u.sysFd),
		uintptr(unsafe.Pointer(&rsa)),
		uintptr(unsafe.Pointer(&rLen)),
	)

	if err != 0 {
		return nil, err
	}

	addr := &udpAddr{}
	if rsa.Addr.Family == unix.AF_INET {
		addr.Port = uint16(rsa.Addr.Data[0])<<8 + uint16(rsa.Addr.Data[1])
		addr.IP = uint32(rsa.Addr.Data[2])<<24 + uint32(rsa.Addr.Data[3])<<16 + uint32(rsa.Addr.Data[4])<<8 + uint32(rsa.Addr.Data[5])
	} else {
		addr.Port = 0
		addr.IP = 0
	}
	return addr, nil
}

func (u *udpConn) ListenOut(f *Interface) {
	plaintext := make([]byte, mtu)
	header := &Header{}
	fwPacket := &FirewallPacket{}
	udpAddr := &udpAddr{}
	nb := make([]byte, 12, 12)

	//TODO: should we track this?
	//metric := metrics.GetOrRegisterHistogram("test.batch_read", nil, metrics.NewExpDecaySample(1028, 0.015))
	msgs, buffers, names := u.PrepareRawMessages(f.udpBatchSize)

	for {
		n, err := u.ReadMulti(msgs)
		if err != nil {
			l.WithError(err).Error("Failed to read packets")
			continue
		}

		//metric.Update(int64(n))
		for i := 0; i < n; i++ {
			udpAddr.IP = binary.BigEndian.Uint32(names[i][4:8])
			udpAddr.Port = binary.BigEndian.Uint16(names[i][2:4])

			f.readOutsidePackets(udpAddr, plaintext[:0], buffers[i][:msgs[i].Len], header, fwPacket, nb)
		}
	}
}

func (u *udpConn) Read(addr *udpAddr, b []byte) ([]byte, error) {
	var rsa rawSockaddrAny
	var rLen = unix.SizeofSockaddrAny

	for {
		n, _, err := unix.Syscall6(
			unix.SYS_RECVFROM,
			uintptr(u.sysFd),
			uintptr(unsafe.Pointer(&b[0])),
			uintptr(len(b)),
			uintptr(0),
			uintptr(unsafe.Pointer(&rsa)),
			uintptr(unsafe.Pointer(&rLen)),
		)

		if err != 0 {
			return nil, &net.OpError{Op: "read", Err: err}
		}

		if rsa.Addr.Family == unix.AF_INET {
			addr.Port = uint16(rsa.Addr.Data[0])<<8 + uint16(rsa.Addr.Data[1])
			addr.IP = uint32(rsa.Addr.Data[2])<<24 + uint32(rsa.Addr.Data[3])<<16 + uint32(rsa.Addr.Data[4])<<8 + uint32(rsa.Addr.Data[5])
		} else {
			addr.Port = 0
			addr.IP = 0
		}

		return b[:n], nil
	}
}

func (u *udpConn) ReadMulti(msgs []rawMessage) (int, error) {
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

func (u *udpConn) WriteTo(b []byte, addr *udpAddr) error {
	var rsa unix.RawSockaddrInet4

	//TODO: sometimes addr is nil!
	rsa.Family = unix.AF_INET
	p := (*[2]byte)(unsafe.Pointer(&rsa.Port))
	p[0] = byte(addr.Port >> 8)
	p[1] = byte(addr.Port)

	rsa.Addr[0] = byte(addr.IP & 0xff000000 >> 24)
	rsa.Addr[1] = byte(addr.IP & 0x00ff0000 >> 16)
	rsa.Addr[2] = byte(addr.IP & 0x0000ff00 >> 8)
	rsa.Addr[3] = byte(addr.IP & 0x000000ff)

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

		//TODO: handle incomplete writes

		return nil
	}
}

func (u *udpConn) reloadConfig(c *Config) {
	b := c.GetInt("listen.read_buffer", 0)
	if b > 0 {
		err := u.SetRecvBuffer(b)
		if err == nil {
			s, err := u.GetRecvBuffer()
			if err == nil {
				l.WithField("size", s).Info("listen.read_buffer was set")
			} else {
				l.WithError(err).Warn("Failed to get listen.read_buffer")
			}
		} else {
			l.WithError(err).Error("Failed to set listen.read_buffer")
		}
	}

	b = c.GetInt("listen.write_buffer", 0)
	if b > 0 {
		err := u.SetSendBuffer(b)
		if err == nil {
			s, err := u.GetSendBuffer()
			if err == nil {
				l.WithField("size", s).Info("listen.write_buffer was set")
			} else {
				l.WithError(err).Warn("Failed to get listen.write_buffer")
			}
		} else {
			l.WithError(err).Error("Failed to set listen.write_buffer")
		}
	}
}

func (ua *udpAddr) Equals(t *udpAddr) bool {
	if t == nil || ua == nil {
		return t == nil && ua == nil
	}
	return ua.IP == t.IP && ua.Port == t.Port
}

func (ua *udpAddr) Copy() *udpAddr {
	return &udpAddr{
		Port: ua.Port,
		IP:   ua.IP,
	}
}

func (ua *udpAddr) String() string {
	return fmt.Sprintf("%s:%v", int2ip(ua.IP), ua.Port)
}

func (ua *udpAddr) MarshalJSON() ([]byte, error) {
	return json.Marshal(m{"ip": int2ip(ua.IP), "port": ua.Port})
}

func udp2ip(addr *udpAddr) net.IP {
	return int2ip(addr.IP)
}

func udp2ipInt(addr *udpAddr) uint32 {
	return addr.IP
}

func hostDidRoam(addr *udpAddr, newaddr *udpAddr) bool {
	return !addr.Equals(newaddr)
}
