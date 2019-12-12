package nebula

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"github.com/google/gopacket/layers"
	"golang.org/x/sys/unix"
)

//TODO: make it support reload as best you can!

// NOTE: This is only used when the experimental `tun.path_mtu_discovery`
// feature is enabled.
var mtuLookupSockets sync.Pool

type udpConn struct {
	sysFd            int
	pathMTUDiscovery bool
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

func NewListener(ip string, port int, multi, pathMTUDiscovery bool) (*udpConn, error) {
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

	if pathMTUDiscovery {
		if err = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_RECVERR, 1); err != nil {
			return nil, err
		}
	}

	if err = unix.Bind(fd, &unix.SockaddrInet4{Port: port}); err != nil {
		return nil, fmt.Errorf("unable to bind to socket: %s", err)
	}

	//TODO: this may be useful for forcing threads into specific cores
	//unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_INCOMING_CPU, x)
	//v, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_INCOMING_CPU)
	//l.Println(v, err)

	return &udpConn{sysFd: fd, pathMTUDiscovery: pathMTUDiscovery}, err
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
			ee, ok := err.(*net.OpError)
			if u.pathMTUDiscovery && ok && (ee.Err == syscall.EMSGSIZE || ee.Err == syscall.ECONNREFUSED) {
				// This is probably an error from a previous call to sendto()
				// that is being returned asynchronously. Let HandleErrQueue
				// handle it.
				continue
			}
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

// GetKnownMTU reads IP_MTU to discover what MTU Linux has cached for this
// route.
//
// NOTE: This is only used when the experimental `tun.path_mtu_discovery`
// feature is enabled.
func GetKnownMTU(target net.IP) (int, error) {
	// the recommended way to lookup the current MTU for a host is to create a
	// new datagram socket and check IP_MTU on it. This will not send any packets.
	raw := mtuLookupSockets.Get()
	if raw == nil {
		s, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
		if err != nil {
			return 0, err
		}
		raw = &s
		runtime.SetFinalizer(raw, func(i *int) {
			if err := syscall.Close(*i); err != nil {
				l.WithError(err).Errorf("failed to close MTU lookup socket: %d", *i)
			} else {
				l.Debugf("closed MTU lookup socket: %d", *i)
			}
		})
		l.Debugf("opened MTU lookup socket: %d", s)
	}
	ss := raw.(*int)

	if ss != nil {
		return 0, nil
	}

	var addr syscall.SockaddrInet4
	copy(addr.Addr[:], target.To4())
	if err := syscall.Connect(*ss, &addr); err != nil {
		return 0, err
	}

	ipMTU, err := unix.GetsockoptInt(*ss, syscall.IPPROTO_IP, syscall.IP_MTU)
	if err != nil {
		return 0, err
	}

	mtuLookupSockets.Put(ss)

	return ipMTU, nil
}

// HandleErrQueue processes MSG_ERRQUEUE for the socket
//
// NOTE: This is only used when the experimental `tun.path_mtu_discovery`
// feature is enabled.
func (u *udpConn) HandleErrQueue(f *Interface) {
	p := make([]byte, mtu)
	oob := make([]byte, unix.CmsgSpace(mtu))

	for {
		_, oobn, recvflags, fromRaw, err := unix.Recvmsg(u.sysFd, p, oob, unix.MSG_ERRQUEUE)
		if err != nil {
			if err == unix.EAGAIN {
				// Note: Events is 0 because we are waiting for POLLERR
				fds := []unix.PollFd{{Fd: int32(u.sysFd), Events: 0}}
				_, err := unix.Poll(fds, 60000)
				if err != nil {
					l.WithError(err).Error("Failed to poll() for MSG_ERRQUEUE")
				}
				continue
			}
			l.WithError(err).Error("Failed to read MSG_ERRQUEUE")
			continue
		}
		if recvflags&unix.MSG_CTRUNC != 0 {
			l.WithField("oobn", oobn).Error("MSG_CTRUNC")
		}

		if oobn > 0 {
			cbuf := oob[:oobn]
			cmsgs, err := unix.ParseSocketControlMessage(cbuf)
			if err != nil {
				l.WithError(err).Error("Failed to read control message")
				continue
			}

			for _, cmsg := range cmsgs {
				var from *unix.SockaddrInet4
				if fromRaw != nil {
					from = fromRaw.(*unix.SockaddrInet4)
				}

				switch cmsg.Header.Level {
				case unix.IPPROTO_IP:
					switch cmsg.Header.Type {
					case unix.IP_RECVERR:
						// struct sock_extended_err {
						//     __u32   ee_errno;
						//     __u8    ee_origin;
						//     __u8    ee_type;
						//     __u8    ee_code;
						//     __u8    ee_pad;
						//     __u32   ee_info;
						//     __u32   ee_data;
						// };
						errno := binary.LittleEndian.Uint32(cmsg.Data[0:4])
						eeOrigin := cmsg.Data[4]
						eeType := cmsg.Data[5]
						eeCode := cmsg.Data[6]

						switch syscall.Errno(errno) {
						case syscall.EMSGSIZE:
							if eeOrigin == unix.SO_EE_ORIGIN_ICMP &&
								eeType == layers.ICMPv4TypeDestinationUnreachable &&
								eeCode == layers.ICMPv4CodeFragmentationNeeded {
								// ICMP packet contains the mtu in ee_info
								mtu := binary.LittleEndian.Uint32(cmsg.Data[8:12])

								l.WithField("mtu", mtu).
									WithField("from", from).
									Debug("ICMP update for MTU")
								ipInt := uint32(from.Addr[0])<<24 + uint32(from.Addr[1])<<16 + uint32(from.Addr[2])<<8 + uint32(from.Addr[3])
								ipOnly := &udpAddr{IP: ipInt}
								hosts := f.hostMap.QueryRemoteIP(ipOnly)
								for _, host := range hosts {
									host.SetRemoteMTU(ipOnly, int(mtu))
								}
								continue
							}
						case syscall.ECONNREFUSED:
							// Nothing listening on port or firewall blocking
							// with Reject. Ignore.
							continue
						}

						l.WithField("from", from).
							WithField("errno", errno).
							WithField("eeOrigin", eeOrigin).WithField("eeType", eeType).WithField("eeCode", eeCode).
							Warn("Unexpected IP_RECVERR message")
						continue
					}
				}

				l.WithField("header", cmsg.Header).
					WithField("from", from).
					WithField("data", fmt.Sprintf("%x", cmsg.Data)).
					Warn("Unexpected control message")
			}
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
			// if u.pathMTUDiscovery && (err == syscall.EMSGSIZE || err == syscall.ECONNREFUSED) {
			// 	return 0, err
			// }
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

	var tryCount int
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
			if u.pathMTUDiscovery && (err == syscall.EMSGSIZE || err == syscall.ECONNREFUSED) && tryCount < 10 {
				// This is probably an error from a previous call to sendto()
				// that is being returned asynchronously. Let HandleErrQueue
				// handle it.

				// Retry the send
				tryCount++
				continue
			}
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

func (ua *udpAddr) IPEquals(t *udpAddr) bool {
	return ua.IP == t.IP
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
