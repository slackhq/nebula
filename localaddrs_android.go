//go:build android

package nebula

import (
	"errors"
	"fmt"
	"net"
	"os"
	"slices"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// The Android app sandbox denies bind() on netlink route sockets and RTM_GETLINK, so
// net.Interfaces fails with EACCES. Enumerate with an RTM_GETADDR dump on an unbound socket instead.
func localInterfaces() ([]localInterface, error) {
	return netlinkInterfaceAddrs()
}

// netlinkInterfaceAddrs returns every interface that has an address, with its addresses. It dumps
// RTM_GETADDR on a netlink socket that is never bound and names each index with SIOCGIFNAME, the
// same operations Bionic's getifaddrs uses for app UIDs, which the sandbox permits.
func netlinkInterfaceAddrs() ([]localInterface, error) {
	dump, err := netlinkAddrDump()
	if err != nil {
		return nil, err
	}
	msgs, err := syscall.ParseNetlinkMessage(dump)
	if err != nil {
		return nil, err
	}

	// Any socket will do for SIOCGIFNAME.
	sfd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, os.NewSyscallError("socket", err)
	}
	defer unix.Close(sfd)

	type iface struct {
		index uint32
		name  string
		addrs []net.Addr
	}
	var ifaces []*iface
	byIndex := make(map[uint32]*iface) // nil marks an index that vanished before we could name it
	for _, m := range msgs {
		if m.Header.Type != unix.RTM_NEWADDR {
			continue
		}
		if len(m.Data) < unix.SizeofIfAddrmsg {
			return nil, fmt.Errorf("short RTM_NEWADDR message: %d bytes", len(m.Data))
		}
		ifam := (*unix.IfAddrmsg)(unsafe.Pointer(&m.Data[0]))

		i, seen := byIndex[ifam.Index]
		if !seen {
			name, err := interfaceNameByIndex(sfd, ifam.Index)
			if err != nil && !errors.Is(err, unix.ENODEV) {
				return nil, fmt.Errorf("failed to resolve name of interface %d: %w", ifam.Index, err)
			}
			if err == nil {
				i = &iface{index: ifam.Index, name: name}
				ifaces = append(ifaces, i)
			}
			byIndex[ifam.Index] = i
		}
		if i == nil {
			// The interface went away between the dump and the ioctl.
			continue
		}

		attrs, err := syscall.ParseNetlinkRouteAttr(&m)
		if err != nil {
			return nil, err
		}
		if a := newNetlinkAddr(ifam, attrs); a != nil {
			i.addrs = append(i.addrs, a)
		}
	}

	// The dump is grouped by address family. Sort by index to match net.Interfaces.
	slices.SortFunc(ifaces, func(a, b *iface) int { return int(a.index) - int(b.index) })
	out := make([]localInterface, 0, len(ifaces))
	for _, i := range ifaces {
		addrs := i.addrs
		out = append(out, localInterface{
			Name:  i.name,
			Addrs: func() ([]net.Addr, error) { return addrs, nil },
		})
	}
	return out, nil
}

// netlinkAddrDump is syscall.NetlinkRIB(RTM_GETADDR, AF_UNSPEC) without the bind() call. The
// kernel autobinds the socket on the first send, which the sandbox permits.
func netlinkAddrDump() ([]byte, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return nil, os.NewSyscallError("socket", err)
	}
	defer unix.Close(fd)

	const seq = 1
	req := make([]byte, unix.SizeofNlMsghdr+unix.SizeofRtGenmsg)
	h := (*unix.NlMsghdr)(unsafe.Pointer(&req[0]))
	h.Len = uint32(len(req))
	h.Type = unix.RTM_GETADDR
	h.Flags = unix.NLM_F_DUMP | unix.NLM_F_REQUEST
	h.Seq = seq
	req[unix.SizeofNlMsghdr] = unix.AF_UNSPEC // rtgenmsg.rtgen_family

	if err := unix.Sendto(fd, req, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, os.NewSyscallError("sendto", err)
	}

	// Read back the port id the kernel assigned on send so replies can be matched.
	lsa, err := unix.Getsockname(fd)
	if err != nil {
		return nil, os.NewSyscallError("getsockname", err)
	}
	nl, ok := lsa.(*unix.SockaddrNetlink)
	if !ok {
		return nil, errors.New("netlink socket returned a non-netlink local address")
	}

	var out []byte
	buf := make([]byte, os.Getpagesize())
	for {
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			return nil, os.NewSyscallError("recvfrom", err)
		}
		if n < unix.NLMSG_HDRLEN {
			return nil, fmt.Errorf("short netlink read: %d bytes", n)
		}
		msgs, err := syscall.ParseNetlinkMessage(buf[:n])
		if err != nil {
			return nil, err
		}
		for _, m := range msgs {
			if m.Header.Seq != seq || m.Header.Pid != nl.Pid {
				return nil, fmt.Errorf("netlink reply for another request: seq %d pid %d", m.Header.Seq, m.Header.Pid)
			}
			switch m.Header.Type {
			case unix.NLMSG_DONE:
				return out, nil
			case unix.NLMSG_ERROR:
				if len(m.Data) < 4 {
					return nil, errors.New("short NLMSG_ERROR")
				}
				errno := *(*int32)(unsafe.Pointer(&m.Data[0]))
				return nil, os.NewSyscallError("RTM_GETADDR", unix.Errno(-errno))
			}
		}
		out = append(out, buf[:n]...)
	}
}

// interfaceNameByIndex resolves an interface index with SIOCGIFNAME.
func interfaceNameByIndex(fd int, index uint32) (string, error) {
	var ifr unix.Ifreq
	ifr.SetUint32(index) // ifr_ifindex is in the ifr_ifru union
	if err := unix.IoctlIfreq(fd, unix.SIOCGIFNAME, &ifr); err != nil {
		return "", err
	}
	return ifr.Name(), nil
}

// newNetlinkAddr builds the address for one RTM_NEWADDR message. On a point-to-point link
// IFA_LOCAL is our side and IFA_ADDRESS the peer, so IFA_LOCAL wins when both are present.
func newNetlinkAddr(ifam *unix.IfAddrmsg, attrs []syscall.NetlinkRouteAttr) net.Addr {
	var pointToPoint bool
	for _, a := range attrs {
		if a.Attr.Type == unix.IFA_LOCAL {
			pointToPoint = true
			break
		}
	}

	for _, a := range attrs {
		if pointToPoint && a.Attr.Type == unix.IFA_ADDRESS {
			continue
		}
		switch ifam.Family {
		case unix.AF_INET:
			if a.Attr.Type != unix.IFA_LOCAL && a.Attr.Type != unix.IFA_ADDRESS {
				continue
			}
			if len(a.Value) < net.IPv4len {
				return nil
			}
			return &net.IPNet{
				IP:   net.IPv4(a.Value[0], a.Value[1], a.Value[2], a.Value[3]),
				Mask: net.CIDRMask(int(ifam.Prefixlen), 8*net.IPv4len),
			}
		case unix.AF_INET6:
			if a.Attr.Type != unix.IFA_LOCAL && a.Attr.Type != unix.IFA_ADDRESS {
				continue
			}
			if len(a.Value) < net.IPv6len {
				return nil
			}
			ifa := &net.IPNet{IP: make(net.IP, net.IPv6len), Mask: net.CIDRMask(int(ifam.Prefixlen), 8*net.IPv6len)}
			copy(ifa.IP, a.Value[:net.IPv6len])
			return ifa
		}
	}
	return nil
}
