//go:build android

package nicfinder

import (
	"errors"
	"fmt"
	"net"
	"os"
	"slices"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

// Android denies bind() on netlink route sockets and RTM_GETLINK, so net.Interfaces fails with EACCES.
// Enumerate with an RTM_GETADDR dump on an unbound socket instead.

// localInterfaces returns every interface that has an address, with its addresses. It lists
// addresses over a netlink socket that is never bound and names each index with SIOCGIFNAME, the
// same operations Bionic's getifaddrs uses for app UIDs, which the sandbox permits.
func localInterfaces() ([]localInterface, error) {
	addrs, dumpErr := netlinkAddrList()
	if dumpErr != nil {
		if !errors.Is(dumpErr, netlink.ErrDumpInterrupted) {
			return nil, fmt.Errorf("failed to enumerate local interfaces: %w", dumpErr)
		}
		// The address table kept changing under the dump and netlink gave up retrying. What it
		// returned is still worth advertising.
		dumpErr = fmt.Errorf("local addresses may be incomplete: %w", dumpErr)
	}

	// Any socket will do for SIOCGIFNAME.
	sfd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, os.NewSyscallError("socket", err)
	}
	defer unix.Close(sfd)

	type iface struct {
		index int
		name  string
		addrs []net.Addr
	}
	var ifaces []*iface
	byIndex := make(map[int]*iface) // nil marks an index that vanished before we could name it
	for _, a := range addrs {
		i, seen := byIndex[a.LinkIndex]
		if !seen {
			name, err := interfaceNameByIndex(sfd, a.LinkIndex)
			if err != nil && !errors.Is(err, unix.ENODEV) {
				return nil, fmt.Errorf("failed to resolve name of interface %d: %w", a.LinkIndex, err)
			}
			if err == nil {
				i = &iface{index: a.LinkIndex, name: name}
				ifaces = append(ifaces, i)
			}
			byIndex[a.LinkIndex] = i
		}
		if i == nil {
			// The interface went away between the dump and the ioctl.
			continue
		}
		if a.IPNet != nil {
			i.addrs = append(i.addrs, a.IPNet)
		}
	}

	// The dump is grouped by address family. Sort by index to match net.Interfaces.
	slices.SortFunc(ifaces, func(a, b *iface) int { return a.index - b.index })
	out := make([]localInterface, 0, len(ifaces))
	for _, i := range ifaces {
		out = append(out, localInterface{Name: i.name, Addrs: netipAddrs(i.addrs)})
	}
	return out, dumpErr
}

// netlinkAddrList is netlink.AddrList over a socket that is never bound. The kernel autobinds it
// on the first send, which the sandbox permits.
func netlinkAddrList() ([]netlink.Addr, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return nil, os.NewSyscallError("socket", err)
	}
	s, err := nl.NewNetlinkSocketFromFd(fd)
	if err != nil {
		unix.Close(fd)
		return nil, err
	}

	h := netlink.NewHandleFromSockets(
		map[int]*nl.SocketHandle{unix.NETLINK_ROUTE: {Socket: s}},
		netlink.HandleOptions{RetryInterrupted: true},
	)
	defer h.Close()
	if err := h.SetSocketTimeout(netlink.GetSocketTimeout()); err != nil {
		return nil, err
	}

	return h.AddrList(nil, netlink.FAMILY_ALL)
}

// interfaceNameByIndex resolves an interface index with SIOCGIFNAME.
func interfaceNameByIndex(fd int, index int) (string, error) {
	var ifr unix.Ifreq
	ifr.SetUint32(uint32(index)) // ifr_ifindex is in the ifr_ifru union
	if err := unix.IoctlIfreq(fd, unix.SIOCGIFNAME, &ifr); err != nil {
		return "", err
	}
	return ifr.Name(), nil
}
