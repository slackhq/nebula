//go:build android

package nicfinder

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"

	"github.com/DefinedNet/netlink"
	"github.com/DefinedNet/netlink/nl"
	"golang.org/x/sys/unix"
)

// Android denies bind() on netlink route sockets and RTM_GETLINK, so net.Interfaces fails with EACCES.
// Enumerate with an RTM_GETADDR dump on an unbound socket instead.

// localInterfaces returns every interface that has an address, with its addresses. It lists
// addresses over a netlink socket that is never bound and names each index with SIOCGIFNAME, the
// same operations Bionic's getifaddrs uses for app UIDs, which the sandbox permits.
func localAddrs(ctx context.Context, l *slog.Logger, filter Filter) ([]netip.Addr, error) {
	var errs []error
	addrs, err := netlinkAddrList()
	if err != nil {
		if !errors.Is(err, netlink.ErrDumpInterrupted) {
			return nil, fmt.Errorf("failed to enumerate local interfaces: %w", err)
		}
		// The address table kept changing under the dump and netlink gave up retrying. What it
		// returned is still worth advertising.
		errs = append(errs, fmt.Errorf("local addresses may be incomplete: %w", err))
	}

	// Any socket will do for SIOCGIFNAME.
	sfd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, os.NewSyscallError("socket", err)
	}
	defer unix.Close(sfd)

	var out []netip.Addr
	nameAllowed := make(map[int]bool) // by interface index, once named
	for _, a := range addrs {
		allow, named := nameAllowed[a.LinkIndex]
		if (named && !allow) || a.IPNet == nil {
			continue
		}
		addr, ok := allowedAddr(ctx, l, filter, a.IPNet)
		if !ok {
			continue
		}
		if !named {
			name, err := interfaceNameByIndex(sfd, a.LinkIndex)
			// ENODEV means the interface went away after the dump. Any other failure is reported
			// and the interface skipped, so the rest are still returned.
			if err != nil && !errors.Is(err, unix.ENODEV) {
				errs = append(errs, fmt.Errorf("failed to resolve name of interface %d: %w", a.LinkIndex, err))
			}
			allow = err == nil && allowName(ctx, l, filter, name)
			nameAllowed[a.LinkIndex] = allow
		}
		if allow {
			out = append(out, addr)
		}
	}
	return out, errors.Join(errs...)
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
