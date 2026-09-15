package nicfinder

import (
	"context"
	"log/slog"
	"net"
	"net/netip"

	"github.com/slackhq/nebula/logging"
)

// localInterface is what Find needs from a net.Interface, provided per platform by localInterfaces.
type localInterface struct {
	Name  string
	Addrs []netip.Addr
}

func netToNetIP(x net.Addr) (netip.Addr, bool) {
	var ip net.IP
	switch v := x.(type) {
	case *net.IPNet:
		ip = v.IP
	case *net.IPAddr:
		ip = v.IP
	}
	if addr, ok := netip.AddrFromSlice(ip); ok {
		return addr, true
	}
	return netip.Addr{}, false
}

// netipAddrs converts the addresses net.Interface.Addrs reports, dropping any that do not carry
// an IP. IPv4 addresses come back as netip 4-byte addresses rather than mapped IPv6.
func netipAddrs(addrs []net.Addr) []netip.Addr {
	out := make([]netip.Addr, 0, len(addrs))
	for _, rawAddr := range addrs {
		if addr, ok := netToNetIP(rawAddr); ok {
			out = append(out, addr.Unmap())
		}
	}
	return out
}

// Filter decides which interfaces, by name, and which of their addresses Find returns.
type Filter interface {
	AllowName(string) bool
	Allow(netip.Addr) bool
}

// Find returns the addresses of this host's network interfaces that allowList accepts, with
// loopback and link-local addresses left out. allowList must not be nil; it is called as given, so
// a nil pointer of a type whose methods accept a nil receiver is fine.
func Find(ctx context.Context, l *slog.Logger, allowList Filter) ([]netip.Addr, error) {
	return collectLocalAddrs(ctx, l, allowList, localInterfaces)
}

func collectLocalAddrs(
	ctx context.Context,
	l *slog.Logger,
	allowList Filter,
	interfaceFinder func() ([]localInterface, error),
) ([]netip.Addr, error) {
	// A finder may return the interfaces it could read alongside an error for the ones it could
	// not. Filter what it returned and pass the error on.
	ifaces, err := interfaceFinder()

	var finalAddrs []netip.Addr
	for _, i := range ifaces {
		allow := allowList.AllowName(i.Name)
		if l.Enabled(ctx, logging.LevelTrace) {
			l.Log(ctx, logging.LevelTrace, "localAllowList.AllowName", "interfaceName", i.Name, "allow", allow)
		}
		if !allow {
			continue
		}
		for _, addr := range i.Addrs {
			if !addr.IsLoopback() && !addr.IsLinkLocalUnicast() {
				isAllowed := allowList.Allow(addr)
				if l.Enabled(ctx, logging.LevelTrace) {
					l.Log(ctx, logging.LevelTrace, "localAllowList.Allow", "localAddr", addr, "allowed", isAllowed)
				}
				if !isAllowed {
					continue
				}

				finalAddrs = append(finalAddrs, addr)
			}
		}
	}
	return finalAddrs, err
}
