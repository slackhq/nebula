package nicfinder

import (
	"context"
	"log/slog"
	"net"
	"net/netip"

	"github.com/slackhq/nebula/logging"
)

// Filter decides which interfaces, by name, and which of their addresses Find returns.
type Filter interface {
	AllowName(string) bool
	Allow(netip.Addr) bool
}

// Find returns the addresses of this host's network interfaces that allowList accepts, with
// loopback and link-local addresses left out. When only some interfaces could be read it returns
// their addresses alongside an error for the rest. allowList must not be nil; it is called as
// given, so a nil pointer of a type whose methods accept a nil receiver is fine.
func Find(ctx context.Context, l *slog.Logger, allowList Filter) ([]netip.Addr, error) {
	return localAddrs(ctx, l, allowList)
}

// allowName asks filter about an interface name and traces the answer.
func allowName(ctx context.Context, l *slog.Logger, filter Filter, name string) bool {
	allow := filter.AllowName(name)
	if l.Enabled(ctx, logging.LevelTrace) {
		l.Log(ctx, logging.LevelTrace, "localAllowList.AllowName", "interfaceName", name, "allow", allow)
	}
	return allow
}

// allowedAddr converts one address a platform reports and says whether to advertise it: it must
// be a *net.IPNet or *net.IPAddr carrying an IP, not be loopback or link-local, and be accepted by
// filter, whose answer is traced. IPv4 comes back unmapped.
func allowedAddr(ctx context.Context, l *slog.Logger, filter Filter, rawAddr net.Addr) (netip.Addr, bool) {
	var ip net.IP
	switch v := rawAddr.(type) {
	case *net.IPNet:
		ip = v.IP
	case *net.IPAddr:
		ip = v.IP
	}
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Addr{}, false
	}
	addr = addr.Unmap()
	if addr.IsLoopback() || addr.IsLinkLocalUnicast() {
		return netip.Addr{}, false
	}
	isAllowed := filter.Allow(addr)
	if l.Enabled(ctx, logging.LevelTrace) {
		l.Log(ctx, logging.LevelTrace, "localAllowList.Allow", "localAddr", addr, "allowed", isAllowed)
	}
	return addr, isAllowed
}
