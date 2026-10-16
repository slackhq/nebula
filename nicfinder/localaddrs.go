//go:build !android

package nicfinder

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
)

func localAddrs(ctx context.Context, l *slog.Logger, filter Filter) ([]netip.Addr, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to enumerate local interfaces: %w", err)
	}

	var out []netip.Addr
	var errs []error

	for _, i := range ifaces {
		if !allowName(ctx, l, filter, i.Name) {
			continue
		}
		addrs, err := i.Addrs()
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to get addresses for %s: %w", i.Name, err))
			continue
		}
		for _, rawAddr := range addrs {
			if addr, ok := allowedAddr(ctx, l, filter, rawAddr); ok {
				out = append(out, addr)
			}
		}
	}
	return out, errors.Join(errs...)
}
