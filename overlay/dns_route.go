package overlay

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/config"
)

// DnsRouteManager manages DNS-based routes that need periodic resolution
type DnsRouteManager struct {
	ctx            context.CancelFunc
	l              *logrus.Logger
	dnsRoutes      []DnsRoute
	resolvedRoutes atomic.Pointer[[]Route]
	cadence        time.Duration
	lookupTimeout  time.Duration
	mutex          sync.RWMutex
}

// NewDnsRouteManager creates a new DNS route manager
func NewDnsRouteManager(ctx context.Context, l *logrus.Logger, c *config.C, dnsRoutes []DnsRoute) (*DnsRouteManager, error) {
	if len(dnsRoutes) == 0 {
		return nil, nil
	}

	cadence := c.GetDuration("tun.unsafe_dns_routes_cadence", 30*time.Second)
	lookupTimeout := c.GetDuration("tun.unsafe_dns_routes_lookup_timeout", 5*time.Second)

	newCtx, cancel := context.WithCancel(ctx)
	drm := &DnsRouteManager{
		ctx:           cancel,
		l:             l,
		dnsRoutes:     dnsRoutes,
		cadence:       cadence,
		lookupTimeout: lookupTimeout,
	}

	// Initialize with empty routes
	emptyRoutes := []Route{}
	drm.resolvedRoutes.Store(&emptyRoutes)

	// Perform initial DNS resolution
	drm.resolveAll()

	// Start periodic resolution in background
	go drm.periodicResolve(newCtx)

	return drm, nil
}

// resolveAll resolves all DNS routes
func (drm *DnsRouteManager) resolveAll() {
	var allRoutes []Route

	for _, dnsRoute := range drm.dnsRoutes {
		routes := drm.resolveDnsRoute(dnsRoute)
		allRoutes = append(allRoutes, routes...)
	}

	drm.resolvedRoutes.Store(&allRoutes)
}

// resolveDnsRoute resolves a single DNS route
func (drm *DnsRouteManager) resolveDnsRoute(dnsRoute DnsRoute) []Route {
	ctx, cancel := context.WithTimeout(context.Background(), drm.lookupTimeout)
	defer cancel()

	// Lookup IP addresses for the hostname
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", dnsRoute.Host)
	if err != nil {
		drm.l.WithError(err).WithField("host", dnsRoute.Host).Warn("Failed to resolve DNS route")
		return nil
	}

	if len(addrs) == 0 {
		drm.l.WithField("host", dnsRoute.Host).Warn("No IP addresses resolved for DNS route")
		return nil
	}

	// Convert resolved IPs to routes
	var routes []Route
	for _, addr := range addrs {
		// Create a /32 (IPv4) or /128 (IPv6) route for each resolved IP
		bits := 32
		if addr.Is6() {
			bits = 128
		}
		cidr := netip.PrefixFrom(addr.Unmap(), bits)

		route := Route{
			Cidr:    cidr,
			Via:     dnsRoute.Via,
			MTU:     dnsRoute.MTU,
			Metric:  dnsRoute.Metric,
			Install: true,
		}
		routes = append(routes, route)
	}

	drm.l.WithField("host", dnsRoute.Host).WithField("num_ips", len(routes)).Debug("DNS route resolved")
	return routes
}

// periodicResolve periodically resolves all DNS routes
func (drm *DnsRouteManager) periodicResolve(ctx context.Context) {
	ticker := time.NewTicker(drm.cadence)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			oldRoutes := drm.resolvedRoutes.Load()
			drm.resolveAll()
			newRoutes := drm.resolvedRoutes.Load()

			// Check if routes have actually changed
			if !routesEqual(*oldRoutes, *newRoutes) {
				drm.l.Info("DNS routes changed, updating route table")
			}
		}
	}
}

// GetResolvedRoutes returns all currently resolved routes
func (drm *DnsRouteManager) GetResolvedRoutes() []Route {
	routes := drm.resolvedRoutes.Load()
	if routes == nil {
		return []Route{}
	}
	return *routes
}

// Close stops the DNS route manager
func (drm *DnsRouteManager) Close() {
	if drm != nil && drm.ctx != nil {
		drm.ctx()
	}
}

// routesEqual checks if two route slices are equal
func routesEqual(a, b []Route) bool {
	if len(a) != len(b) {
		return false
	}

	// Create a map of routes for comparison
	aMap := make(map[netip.Prefix]bool)
	for _, r := range a {
		aMap[r.Cidr] = true
	}

	for _, r := range b {
		if !aMap[r.Cidr] {
			return false
		}
	}

	return true
}

