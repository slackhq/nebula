package nebula

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"time"

	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/pq/rphttp"
	"github.com/slackhq/nebula/pq/rpsidecar"
)

// sidecarBindAttempts / sidecarBindBackoff govern the retry loop that
// probes the discovery TCP listen address before starting the
// file-backed Discovery server. Mirrors the embedded path so the
// tun-bringup race on Ubuntu 24.04 / systemd-networkd is bounded
// the same way for sidecar deployments.
const (
	sidecarBindAttempts = 5
	sidecarBindBackoff  = 200 * time.Millisecond
)

// startSidecarDistributor constructs the file-backed Discovery server
// (when pq.sidecar.pubkey_serve_file is set) and the PubkeyDistributor
// (when pq.sidecar.pubkey_distribute_dir is set), and returns a
// *sidecarBundle that owns both pieces' lifecycle. The caller stores
// the bundle in f.pqProvider; notifyPQProvider type-asserts the
// field back to *sidecarBundle to dispatch peer-observed events to
// the Distributor.
//
// Either of the two configs may be empty: serve-only and
// distribute-only are valid operator postures. If both are empty,
// startSidecarDistributor is never called (the caller short-circuits
// on the config check).
//
// Defers binding until f.activate() has brought up the overlay so the
// listener can bind to the assigned VPN address without racing
// EADDRNOTAVAIL on platforms with slow tun-address assignment.
func startSidecarDistributor(ctx context.Context, l *slog.Logger, c *config.C, f *Interface) (*sidecarBundle, error) {
	serveFile := c.GetString("pq.sidecar.pubkey_serve_file", "")
	distDir := c.GetString("pq.sidecar.pubkey_distribute_dir", "")
	listenHost := c.GetString("pq.sidecar.listen_host", "")
	// pq.discovery_port is the SAME key the lighthouse reads at startup
	// for gossip (see lighthouse.go's pq.discovery_port resolution).
	// Operators set it once; we use it here for both the local serve
	// listener bind and the fallback fetch port for the Distributor.
	discoveryPort := c.GetInt("pq.discovery_port", 51820)
	fetchRetries := c.GetInt("pq.sidecar.fetch_retries", 3)
	fetchTimeoutMS := c.GetInt("pq.sidecar.fetch_timeout_ms", 10000)

	if serveFile == "" && distDir == "" {
		return nil, errors.New("rosenpass sidecar: at least one of pq.sidecar.pubkey_serve_file or pq.sidecar.pubkey_distribute_dir must be set")
	}

	var bundle sidecarBundle

	// File-backed Discovery server: reads pubkey from disk at startup
	// and serves it on the configured port. Operator restarts nebula
	// when the rosenpass key file rotates (rare event).
	if serveFile != "" {
		pubkey, err := os.ReadFile(serveFile)
		if err != nil {
			return nil, fmt.Errorf("rosenpass sidecar: read serve file %q: %w", serveFile, err)
		}
		if len(pubkey) == 0 {
			return nil, fmt.Errorf("rosenpass sidecar: serve file %q is empty", serveFile)
		}
		bindIP, err := sidecarBindAddr(listenHost, f)
		if err != nil {
			return nil, err
		}
		listenAddr := &net.TCPAddr{IP: bindIP, Port: discoveryPort}
		var disc *rphttp.Discovery
		var bindErr error
		for i := 0; i < sidecarBindAttempts; i++ {
			disc, bindErr = rphttp.NewDiscovery(listenAddr, pubkey)
			if bindErr == nil {
				break
			}
			l.Warn("rosenpass sidecar discovery bind failed, retrying",
				"attempt", i+1, "of", sidecarBindAttempts, "err", bindErr)
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(sidecarBindBackoff):
			}
		}
		if bindErr != nil {
			return nil, fmt.Errorf("rosenpass sidecar discovery listen: %w", bindErr)
		}
		bundle.disc = disc
		l.Info("rosenpass sidecar discovery serving",
			"addr", disc.LocalAddr().String(), "pubkey_bytes", len(pubkey))
	}

	// Distributor: subscribes to PeerObserved (via notifyPQProvider)
	// and writes peer pubkeys to PubkeyDir. Always created when
	// distDir is non-empty, regardless of whether serve is also wired.
	if distDir != "" {
		dist, err := rpsidecar.New(rpsidecar.Config{
			PubkeyDir:     distDir,
			DiscoveryPort: discoveryPort,
			FetchTimeout:  time.Duration(fetchTimeoutMS) * time.Millisecond,
			FetchRetries:  fetchRetries,
			Logger:        l,
		})
		if err != nil {
			_ = bundle.Close()
			return nil, fmt.Errorf("rosenpass sidecar distributor: %w", err)
		}
		dist.Start()
		bundle.dist = dist
		l.Info("rosenpass sidecar distributor armed",
			"dir", distDir, "discovery_port", discoveryPort, "retries", fetchRetries)
	}

	return &bundle, nil
}

// sidecarBundle holds the resources startSidecarDistributor allocated
// so they can be released together. Either disc or dist may be nil
// depending on operator config.
type sidecarBundle struct {
	disc *rphttp.Discovery
	dist *rpsidecar.Distributor
}

func (b *sidecarBundle) Close() error {
	var errs []error
	if b.dist != nil {
		if err := b.dist.Close(); err != nil {
			errs = append(errs, fmt.Errorf("distributor: %w", err))
		}
	}
	if b.disc != nil {
		if err := b.disc.Close(); err != nil {
			errs = append(errs, fmt.Errorf("discovery: %w", err))
		}
	}
	if len(errs) == 0 {
		return nil
	}
	return errors.Join(errs...)
}

// sidecarBindAddr resolves the listen IP for the sidecar Discovery
// server. listenHost overrides the tun address if non-empty (useful
// for service meshes that share the underlay); otherwise we bind to
// the first assigned VPN address.
func sidecarBindAddr(listenHost string, f *Interface) (net.IP, error) {
	if listenHost != "" {
		ip := net.ParseIP(listenHost)
		if ip == nil {
			return nil, fmt.Errorf("rosenpass sidecar: pq.sidecar.listen_host %q is not a valid IP", listenHost)
		}
		return ip, nil
	}
	if f == nil || f.myVpnAddrs == nil || len(f.myVpnAddrs) == 0 {
		return nil, errors.New("rosenpass sidecar: no VPN address assigned yet; configure pq.sidecar.listen_host or ensure tun is up")
	}
	return netipToIP(f.myVpnAddrs[0]), nil
}

func netipToIP(a netip.Addr) net.IP {
	if a.Is4() {
		b := a.As4()
		return net.IP(b[:])
	}
	b := a.As16()
	return net.IP(b[:])
}
