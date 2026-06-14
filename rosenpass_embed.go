//go:build rosenpass_embedded

package nebula

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"syscall"
	"time"

	"github.com/rcrowley/go-metrics"
	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/pq/rphttp"
	"github.com/slackhq/nebula/pq/rposvc"
)

// bindAttempts / bindBackoff govern the retry loop that probes the
// rosenpass UDP listen address before constructing rposvc.Service.
//
// Now that startEmbeddedRosenpass runs from Control.Start AFTER
// f.activate() has brought up the tun, the address is generally
// already assigned when we probe. The retry budget exists only to
// cover a narrow race on platforms where the kernel-side address
// assignment lags the Activate() return (observed on Ubuntu 24.04
// with systemd-networkd). 1s is enough to absorb that without
// turning the embedded rosenpass startup into a 5s wait when the
// real problem is misconfiguration.
const (
	bindAttempts = 10
	bindBackoff  = 100 * time.Millisecond
)

// startEmbeddedRosenpass wires up + starts the in-process Rosenpass
// glue: keypair on disk, UDP server bound to the local nebula tun
// IP (or an operator-supplied override), HTTP discovery service for
// peers fetching the local pubkey, and the Coordinator that drives
// lazy peer registration on handshake completion. Called from main
// when pq.embedded_rosenpass.enabled is true.
//
// By default both listeners bind to the local nebula address (the
// cert's primary VPN address) so traffic stays inside the encrypted
// overlay even if the host has multiple interfaces. Operators running
// without a tun (e.g. tun.disabled: true smoke tests) can override
// the bind address via pq.embedded_rosenpass.listen_host and
// pq.embedded_rosenpass.discovery_listen_host.
func startEmbeddedRosenpass(ctx context.Context, l *slog.Logger, c *config.C, ifce *Interface) (io.Closer, error) {
	stateDir := c.GetString("pq.embedded_rosenpass.state_dir", "/var/lib/nebula/rosenpass")
	rpPort := c.GetInt("pq.embedded_rosenpass.port", 51821)
	discPort := c.GetInt("pq.embedded_rosenpass.discovery_port", 51820)
	listenHost := c.GetString("pq.embedded_rosenpass.listen_host", "")
	discListenHost := c.GetString("pq.embedded_rosenpass.discovery_listen_host", "")

	// strict_identity (default false) is the explicit opt-in for
	// operators who want required-style PQ guarantees: when set, a PQ
	// identity problem (truncated keyfile, dangerous regen of issue
	// #6, or a local-pubkey-vs-cert-binding mismatch) becomes a hard
	// start failure instead of a degrade-to-IXPSK0. Default behaviour
	// stays exactly as today (auto-generate, keep running) plus the
	// loud Error logs + metrics added here.
	strictIdentity := c.GetBool("pq.embedded_rosenpass.strict_identity", false)

	// Fetch this node's own cert v2 PqPskBinding (if any). When the
	// cert binds a PQ identity, generateKeypair treats a fresh mint as
	// the dangerous issue-#6 regen, and we compare the binding against
	// the embedded pubkey hash below.
	certBinding := localPqPskBinding(ifce)

	// tun.disabled with no listen_host override is unreachable: the
	// default bind target is the cert's VPN address, which the kernel
	// will never assign without the tun. Refuse to start with a
	// pointer at the override knob rather than spinning bindRetry for
	// 5s only to fail with EADDRNOTAVAIL.
	tunDisabled := c.GetBool("tun.disabled", false)
	if tunDisabled && listenHost == "" {
		return nil, errors.New("pq.embedded_rosenpass.enabled requires either a tun device or pq.embedded_rosenpass.listen_host explicitly set (e.g. 127.0.0.1 for smoke tests)")
	}

	// Resolve UDP listen IP. listen_host override wins; otherwise fall
	// back to the cert's primary VPN address (existing behaviour).
	var listenIP net.IP
	if listenHost != "" {
		listenIP = net.ParseIP(listenHost)
		if listenIP == nil {
			return nil, fmt.Errorf("pq.embedded_rosenpass.listen_host: invalid IP %q", listenHost)
		}
	} else {
		if len(ifce.myVpnAddrs) == 0 {
			return nil, errors.New("pq.embedded_rosenpass: no VPN address available and no listen_host set; either bring up the tun or set pq.embedded_rosenpass.listen_host explicitly")
		}
		listenIP = addrToNetIP(ifce.myVpnAddrs[0])
	}

	// Discovery listen IP defaults to the UDP listen IP unless
	// discovery_listen_host is set. Same parse + fallback rules.
	var discListenIP net.IP
	if discListenHost != "" {
		discListenIP = net.ParseIP(discListenHost)
		if discListenIP == nil {
			return nil, fmt.Errorf("pq.embedded_rosenpass.discovery_listen_host: invalid IP %q", discListenHost)
		}
	} else {
		discListenIP = listenIP
	}

	listenUDP := &net.UDPAddr{IP: listenIP, Port: rpPort}
	listenTCP := &net.TCPAddr{IP: discListenIP, Port: discPort}

	// Probe the UDP bind once before constructing rposvc.Service. The
	// expensive bits inside rposvc.New are loading/generating the
	// ~1 MB Classic McEliece keypair and building the go-rosenpass
	// server; running those 50 times when the tun is slow to come up
	// is wasted work + log spam. We probe by opening + immediately
	// closing a real net.ListenUDP — if it succeeds the address is
	// assignable, otherwise we retry on EADDRNOTAVAIL.
	//
	// Race window: there's a tiny gap between the probe-close and
	// rposvc.New's real bind during which another process could grab
	// the port. For a long-lived nebula daemon binding a fixed
	// service port inside its own tunnel that race is negligible; if
	// it does fire, rposvc.New will surface the EADDRINUSE
	// immediately and the operator sees a clean error.
	if err := probeBindUDP(listenUDP); err != nil {
		return nil, fmt.Errorf("rposvc: probe bind %s: %w", listenUDP, err)
	}

	svc, err := rposvc.New(rposvc.Config{
		StateDir:         stateDir,
		ListenAddr:       listenUDP,
		MemoryProvider:   ifce.pki.PQMemory(),
		CertHasPqBinding: len(certBinding) > 0,
		StrictIdentity:   strictIdentity,
		Logger:           l.With("component", "rposvc"),
	})
	if err != nil {
		return nil, fmt.Errorf("rposvc.New: %w", err)
	}

	// C2: compare the local embedded pubkey hash against the CA-signed
	// PqPskBinding. If the cert binds a PQ identity and it does NOT
	// match what we just loaded/generated, peers will reject our PQ
	// identity and tunnels degrade to IXPSK0. Surface it LOUDLY. By
	// default we keep running (classical connectivity is preserved);
	// only strict_identity turns this into a refusal to start.
	if len(certBinding) > 0 {
		localHash := sha256.Sum256(svc.PublicKey())
		if !bytesEqual(certBinding, localHash[:]) {
			metrics.GetOrRegisterCounter("pq.embedded.identity_mismatch", nil).Inc(1)
			l.Error("embedded rosenpass pubkey does not match this node's CA-signed PqPskBinding; peers will reject PQ and tunnels will degrade to IXPSK0",
				"local_pubkey_sha256", hex.EncodeToString(localHash[:]),
				"cert_binding", hex.EncodeToString(certBinding),
				"remediation", "restore the original rp.pub/rp.sk from backup, OR re-issue this node's nebula cert so its PqPskBinding matches the embedded identity")
			if strictIdentity {
				_ = svc.Close()
				return nil, errors.New("embedded rosenpass identity does not match cert PqPskBinding and pq.embedded_rosenpass.strict_identity is set")
			}
		}
	}

	disc, err := rphttp.NewDiscovery(listenTCP, svc.PublicKey())
	if err != nil {
		_ = svc.Close()
		return nil, fmt.Errorf("rphttp.NewDiscovery: %w", err)
	}

	coord, err := rposvc.NewCoordinator(rposvc.CoordinatorConfig{
		Service:       svc,
		Discovery:     disc,
		RosenpassPort: rpPort,
		DiscoveryPort: discPort,
		Logger:        l.With("component", "rposvc-coord"),
	})
	if err != nil {
		_ = disc.Close()
		_ = svc.Close()
		return nil, fmt.Errorf("rposvc.NewCoordinator: %w", err)
	}

	svc.Start()
	coord.Start()

	go func() {
		<-ctx.Done()
		_ = coord.Close()
		_ = disc.Close()
		_ = svc.Close()
	}()

	// C1: watch for unexpected death of the embedded rosenpass server.
	// rposvc.Service logs + bumps pq.embedded.server_exited from inside
	// its run-loop goroutine, but nothing in the embed layer reacts —
	// the Coordinator would keep "registering" peers against a dead
	// server that never drives a handshake, so new peers silently never
	// derive a PSK. Here we select on ctx.Done() (clean shutdown) vs
	// svc.Done() (the server exited). On unexpected exit we log LOUDLY
	// at the embed layer and tear down the Coordinator + discovery so
	// it stops claiming success; the node keeps running and degrades to
	// IXPSK0. We do NOT panic/exit. Restart is intentionally not
	// attempted automatically here: a dead go-rosenpass run loop almost
	// always means the listen socket is gone (tun down) or a fatal
	// internal error, neither of which a tight restart loop fixes; the
	// metric + Error give operators the signal to intervene.
	go func() {
		select {
		case <-ctx.Done():
			return
		case <-svc.Done():
		}
		if ctx.Err() != nil {
			// Clean shutdown path: Close cancelled ctx, svc.Done()
			// fired as a consequence. Nothing to surface.
			return
		}
		l.Error("embedded rosenpass server died unexpectedly; stopping Coordinator so it no longer claims PQ peer registrations — existing and new tunnels degrade to IXPSK0",
			"err", svc.Err())
		_ = coord.Close()
		_ = disc.Close()
	}()

	l.Info("embedded rosenpass started",
		"listen_udp", listenUDP.String(),
		"listen_discovery", listenTCP.String(),
		"local_pubkey_sha256", svc.PublicKeyHex(),
	)
	return coord, nil
}

// localPqPskBinding returns this node's CA-signed PqPskBinding from its
// own cert v2, or nil if there is no usable binding (no cert state, no
// v2 cert, or a malformed/empty binding). Mirrors the accessor chain
// used by lighthouse.go's myPQGossip. A nil return means "this node
// was not provisioned with a PQ identity", which is the legitimate
// fresh-node case where auto-generating a keypair is expected.
func localPqPskBinding(ifce *Interface) []byte {
	if ifce == nil || ifce.pki == nil {
		return nil
	}
	cs := ifce.pki.getCertState()
	if cs == nil {
		return nil
	}
	myCert := cs.getCertificate(cert.Version2)
	if myCert == nil {
		return nil
	}
	h := myCert.PqPskBinding()
	if len(h) != cert.PqPskBindingLen {
		return nil
	}
	return h
}

// bytesEqual is a tiny constant-time-free equality helper kept local to
// avoid importing bytes solely for one call site. The comparison is on
// a 32-byte public binding hash, not secret material, so a non-constant-
// time compare is fine here.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// addrToNetIP mirrors rposvc's helper but in this package; avoids
// pulling that helper into the public API.
func addrToNetIP(a netip.Addr) net.IP {
	if a.Is4() {
		b := a.As4()
		return net.IP(b[:])
	}
	b := a.As16()
	return net.IP(b[:])
}

// probeBindUDP attempts to bind + immediately release a UDP socket on
// addr. On EADDRNOTAVAIL (the common case while the nebula tun
// interface is still coming up) it retries bindAttempts times at
// bindBackoff intervals. Any other error returns immediately so
// genuine misconfigurations (e.g. EADDRINUSE, bad IP family) surface
// without waiting out the full 5s budget.
func probeBindUDP(addr *net.UDPAddr) error {
	var last error
	for i := 0; i < bindAttempts; i++ {
		conn, err := net.ListenUDP("udp", addr)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		if !errors.Is(err, syscall.EADDRNOTAVAIL) {
			return err
		}
		last = err
		time.Sleep(bindBackoff)
	}
	return fmt.Errorf("address not bindable after %s: %w",
		time.Duration(bindAttempts)*bindBackoff, last)
}
