//go:build !rosenpass_embedded

package nebula

import (
	"encoding/hex"
	"net/netip"

	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/pq/rphttp"
)

// notifyPQProvider dispatches to the sidecar Distributor when one is
// configured. The default (non-rosenpass_embedded) build uses an
// out-of-process rosenpass binary; nebula's job here is to deliver
// peer rosenpass pubkeys (cert-extension-verified) into the sidecar's
// watched directory, and to log a Debug line when a peer is observed
// whose cert lacks the trust extension.
//
// When no Distributor is wired up (operator runs nebula without
// pq.sidecar.pubkey_distribute_dir configured, or runs pure-IXPSK0
// without any rosenpass), this collapses to a no-op via the type
// assertion failure.
//
// Build with -tags rosenpass_embedded to switch to the in-process
// coordinator path in pq_rosenpass_notify_embedded.go.
func notifyPQProvider(f *Interface, remoteCert *cert.CachedCertificate, vpnAddrs []netip.Addr) {
	if f == nil || f.pqProvider == nil || remoteCert == nil || len(vpnAddrs) == 0 {
		return
	}
	// f.pqProvider is stored as io.Closer (the always-built field
	// type) so we type-assert back to the sidecar bundle that owns
	// both Discovery + Distributor. The bundle's dist may be nil if
	// the operator configured serve-only (no distribute_dir).
	bundle, ok := f.pqProvider.(*sidecarBundle)
	if !ok || bundle == nil || bundle.dist == nil {
		return
	}
	dist := bundle.dist
	rpHash := remoteCert.Certificate.PqPskBinding()
	if len(rpHash) == 0 {
		f.l.Debug("peer cert lacks rosenpassPubKeySha256; skipping rosenpass distribution",
			"vpnAddr", vpnAddrs[0], "fingerprint", remoteCert.Fingerprint)
		return
	}
	var discPort uint16
	if f.pki != nil {
		discPort = f.pki.GossipedDiscoveryPortFor(vpnAddrs[0])
	}
	dist.Notify(rphttp.PeerObserved{
		VpnIP:              vpnAddrs[0],
		PeerStaticPubKey:   remoteCert.Certificate.PublicKey(),
		Fingerprint:        remoteCert.Fingerprint,
		ExpectedPubkeyHash: hex.EncodeToString(rpHash),
		DiscoveryPort:      discPort,
	})
}

// handleGossipChanged re-runs notifyPQProvider when a peer's
// gossiped rosenpass info changes (typically a discovery_port update
// arriving after the initial handshake). Without this, sidecar mode
// would stay pinned to cfg.DiscoveryPort for the lifetime of the
// tunnel in heterogeneous-port deployments.
func handleGossipChanged(f *Interface, vpnAddr netip.Addr) {
	if f == nil || !vpnAddr.IsValid() {
		return
	}
	hostInfo := f.hostMap.QueryVpnAddr(vpnAddr)
	if hostInfo == nil {
		return
	}
	remoteCert := hostInfo.GetCert()
	if remoteCert == nil {
		return
	}
	notifyPQProvider(f, remoteCert, []netip.Addr{vpnAddr})
}
