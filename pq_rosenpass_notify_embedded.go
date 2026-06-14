//go:build rosenpass_embedded

package nebula

import (
	"encoding/hex"
	"net/netip"

	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/pq/rphttp"
	"github.com/slackhq/nebula/pq/rposvc"
)

// handleGossipChanged is the embedded-build handler wired into
// PKI.SetGossipedBindingChangeCallback by main(). It is invoked by the
// lighthouse receive path whenever a peer's gossiped rosenpass UDP
// port just changed (different from the cached value), AFTER the
// lighthouse has released its locks. The handler looks up the
// peer's HostInfo (so it has the CA-verified cert in hand) and
// re-runs notifyPQProvider, which the Coordinator picks up via
// Notify -> fetchAndRegister -> Service.AddPeer. Service.AddPeer is
// now endpoint-aware: if the gossiped port differs from the cached
// registration, the embedded server is re-pointed at the corrected
// destination.
//
// Why this exists: gossip frequently arrives AFTER the handshake
// completes, so the first AddPeer call uses cfg.RosenpassPort (the
// fallback when no port has been gossiped yet). Without this
// re-notification trigger, asymmetric-port deployments would stay
// pinned to the wrong port for the lifetime of the tunnel; ix_psk2
// would never complete because the rosenpass server would keep
// driving handshakes to dev/null.
//
// Returns silently for unknown peers (handshake never happened, or
// the HostInfo was torn down between gossip arrival and callback
// fire); the next handshake completion will Notify from scratch.
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

// notifyPQProvider nudges the embedded Rosenpass coordinator (if
// configured) to fetch the peer's Rosenpass public key and register
// it for PSK derivation. Called from both initiator and responder
// handshake-complete paths so peer registration is symmetric and
// idempotent: the Coordinator de-dupes by peer static key.
//
// The Coordinator reaches the peer at vpnAddrs[0]; the cert may
// assert multiple VPN addresses (the cert.networks field is a list)
// and operators who issue such certs control the order. By
// convention nebula uses index 0 as the primary; if your CA issues
// certs with multi-address networks, ensure index 0 is the address
// the peer actually serves Rosenpass discovery on.
//
// This file is compiled into the binary only with -tags
// rosenpass_embedded; the default build uses the no-op stub in
// pq_rosenpass_notify_stub.go.
func notifyPQProvider(f *Interface, remoteCert *cert.CachedCertificate, vpnAddrs []netip.Addr) {
	if f == nil || f.pqProvider == nil || remoteCert == nil || len(vpnAddrs) == 0 {
		return
	}
	// f.pqProvider is stored as io.Closer (the always-built field
	// type) so this build-tagged file can downcast to the concrete
	// *rposvc.Coordinator without forcing the default build to
	// import rposvc. The assignment site in rosenpass_embed.go is
	// the only place that ever writes the field, and it only
	// writes *rposvc.Coordinator values.
	coord, ok := f.pqProvider.(*rposvc.Coordinator)
	if !ok || coord == nil {
		return
	}
	// The peer's cert must bind a rosenpass pubkey hash (cert-v2
	// rosenpassPubKeySha256 extension) for the Coordinator to
	// register it. Peers with old certs that predate the extension
	// fall through here without ever firing Notify; they keep
	// running non-PQ (IXPSK0) until their cert is rotated through a
	// CA that signs the extension.
	rpHash := remoteCert.Certificate.PqPskBinding()
	if len(rpHash) == 0 {
		f.l.Debug("peer cert lacks rosenpassPubKeySha256; skipping rosenpass registration",
			"vpnAddr", vpnAddrs[0], "fingerprint", remoteCert.Fingerprint)
		return
	}
	// Look up the peer's gossiped rosenpass UDP port. 0 means "no
	// HostUpdate observed yet" (or the peer is an old binary that
	// doesn't gossip the port); the Coordinator falls back to its
	// own cfg.RosenpassPort in that case. The PKI helper short-
	// circuits to 0 if SetGossipedPQProviderPortLookup has not been wired up,
	// which keeps unit-test builds without a LightHouse working.
	var rpPort, discPort uint16
	if f.pki != nil {
		rpPort = f.pki.GossipedPQProviderPortFor(vpnAddrs[0])
		// DiscoveryPort mirrors the same lookup pattern; 0 means the
		// peer hasn't gossiped a TCP discovery port and the
		// Coordinator falls back to cfg.DiscoveryPort.
		discPort = f.pki.GossipedDiscoveryPortFor(vpnAddrs[0])
	}
	coord.Notify(rphttp.PeerObserved{
		VpnIP:              vpnAddrs[0],
		PeerStaticPubKey:   remoteCert.Certificate.PublicKey(),
		Fingerprint:        remoteCert.Fingerprint,
		ExpectedPubkeyHash: hex.EncodeToString(rpHash),
		RosenpassPort:      rpPort,
		DiscoveryPort:      discPort,
	})
}
