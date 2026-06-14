package rphttp

import "net/netip"

// PeerObserved is the event emitted by nebula when it has just
// completed a handshake (subtype 0 or 2) with a peer over the
// underlay or upgraded an existing tunnel. Both the embedded
// rposvc.Coordinator and the sidecar rpsidecar.Distributor consume
// this event to drive pubkey discovery + Rosenpass peer setup.
//
// VpnIP is the peer's nebula overlay address (used to reach the
// peer's discovery service and Rosenpass server inside the tunnel).
// PeerStaticPubKey is the peer's nebula static public key (32 bytes
// for X25519); it is the lookup key in pq.MemoryProvider once a PSK
// is derived. Fingerprint is the peer's nebula cert fingerprint, used
// for logging, file naming, and de-duplication.
//
// ExpectedPubkeyHash is the SHA-256 of the peer's Rosenpass public
// key, sourced from the CA-signed cert-v2 extension that binds it.
// It is the sole trust anchor for pubkey validation: empty means the
// peer's cert lacks the extension, in which case consumers refuse
// to register the peer (operator must rotate that peer's cert
// through a CA that signs the extension to enable PQ).
//
// RosenpassPort is the UDP port the peer has gossiped (via
// NebulaMetaDetails.RosenpassPort in HostUpdate) that it's listening
// on for rosenpass handshakes. 0 means "peer hasn't gossiped a port
// yet" — typically a pre-gossip binary or first-contact before any
// HostUpdate has arrived — and the consumer falls back to its own
// cfg.RosenpassPort. Trust model: the gossiped port is routing
// information only. A peer lying about its port harms only its own
// PQ handshake; the CA is not involved.
//
// DiscoveryPort is the analogous TCP port the peer has gossiped for
// its rosenpass-discovery HTTP service (the endpoint we hit via
// FetchPubkey to retrieve its rosenpass pubkey). 0 falls back to
// the consumer's cfg.DiscoveryPort. Same trust model as
// RosenpassPort: a peer misreporting the port only breaks its own
// PQ setup.
type PeerObserved struct {
	VpnIP              netip.Addr
	PeerStaticPubKey   []byte
	Fingerprint        string
	ExpectedPubkeyHash string
	RosenpassPort      uint16
	DiscoveryPort      uint16
}
