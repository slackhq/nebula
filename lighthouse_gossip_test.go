package nebula

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"net/netip"
	"testing"
	"time"

	"github.com/gaissmai/bart"
	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/header"
	"github.com/slackhq/nebula/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeCodec is a trivial test-local pq.IdentityCodec so the core gossip
// tests don't depend on any concrete provider's wire layout (the provider
// byte layout is exercised in the provider package's own identity_test).
// Format: 1 magic byte (0xf0), 32-byte hash, two big-endian uint16 ports.
// Encode returns nil for a non-32-byte hash (mirroring "advertise nothing
// when we have no binding"); Decode rejects anything that isn't exactly
// this shape, so a garbage/truncated blob round-trips to ok=false.
type fakeCodec struct{}

const fakeMagic = 0xf0

func fakeEncode(hash []byte, portA, portB uint16) []byte {
	if len(hash) != cert.PqPskBindingLen {
		return nil
	}
	b := make([]byte, 1+cert.PqPskBindingLen+4)
	b[0] = fakeMagic
	copy(b[1:1+cert.PqPskBindingLen], hash)
	binary.BigEndian.PutUint16(b[1+cert.PqPskBindingLen:], portA)
	binary.BigEndian.PutUint16(b[1+cert.PqPskBindingLen+2:], portB)
	return b
}

func fakeDecode(blob []byte) (hash []byte, portA, portB uint16, ok bool) {
	if len(blob) != 1+cert.PqPskBindingLen+4 || blob[0] != fakeMagic {
		return nil, 0, 0, false
	}
	hash = make([]byte, cert.PqPskBindingLen)
	copy(hash, blob[1:1+cert.PqPskBindingLen])
	portA = binary.BigEndian.Uint16(blob[1+cert.PqPskBindingLen:])
	portB = binary.BigEndian.Uint16(blob[1+cert.PqPskBindingLen+2:])
	return hash, portA, portB, true
}

func (fakeCodec) Encode(hash []byte, portA, portB uint16) []byte {
	return fakeEncode(hash, portA, portB)
}
func (fakeCodec) Decode(blob []byte) ([]byte, uint16, uint16, bool) { return fakeDecode(blob) }

// TestLighthouse_GossipReceiveAndAccessor exercises the receive side of
// the rosenpass-pubkey gossip wire: a HostUpdate with RosenpassPubkeySha256
// + RosenpassPort should land on the peer's RemoteList, and
// LookupGossipedPQBindingHash should return the same hex hash given a cert that
// asserts the peer's vpn address.
func TestLighthouse_GossipReceiveAndAccessor(t *testing.T) {
	l := test.NewLogger()

	myVpnNet := netip.MustParsePrefix("10.128.0.1/24")
	nt := new(bart.Lite)
	nt.Insert(myVpnNet)
	cs := &CertState{
		myVpnNetworks:      []netip.Prefix{myVpnNet},
		myVpnNetworksTable: nt,
	}

	c := config.NewC(l)
	c.Settings["lighthouse"] = map[string]any{"am_lighthouse": true}
	c.Settings["listen"] = map[string]any{"port": 4242}

	lh, err := NewLightHouseFromConfig(t.Context(), l, c, cs, nil, nil)
	require.NoError(t, err)
	lh.SetPQIdentityCodec(fakeCodec{})
	lh.ifce = &mockEncWriter{}
	lhh := lh.NewRequestHandler()

	peerVpn := netip.MustParseAddr("10.128.0.42")
	peerUdp := netip.MustParseAddrPort("198.51.100.42:4242")

	// 32-byte hash all 0xab.
	rpHash := bytes.Repeat([]byte{0xab}, cert.PqPskBindingLen)

	upd := &NebulaMeta{
		Type: NebulaMeta_HostUpdateNotification,
		Details: &NebulaMetaDetails{
			VpnAddr: netAddrToProtoAddr(peerVpn),
			V4AddrPorts: []*V4AddrPort{
				netAddrToProtoV4AddrPort(peerUdp.Addr(), peerUdp.Port()),
			},
			PqPskIdentity: fakeEncode(rpHash, 51820, 0),
		},
	}
	b, err := upd.Marshal()
	require.NoError(t, err)
	lhh.HandleRequest(peerUdp, []netip.Addr{peerVpn}, b, &testEncWriter{})

	// Peer's RemoteList must hold both gossiped fields.
	rl := lh.Query(peerVpn)
	require.NotNil(t, rl)
	require.Equal(t, hex.EncodeToString(rpHash), rl.GossipedPQBindingHashHex())
	require.Equal(t, uint16(51820), rl.GossipedPQProviderPort())

	// Accessor on the lighthouse must resolve the same value via a cert.
	stub := &gossipStubCert{networks: []netip.Prefix{
		netip.PrefixFrom(peerVpn, peerVpn.BitLen()),
	}}
	require.Equal(t, hex.EncodeToString(rpHash), lh.LookupGossipedPQBindingHash(stub))

	// And a cert that names an unrelated VPN address resolves to "".
	unrelated := netip.MustParseAddr("10.128.0.99")
	stubUnknown := &gossipStubCert{networks: []netip.Prefix{
		netip.PrefixFrom(unrelated, unrelated.BitLen()),
	}}
	require.Equal(t, "", lh.LookupGossipedPQBindingHash(stubUnknown))

	// Nil cert and nil lighthouse must be safe.
	require.Equal(t, "", lh.LookupGossipedPQBindingHash(nil))
	var nilLh *LightHouse
	require.Equal(t, "", nilLh.LookupGossipedPQBindingHash(stub))
}

// TestLighthouse_LookupGossipedPQProviderPort exercises the by-vpnAddr accessor
// the Coordinator consumes: a HostUpdate carrying RosenpassPort=51823
// should be retrievable by vpnAddr, and unknown / nil-receiver inputs
// must return 0 without crashing.
func TestLighthouse_LookupGossipedPQProviderPort(t *testing.T) {
	l := test.NewLogger()

	myVpnNet := netip.MustParsePrefix("10.128.0.1/24")
	nt := new(bart.Lite)
	nt.Insert(myVpnNet)
	cs := &CertState{
		myVpnNetworks:      []netip.Prefix{myVpnNet},
		myVpnNetworksTable: nt,
	}

	c := config.NewC(l)
	c.Settings["lighthouse"] = map[string]any{"am_lighthouse": true}
	c.Settings["listen"] = map[string]any{"port": 4242}

	lh, err := NewLightHouseFromConfig(t.Context(), l, c, cs, nil, nil)
	require.NoError(t, err)
	lh.SetPQIdentityCodec(fakeCodec{})
	lh.ifce = &mockEncWriter{}
	lhh := lh.NewRequestHandler()

	peerVpn := netip.MustParseAddr("10.128.0.42")
	peerUdp := netip.MustParseAddrPort("198.51.100.42:4242")

	// Peer gossips an asymmetric rosenpass port.
	upd := &NebulaMeta{
		Type: NebulaMeta_HostUpdateNotification,
		Details: &NebulaMetaDetails{
			VpnAddr: netAddrToProtoAddr(peerVpn),
			V4AddrPorts: []*V4AddrPort{
				netAddrToProtoV4AddrPort(peerUdp.Addr(), peerUdp.Port()),
			},
			PqPskIdentity: fakeEncode(make([]byte, cert.PqPskBindingLen), 51823, 0),
		},
	}
	b, err := upd.Marshal()
	require.NoError(t, err)
	lhh.HandleRequest(peerUdp, []netip.Addr{peerVpn}, b, &testEncWriter{})

	// Direct vpnAddr lookup must round-trip the gossiped value.
	require.Equal(t, uint16(51823), lh.LookupGossipedPQProviderPort(peerVpn))

	// An unrelated vpnAddr (we've never heard from this peer) returns 0.
	require.Equal(t, uint16(0), lh.LookupGossipedPQProviderPort(netip.MustParseAddr("10.128.0.99")))

	// Invalid vpnAddr returns 0.
	require.Equal(t, uint16(0), lh.LookupGossipedPQProviderPort(netip.Addr{}))

	// Nil receiver is safe.
	var nilLh *LightHouse
	require.Equal(t, uint16(0), nilLh.LookupGossipedPQProviderPort(peerVpn))
}

// TestLighthouse_LookupGossipedPQProviderPort_PortAbsent verifies a HostUpdate
// without the RosenpassPort field — pre-gossip peer or new peer that
// hasn't yet sent one — leaves the lookup returning 0, which the
// embedded rosenpass Coordinator interprets as "fall back to local
// cfg.RosenpassPort".
func TestLighthouse_LookupGossipedPQProviderPort_PortAbsent(t *testing.T) {
	l := test.NewLogger()

	myVpnNet := netip.MustParsePrefix("10.128.0.1/24")
	nt := new(bart.Lite)
	nt.Insert(myVpnNet)
	cs := &CertState{
		myVpnNetworks:      []netip.Prefix{myVpnNet},
		myVpnNetworksTable: nt,
	}

	c := config.NewC(l)
	c.Settings["lighthouse"] = map[string]any{"am_lighthouse": true}
	c.Settings["listen"] = map[string]any{"port": 4242}

	lh, err := NewLightHouseFromConfig(t.Context(), l, c, cs, nil, nil)
	require.NoError(t, err)
	lh.SetPQIdentityCodec(fakeCodec{})
	lh.ifce = &mockEncWriter{}
	lhh := lh.NewRequestHandler()

	peerVpn := netip.MustParseAddr("10.128.0.42")
	peerUdp := netip.MustParseAddrPort("198.51.100.42:4242")
	newLHHostUpdate(peerUdp, peerVpn, []netip.AddrPort{peerUdp}, lhh)

	assert.Equal(t, uint16(0), lh.LookupGossipedPQProviderPort(peerVpn),
		"absent RosenpassPort must resolve to 0 (Coordinator-fallback signal)")
}

// TestLighthouse_GossipChangedCallbackFiresOnPortChange pins down the
// Prod-1 fix-B re-notify trigger: when a HostUpdate carries a fresh
// rosenpass UDP port (different from the cached one), the lighthouse
// must fire the gossip-changed callback exactly once with the peer's
// vpnAddr. Receiving an identical update again is a no-op. A third
// update with another new port fires the callback again. Without
// this signal, the embedded rosenpass Coordinator would never learn
// about gossip that arrives AFTER handshake completion and would
// stay pinned to the cfg-fallback port for the lifetime of the
// tunnel.
func TestLighthouse_GossipChangedCallbackFiresOnPortChange(t *testing.T) {
	l := test.NewLogger()

	myVpnNet := netip.MustParsePrefix("10.128.0.1/24")
	nt := new(bart.Lite)
	nt.Insert(myVpnNet)
	cs := &CertState{
		myVpnNetworks:      []netip.Prefix{myVpnNet},
		myVpnNetworksTable: nt,
	}

	c := config.NewC(l)
	c.Settings["lighthouse"] = map[string]any{"am_lighthouse": true}
	c.Settings["listen"] = map[string]any{"port": 4242}

	lh, err := NewLightHouseFromConfig(t.Context(), l, c, cs, nil, nil)
	require.NoError(t, err)
	lh.SetPQIdentityCodec(fakeCodec{})
	lh.ifce = &mockEncWriter{}
	lhh := lh.NewRequestHandler()

	// Install a recording callback. The lighthouse fires it on every
	// transition to a new in-range port, never on duplicates. We
	// don't need synchronisation in this test because the
	// HostUpdate receive path is invoked directly on the test
	// goroutine via lhh.HandleRequest — the lighthouse only spawns
	// background goroutines for queries, not for HostUpdate
	// processing.
	var fired []netip.Addr
	lh.SetGossipChangedCallback(func(addr netip.Addr) {
		fired = append(fired, addr)
	})

	peerVpn := netip.MustParseAddr("10.128.0.42")
	peerUdp := netip.MustParseAddrPort("198.51.100.42:4242")

	sendUpdate := func(port uint16) {
		upd := &NebulaMeta{
			Type: NebulaMeta_HostUpdateNotification,
			Details: &NebulaMetaDetails{
				VpnAddr: netAddrToProtoAddr(peerVpn),
				V4AddrPorts: []*V4AddrPort{
					netAddrToProtoV4AddrPort(peerUdp.Addr(), peerUdp.Port()),
				},
				PqPskIdentity: fakeEncode(make([]byte, cert.PqPskBindingLen), port, 0),
			},
		}
		b, err := upd.Marshal()
		require.NoError(t, err)
		lhh.HandleRequest(peerUdp, []netip.Addr{peerVpn}, b, &testEncWriter{})
	}

	// First port (51823) → callback fires once.
	sendUpdate(51823)
	require.Equal(t, []netip.Addr{peerVpn}, fired,
		"first non-zero gossiped port should fire the callback")

	// Same port again → callback does NOT fire (duplicate gossip).
	sendUpdate(51823)
	require.Equal(t, []netip.Addr{peerVpn}, fired,
		"identical port re-gossip must not refire the callback")

	// New port (51824) → callback fires again.
	sendUpdate(51824)
	require.Equal(t, []netip.Addr{peerVpn, peerVpn}, fired,
		"port-change gossip must refire the callback")

	// Port 0 (absent / proto3 default) → callback does NOT fire,
	// and the cached port is left intact (zero is "unset" not
	// "clear"). This matches the receive-side setter contract.
	sendUpdate(0)
	require.Equal(t, []netip.Addr{peerVpn, peerVpn}, fired,
		"port=0 (unset) must not refire the callback")
	require.Equal(t, uint16(51824), lh.LookupGossipedPQProviderPort(peerVpn))

	// nil callback unset → still safe.
	lh.SetGossipChangedCallback(nil)
	sendUpdate(51825)
	require.Equal(t, []netip.Addr{peerVpn, peerVpn}, fired,
		"nil-callback unset must suppress further firings")
}

// TestLighthouse_GossipOldPeerNoFields verifies the receive path remains
// backwards-compatible: a HostUpdate from an old peer (no gossip fields)
// must not crash and must leave the RemoteList's gossip state empty.
func TestLighthouse_GossipOldPeerNoFields(t *testing.T) {
	l := test.NewLogger()

	myVpnNet := netip.MustParsePrefix("10.128.0.1/24")
	nt := new(bart.Lite)
	nt.Insert(myVpnNet)
	cs := &CertState{
		myVpnNetworks:      []netip.Prefix{myVpnNet},
		myVpnNetworksTable: nt,
	}

	c := config.NewC(l)
	c.Settings["lighthouse"] = map[string]any{"am_lighthouse": true}
	c.Settings["listen"] = map[string]any{"port": 4242}

	lh, err := NewLightHouseFromConfig(t.Context(), l, c, cs, nil, nil)
	require.NoError(t, err)
	lh.SetPQIdentityCodec(fakeCodec{})
	lh.ifce = &mockEncWriter{}
	lhh := lh.NewRequestHandler()

	peerVpn := netip.MustParseAddr("10.128.0.42")
	peerUdp := netip.MustParseAddrPort("198.51.100.42:4242")
	newLHHostUpdate(peerUdp, peerVpn, []netip.AddrPort{peerUdp}, lhh)

	rl := lh.Query(peerVpn)
	require.NotNil(t, rl)
	assert.Equal(t, "", rl.GossipedPQBindingHashHex())
	assert.Equal(t, uint16(0), rl.GossipedPQProviderPort())
}

// TestLighthouse_GossipMalformedHashIgnored verifies a peer that sends
// a wrong-length RosenpassPubkeySha256 (e.g. 16 bytes from a buggy or
// hostile implementation) does not poison the per-peer slot. The
// previous claim (or empty) stays untouched.
func TestLighthouse_GossipMalformedHashIgnored(t *testing.T) {
	l := test.NewLogger()

	myVpnNet := netip.MustParsePrefix("10.128.0.1/24")
	nt := new(bart.Lite)
	nt.Insert(myVpnNet)
	cs := &CertState{
		myVpnNetworks:      []netip.Prefix{myVpnNet},
		myVpnNetworksTable: nt,
	}

	c := config.NewC(l)
	c.Settings["lighthouse"] = map[string]any{"am_lighthouse": true}
	c.Settings["listen"] = map[string]any{"port": 4242}

	lh, err := NewLightHouseFromConfig(t.Context(), l, c, cs, nil, nil)
	require.NoError(t, err)
	lh.SetPQIdentityCodec(fakeCodec{})
	lh.ifce = &mockEncWriter{}
	lhh := lh.NewRequestHandler()

	peerVpn := netip.MustParseAddr("10.128.0.42")
	peerUdp := netip.MustParseAddrPort("198.51.100.42:4242")

	// First, store a valid 32-byte claim.
	rpHash := bytes.Repeat([]byte{0xab}, cert.PqPskBindingLen)
	upd := &NebulaMeta{
		Type: NebulaMeta_HostUpdateNotification,
		Details: &NebulaMetaDetails{
			VpnAddr:       netAddrToProtoAddr(peerVpn),
			V4AddrPorts:   []*V4AddrPort{netAddrToProtoV4AddrPort(peerUdp.Addr(), peerUdp.Port())},
			PqPskIdentity: fakeEncode(rpHash, 0, 0),
		},
	}
	b, err := upd.Marshal()
	require.NoError(t, err)
	lhh.HandleRequest(peerUdp, []netip.Addr{peerVpn}, b, &testEncWriter{})
	require.Equal(t, hex.EncodeToString(rpHash), lh.Query(peerVpn).GossipedPQBindingHashHex())

	// Now send a malformed/garbage PqPskIdentity blob (truncated, so the
	// codec's Decode rejects it). The prior valid claim must stay, since
	// the receive path skips on a non-decodable blob.
	upd.Details.PqPskIdentity = bytes.Repeat([]byte{0xcd}, 16)
	b, err = upd.Marshal()
	require.NoError(t, err)
	lhh.HandleRequest(peerUdp, []netip.Addr{peerVpn}, b, &testEncWriter{})
	assert.Equal(t, hex.EncodeToString(rpHash), lh.Query(peerVpn).GossipedPQBindingHashHex(),
		"malformed gossip must not overwrite a valid prior claim")
}

// TestRemoteList_UnlockedSetPQGossip pins the setter's
// boundary behaviour: empty hash clears; wrong-length hash is ignored;
// 32-byte hash is hex-encoded and stored; port 0 leaves prior port
// untouched.
func TestRemoteList_UnlockedSetPQGossip(t *testing.T) {
	rl := NewRemoteList(nil, nil)

	// 32-byte hash + port → stored.
	h32 := bytes.Repeat([]byte{0xab}, cert.PqPskBindingLen)
	rl.Lock()
	rl.unlockedSetPQGossip(nil, h32, 51820, 51840)
	rl.Unlock()
	assert.Equal(t, hex.EncodeToString(h32), rl.GossipedPQBindingHashHex())
	assert.Equal(t, uint16(51820), rl.GossipedPQProviderPort())
	assert.Equal(t, uint16(51840), rl.GossipedDiscoveryPort())

	// Wrong-length hash → leaves prior claim untouched.
	rl.Lock()
	rl.unlockedSetPQGossip(nil, []byte{0x01, 0x02}, 0, 0)
	rl.Unlock()
	assert.Equal(t, hex.EncodeToString(h32), rl.GossipedPQBindingHashHex())
	assert.Equal(t, uint16(51820), rl.GossipedPQProviderPort(),
		"zero port must leave prior port intact (treated as 'unset')")
	assert.Equal(t, uint16(51840), rl.GossipedDiscoveryPort(),
		"zero discovery port must leave prior discovery port intact")

	// Empty hash → clears prior claim.
	rl.Lock()
	rl.unlockedSetPQGossip(nil, nil, 0, 0)
	rl.Unlock()
	assert.Equal(t, "", rl.GossipedPQBindingHashHex())
	assert.Equal(t, uint16(51820), rl.GossipedPQProviderPort())
	assert.Equal(t, uint16(51840), rl.GossipedDiscoveryPort())

	// Out-of-range port (proto3 uint32 > uint16 max) is ignored.
	rl.Lock()
	rl.unlockedSetPQGossip(nil, h32, 1<<20, 1<<20)
	rl.Unlock()
	assert.Equal(t, uint16(51820), rl.GossipedPQProviderPort())
	assert.Equal(t, uint16(51840), rl.GossipedDiscoveryPort())
}

// TestLighthouse_GossipSendIncludesOwnHash verifies the send path
// pulls our own RosenpassPubkeySha256 cert extension into the
// outbound HostUpdate. The send path is gated on v2 cert / amLighthouse
// false; this test builds a real v2 path through SendUpdate by stubbing
// a CertState that exposes a cert with the extension.
func TestLighthouse_GossipSendIncludesOwnHash(t *testing.T) {
	l := test.NewLogger()

	myVpnNet := netip.MustParsePrefix("10.128.0.1/24")
	nt := new(bart.Lite)
	nt.Insert(myVpnNet)

	c := config.NewC(l)
	c.Settings["lighthouse"] = map[string]any{
		"hosts":           []any{"10.128.0.99"},
		"advertise_addrs": []any{"1.2.3.4:4242"},
	}
	c.Settings["static_host_map"] = map[string]any{
		"10.128.0.99": []any{"203.0.113.99:4242"},
	}
	c.Settings["pq"] = map[string]any{"rosenpass_port": 51820}
	c.Settings["listen"] = map[string]any{"port": 4242}

	myRPHash := bytes.Repeat([]byte{0xab}, cert.PqPskBindingLen)
	myV2 := &gossipStubCert{
		version:  cert.Version2,
		rpHash:   myRPHash,
		networks: []netip.Prefix{myVpnNet},
	}
	cs := &CertState{
		myVpnNetworks:      []netip.Prefix{myVpnNet},
		myVpnNetworksTable: nt,
		initiatingVersion:  cert.Version2,
		v2Cert:             myV2,
	}

	lh, err := NewLightHouseFromConfig(t.Context(), l, c, cs, nil, nil)
	require.NoError(t, err)
	lh.SetPQIdentityCodec(fakeCodec{})

	// Capture the outbound HostUpdate so we can inspect the wire fields.
	cap := &gossipSendCaptureEncWriter{certState: cs}
	lh.ifce = cap

	lh.SendUpdate()

	require.NotNil(t, cap.lastDetails, "no HostUpdate was sent")
	// Assert via the plain legacy scalar fields (no provider import needed)
	// — these are emitted unconditionally for backward compat alongside the
	// opaque blob.
	assert.Equal(t, myRPHash, cap.lastDetails.RosenpassPubkeySha256,
		"send path must include our own cert extension hash")
	assert.Equal(t, uint32(51820), cap.lastDetails.RosenpassPort,
		"send path must include the configured rosenpass port")
}

// TestLighthouse_GossipSendNoCertExtensionOmits verifies the send
// path leaves the gossip fields blank when our cert lacks the
// extension. Backwards-compat: nodes without rosenpass identity stay
// silent on the wire.
func TestLighthouse_GossipSendNoCertExtensionOmits(t *testing.T) {
	l := test.NewLogger()

	myVpnNet := netip.MustParsePrefix("10.128.0.1/24")
	nt := new(bart.Lite)
	nt.Insert(myVpnNet)

	c := config.NewC(l)
	c.Settings["lighthouse"] = map[string]any{
		"hosts":           []any{"10.128.0.99"},
		"advertise_addrs": []any{"1.2.3.4:4242"},
	}
	c.Settings["static_host_map"] = map[string]any{
		"10.128.0.99": []any{"203.0.113.99:4242"},
	}
	c.Settings["listen"] = map[string]any{"port": 4242}

	// v2 cert WITHOUT a rosenpass extension.
	myV2 := &gossipStubCert{
		version:  cert.Version2,
		rpHash:   nil,
		networks: []netip.Prefix{myVpnNet},
	}
	cs := &CertState{
		myVpnNetworks:      []netip.Prefix{myVpnNet},
		myVpnNetworksTable: nt,
		initiatingVersion:  cert.Version2,
		v2Cert:             myV2,
	}

	lh, err := NewLightHouseFromConfig(t.Context(), l, c, cs, nil, nil)
	require.NoError(t, err)
	lh.SetPQIdentityCodec(fakeCodec{})

	cap := &gossipSendCaptureEncWriter{certState: cs}
	lh.ifce = cap
	lh.SendUpdate()

	require.NotNil(t, cap.lastDetails)
	assert.Nil(t, cap.lastDetails.PqPskIdentity,
		"missing extension must produce no gossip blob (codec returns nil for a nil hash)")
}

// TestLighthouse_HostUpdateAckPiggybacksGossip verifies the
// lighthouse-side fix-vice-versa: a HostUpdateNotificationAck the
// lighthouse sends back to a client must include the lighthouse's
// own RosenpassPubkeySha256 + RosenpassPort. Without this back
// channel, non-lighthouse peers never learn the lighthouse's
// rosenpass UDP port (HostUpdate is one-directional and
// HostQueryReply strips the gossip fields), so their embedded
// rosenpass Coordinator stays pinned to cfg.RosenpassPort and
// ix_psk2 fails in heterogeneous-port deployments.
func TestLighthouse_HostUpdateAckPiggybacksGossip(t *testing.T) {
	l := test.NewLogger()

	myVpnNet := netip.MustParsePrefix("10.128.0.1/24")
	nt := new(bart.Lite)
	nt.Insert(myVpnNet)

	c := config.NewC(l)
	c.Settings["lighthouse"] = map[string]any{"am_lighthouse": true}
	c.Settings["listen"] = map[string]any{"port": 4242}
	c.Settings["pq"] = map[string]any{"rosenpass_port": 51823}

	// Lighthouse's own v2 cert carries a well-formed rosenpass hash.
	myRPHash := bytes.Repeat([]byte{0xde}, cert.PqPskBindingLen)
	myV2 := &gossipStubCert{
		version:  cert.Version2,
		rpHash:   myRPHash,
		networks: []netip.Prefix{myVpnNet},
	}
	cs := &CertState{
		myVpnNetworks:      []netip.Prefix{myVpnNet},
		myVpnNetworksTable: nt,
		initiatingVersion:  cert.Version2,
		v2Cert:             myV2,
	}

	lh, err := NewLightHouseFromConfig(t.Context(), l, c, cs, nil, nil)
	require.NoError(t, err)
	lh.SetPQIdentityCodec(fakeCodec{})
	// lh.ifce is consulted by myRosenpassGossip to reach our v2 cert,
	// not for transport — the ack itself goes through the writer
	// passed into HandleRequest (ackCap below).
	lh.ifce = &gossipSendCaptureEncWriter{certState: cs}
	lhh := lh.NewRequestHandler()

	// Client sends a v2 HostUpdate to the lighthouse. We don't set
	// OldVpnAddr → v2 path is taken; the lighthouse must respond with
	// an ack carrying its own gossip fields.
	peerVpn := netip.MustParseAddr("10.128.0.42")
	peerUdp := netip.MustParseAddrPort("198.51.100.42:4242")
	upd := &NebulaMeta{
		Type: NebulaMeta_HostUpdateNotification,
		Details: &NebulaMetaDetails{
			VpnAddr: netAddrToProtoAddr(peerVpn),
			V4AddrPorts: []*V4AddrPort{
				netAddrToProtoV4AddrPort(peerUdp.Addr(), peerUdp.Port()),
			},
		},
	}
	b, err := upd.Marshal()
	require.NoError(t, err)

	// Capture the ack on the per-request writer (handleHostUpdate-
	// Notification calls w.SendMessageToVpnAddr to send the ack back
	// to fromVpnAddrs[0]).
	ackCap := &gossipSendCaptureEncWriter{certState: cs}
	lhh.HandleRequest(peerUdp, []netip.Addr{peerVpn}, b, ackCap)

	require.NotNil(t, ackCap.lastDetails, "no ack was sent")
	// Assert via the plain legacy scalar fields (no provider import needed).
	assert.Equal(t, myRPHash, ackCap.lastDetails.RosenpassPubkeySha256,
		"ack must include lighthouse's rosenpass hash")
	assert.Equal(t, uint32(51823), ackCap.lastDetails.RosenpassPort,
		"ack must include lighthouse's rosenpass port")
}

// TestLighthouse_HostUpdateAckRecvStoresGossip verifies the
// client-side complement: when a non-lighthouse peer receives a
// HostUpdateNotificationAck from one of its configured lighthouses,
// it must extract the gossip fields and store them in the
// lighthouse's RemoteList, AND fire the gossip-changed callback so
// the embedded rosenpass Coordinator can re-register the lighthouse
// at its corrected UDP port.
func TestLighthouse_HostUpdateAckRecvStoresGossip(t *testing.T) {
	l := test.NewLogger()

	myVpnNet := netip.MustParsePrefix("10.128.0.1/24")
	nt := new(bart.Lite)
	nt.Insert(myVpnNet)
	cs := &CertState{
		myVpnNetworks:      []netip.Prefix{myVpnNet},
		myVpnNetworksTable: nt,
	}

	// Client config: we have one lighthouse at 10.128.0.99.
	c := config.NewC(l)
	c.Settings["lighthouse"] = map[string]any{
		"am_lighthouse": false,
		"hosts":         []any{"10.128.0.99"},
	}
	c.Settings["static_host_map"] = map[string]any{
		"10.128.0.99": []any{"203.0.113.99:4242"},
	}
	c.Settings["listen"] = map[string]any{"port": 4242}

	lh, err := NewLightHouseFromConfig(t.Context(), l, c, cs, nil, nil)
	require.NoError(t, err)
	lh.SetPQIdentityCodec(fakeCodec{})
	lh.ifce = &mockEncWriter{}
	lhh := lh.NewRequestHandler()

	// Install a callback so we can assert it fires on first non-zero
	// gossiped port.
	var fired []netip.Addr
	lh.SetGossipChangedCallback(func(addr netip.Addr) {
		fired = append(fired, addr)
	})

	lhVpn := netip.MustParseAddr("10.128.0.99")
	lhUdp := netip.MustParseAddrPort("203.0.113.99:4242")
	lhRPHash := bytes.Repeat([]byte{0xbe}, cert.PqPskBindingLen)

	// Lighthouse-side ack carries gossip piggyback.
	ack := &NebulaMeta{
		Type: NebulaMeta_HostUpdateNotificationAck,
		Details: &NebulaMetaDetails{
			PqPskIdentity: fakeEncode(lhRPHash, 51823, 0),
		},
	}
	b, err := ack.Marshal()
	require.NoError(t, err)
	lhh.HandleRequest(lhUdp, []netip.Addr{lhVpn}, b, &testEncWriter{})

	// Lighthouse's gossip fields should now be in our cache.
	assert.Equal(t, uint16(51823), lh.LookupGossipedPQProviderPort(lhVpn),
		"client must store lighthouse's gossiped port from the ack")
	assert.Equal(t, hex.EncodeToString(lhRPHash), lh.Query(lhVpn).GossipedPQBindingHashHex(),
		"client must store lighthouse's gossiped hash from the ack")

	// Callback fires for the lighthouse's vpnAddr.
	require.Equal(t, []netip.Addr{lhVpn}, fired,
		"first non-zero gossiped port from ack must fire the callback")

	// Re-receive the same ack: callback must NOT fire again
	// (portChanged stays false on duplicate gossip).
	lhh.HandleRequest(lhUdp, []netip.Addr{lhVpn}, b, &testEncWriter{})
	assert.Equal(t, []netip.Addr{lhVpn}, fired,
		"duplicate ack must not refire the callback")
}

// TestLighthouse_HostUpdateAckRecvDropsNonLighthouseSource verifies
// the receive guard: an ack-shaped message from a peer that is NOT
// configured as a lighthouse must be ignored. This is defence-in-
// depth — we only initiate HostUpdate to lighthouses, so any ack we
// see should come from one, but a hostile peer could try to forge an
// ack to inject a wrong rosenpass port for the lighthouse.
func TestLighthouse_HostUpdateAckRecvDropsNonLighthouseSource(t *testing.T) {
	l := test.NewLogger()

	myVpnNet := netip.MustParsePrefix("10.128.0.1/24")
	nt := new(bart.Lite)
	nt.Insert(myVpnNet)
	cs := &CertState{
		myVpnNetworks:      []netip.Prefix{myVpnNet},
		myVpnNetworksTable: nt,
	}

	// We have ONE lighthouse: 10.128.0.99.
	c := config.NewC(l)
	c.Settings["lighthouse"] = map[string]any{
		"am_lighthouse": false,
		"hosts":         []any{"10.128.0.99"},
	}
	c.Settings["static_host_map"] = map[string]any{
		"10.128.0.99": []any{"203.0.113.99:4242"},
	}
	c.Settings["listen"] = map[string]any{"port": 4242}

	lh, err := NewLightHouseFromConfig(t.Context(), l, c, cs, nil, nil)
	require.NoError(t, err)
	lh.SetPQIdentityCodec(fakeCodec{})
	lh.ifce = &mockEncWriter{}
	lhh := lh.NewRequestHandler()

	// Ack arrives from a DIFFERENT peer (not our lighthouse).
	hostileVpn := netip.MustParseAddr("10.128.0.66")
	hostileUdp := netip.MustParseAddrPort("198.51.100.66:4242")
	ack := &NebulaMeta{
		Type: NebulaMeta_HostUpdateNotificationAck,
		Details: &NebulaMetaDetails{
			PqPskIdentity: fakeEncode(bytes.Repeat([]byte{0x33}, cert.PqPskBindingLen), 12345, 0),
		},
	}
	b, err := ack.Marshal()
	require.NoError(t, err)
	lhh.HandleRequest(hostileUdp, []netip.Addr{hostileVpn}, b, &testEncWriter{})

	// No gossip stored for the hostile peer.
	assert.Equal(t, uint16(0), lh.LookupGossipedPQProviderPort(hostileVpn),
		"non-lighthouse ack source must be ignored")
}

// TestLighthouse_LookupGossipedDiscoveryPort exercises the by-vpnAddr
// accessor that the Coordinator consumes for the TCP-discovery side of
// the heterogeneous-port fix: a HostUpdate carrying DiscoveryPort=51841
// should be retrievable by vpnAddr, and unknown / nil-receiver inputs
// must return 0 without crashing. Mirrors
// TestLighthouse_LookupGossipedPQProviderPort.
func TestLighthouse_LookupGossipedDiscoveryPort(t *testing.T) {
	l := test.NewLogger()

	myVpnNet := netip.MustParsePrefix("10.128.0.1/24")
	nt := new(bart.Lite)
	nt.Insert(myVpnNet)
	cs := &CertState{
		myVpnNetworks:      []netip.Prefix{myVpnNet},
		myVpnNetworksTable: nt,
	}

	c := config.NewC(l)
	c.Settings["lighthouse"] = map[string]any{"am_lighthouse": true}
	c.Settings["listen"] = map[string]any{"port": 4242}

	lh, err := NewLightHouseFromConfig(t.Context(), l, c, cs, nil, nil)
	require.NoError(t, err)
	lh.SetPQIdentityCodec(fakeCodec{})
	lh.ifce = &mockEncWriter{}
	lhh := lh.NewRequestHandler()

	peerVpn := netip.MustParseAddr("10.128.0.42")
	peerUdp := netip.MustParseAddrPort("198.51.100.42:4242")

	// Peer gossips an asymmetric rosenpass-discovery port.
	upd := &NebulaMeta{
		Type: NebulaMeta_HostUpdateNotification,
		Details: &NebulaMetaDetails{
			VpnAddr: netAddrToProtoAddr(peerVpn),
			V4AddrPorts: []*V4AddrPort{
				netAddrToProtoV4AddrPort(peerUdp.Addr(), peerUdp.Port()),
			},
			PqPskIdentity: fakeEncode(make([]byte, cert.PqPskBindingLen), 0, 51841),
		},
	}
	b, err := upd.Marshal()
	require.NoError(t, err)
	lhh.HandleRequest(peerUdp, []netip.Addr{peerVpn}, b, &testEncWriter{})

	require.Equal(t, uint16(51841), lh.LookupGossipedDiscoveryPort(peerVpn))

	// Unrelated vpnAddr returns 0.
	require.Equal(t, uint16(0), lh.LookupGossipedDiscoveryPort(netip.MustParseAddr("10.128.0.99")))

	// Invalid vpnAddr returns 0.
	require.Equal(t, uint16(0), lh.LookupGossipedDiscoveryPort(netip.Addr{}))

	// Nil receiver is safe.
	var nilLh *LightHouse
	require.Equal(t, uint16(0), nilLh.LookupGossipedDiscoveryPort(peerVpn))
}

// TestLighthouse_GossipChangedCallbackFiresOnDiscoveryPortChange pins
// the discovery-port-change fire signal: the callback (today wired
// into the embedded Coordinator's re-notify chain) must fire on first
// non-zero discoveryPort, NOT fire on duplicate, and fire again on a
// new discoveryPort. Without this, peers that gossip discovery-port
// LATE (the common case where HostUpdate arrives after the first
// handshake) would never re-trigger pubkey fetch at the corrected
// TCP port. Same shape as the existing RP-port test but flips
// DiscoveryPort instead of RosenpassPort.
func TestLighthouse_GossipChangedCallbackFiresOnDiscoveryPortChange(t *testing.T) {
	l := test.NewLogger()

	myVpnNet := netip.MustParsePrefix("10.128.0.1/24")
	nt := new(bart.Lite)
	nt.Insert(myVpnNet)
	cs := &CertState{
		myVpnNetworks:      []netip.Prefix{myVpnNet},
		myVpnNetworksTable: nt,
	}

	c := config.NewC(l)
	c.Settings["lighthouse"] = map[string]any{"am_lighthouse": true}
	c.Settings["listen"] = map[string]any{"port": 4242}

	lh, err := NewLightHouseFromConfig(t.Context(), l, c, cs, nil, nil)
	require.NoError(t, err)
	lh.SetPQIdentityCodec(fakeCodec{})
	lh.ifce = &mockEncWriter{}
	lhh := lh.NewRequestHandler()

	var fired []netip.Addr
	lh.SetGossipChangedCallback(func(addr netip.Addr) {
		fired = append(fired, addr)
	})

	peerVpn := netip.MustParseAddr("10.128.0.42")
	peerUdp := netip.MustParseAddrPort("198.51.100.42:4242")

	sendUpdate := func(disc uint16) {
		upd := &NebulaMeta{
			Type: NebulaMeta_HostUpdateNotification,
			Details: &NebulaMetaDetails{
				VpnAddr: netAddrToProtoAddr(peerVpn),
				V4AddrPorts: []*V4AddrPort{
					netAddrToProtoV4AddrPort(peerUdp.Addr(), peerUdp.Port()),
				},
				PqPskIdentity: fakeEncode(make([]byte, cert.PqPskBindingLen), 0, disc),
			},
		}
		b, err := upd.Marshal()
		require.NoError(t, err)
		lhh.HandleRequest(peerUdp, []netip.Addr{peerVpn}, b, &testEncWriter{})
	}

	sendUpdate(51841)
	require.Equal(t, []netip.Addr{peerVpn}, fired,
		"first non-zero gossiped discoveryPort should fire the callback")

	sendUpdate(51841)
	require.Equal(t, []netip.Addr{peerVpn}, fired,
		"identical discoveryPort re-gossip must not refire the callback")

	sendUpdate(51842)
	require.Equal(t, []netip.Addr{peerVpn, peerVpn}, fired,
		"discoveryPort-change gossip must refire the callback")

	sendUpdate(0)
	require.Equal(t, []netip.Addr{peerVpn, peerVpn}, fired,
		"discoveryPort=0 (unset) must not refire the callback")
	require.Equal(t, uint16(51842), lh.LookupGossipedDiscoveryPort(peerVpn))
}

// TestLighthouse_GossipSendIncludesDiscoveryPort verifies the
// send path populates DiscoveryPort in outbound HostUpdates when the
// local node is configured with pq.discovery_port. Mirrors
// TestLighthouse_GossipSendIncludesOwnHash + the RP-port assertion in
// it, but pulls the gossip field this commit added.
func TestLighthouse_GossipSendIncludesDiscoveryPort(t *testing.T) {
	l := test.NewLogger()

	myVpnNet := netip.MustParsePrefix("10.128.0.1/24")
	nt := new(bart.Lite)
	nt.Insert(myVpnNet)

	c := config.NewC(l)
	c.Settings["lighthouse"] = map[string]any{
		"hosts":           []any{"10.128.0.99"},
		"advertise_addrs": []any{"1.2.3.4:4242"},
	}
	c.Settings["static_host_map"] = map[string]any{
		"10.128.0.99": []any{"203.0.113.99:4242"},
	}
	c.Settings["pq"] = map[string]any{
		"rosenpass_port": 51820,
		"discovery_port": 51840,
	}
	c.Settings["listen"] = map[string]any{"port": 4242}

	myRPHash := bytes.Repeat([]byte{0xab}, cert.PqPskBindingLen)
	myV2 := &gossipStubCert{
		version:  cert.Version2,
		rpHash:   myRPHash,
		networks: []netip.Prefix{myVpnNet},
	}
	cs := &CertState{
		myVpnNetworks:      []netip.Prefix{myVpnNet},
		myVpnNetworksTable: nt,
		initiatingVersion:  cert.Version2,
		v2Cert:             myV2,
	}

	lh, err := NewLightHouseFromConfig(t.Context(), l, c, cs, nil, nil)
	require.NoError(t, err)
	lh.SetPQIdentityCodec(fakeCodec{})

	cap := &gossipSendCaptureEncWriter{certState: cs}
	lh.ifce = cap

	lh.SendUpdate()

	require.NotNil(t, cap.lastDetails, "no HostUpdate was sent")
	assert.Equal(t, uint32(51820), cap.lastDetails.RosenpassPort,
		"send path must include the configured rosenpass port")
	assert.Equal(t, uint32(51840), cap.lastDetails.DiscoveryPort,
		"send path must include the configured discovery port")
}

// TestLighthouse_HostUpdateAckPiggybacksDiscoveryPort verifies the
// lighthouse's HostUpdateNotificationAck carries the local
// DiscoveryPort gossip — closing the vice-versa leg for the TCP
// discovery port the same way TestLighthouse_HostUpdateAckPiggybacksGossip
// did for the UDP rosenpass port. Without this, non-lighthouse peers
// have no channel to learn the lighthouse's discovery_port and would
// stay pinned to their own cfg.DiscoveryPort fallback for the
// lifetime of the tunnel — the HTTP pubkey fetch would hit the wrong
// TCP port and FetchPubkey would fail with connection-refused.
func TestLighthouse_HostUpdateAckPiggybacksDiscoveryPort(t *testing.T) {
	l := test.NewLogger()

	myVpnNet := netip.MustParsePrefix("10.128.0.1/24")
	nt := new(bart.Lite)
	nt.Insert(myVpnNet)

	c := config.NewC(l)
	c.Settings["lighthouse"] = map[string]any{"am_lighthouse": true}
	c.Settings["listen"] = map[string]any{"port": 4242}
	c.Settings["pq"] = map[string]any{
		"rosenpass_port": 51823,
		"discovery_port": 51843,
	}

	myRPHash := bytes.Repeat([]byte{0xde}, cert.PqPskBindingLen)
	myV2 := &gossipStubCert{
		version:  cert.Version2,
		rpHash:   myRPHash,
		networks: []netip.Prefix{myVpnNet},
	}
	cs := &CertState{
		myVpnNetworks:      []netip.Prefix{myVpnNet},
		myVpnNetworksTable: nt,
		initiatingVersion:  cert.Version2,
		v2Cert:             myV2,
	}

	lh, err := NewLightHouseFromConfig(t.Context(), l, c, cs, nil, nil)
	require.NoError(t, err)
	lh.SetPQIdentityCodec(fakeCodec{})
	lh.ifce = &gossipSendCaptureEncWriter{certState: cs}
	lhh := lh.NewRequestHandler()

	peerVpn := netip.MustParseAddr("10.128.0.42")
	peerUdp := netip.MustParseAddrPort("198.51.100.42:4242")
	upd := &NebulaMeta{
		Type: NebulaMeta_HostUpdateNotification,
		Details: &NebulaMetaDetails{
			VpnAddr: netAddrToProtoAddr(peerVpn),
			V4AddrPorts: []*V4AddrPort{
				netAddrToProtoV4AddrPort(peerUdp.Addr(), peerUdp.Port()),
			},
		},
	}
	b, err := upd.Marshal()
	require.NoError(t, err)

	ackCap := &gossipSendCaptureEncWriter{certState: cs}
	lhh.HandleRequest(peerUdp, []netip.Addr{peerVpn}, b, ackCap)

	require.NotNil(t, ackCap.lastDetails, "no ack was sent")
	assert.Equal(t, uint32(51823), ackCap.lastDetails.RosenpassPort,
		"ack must include lighthouse's rosenpass port")
	assert.Equal(t, uint32(51843), ackCap.lastDetails.DiscoveryPort,
		"ack must include lighthouse's discovery port")
}

// TestLighthouse_HostUpdateAckRecvStoresDiscoveryPort mirrors the
// RP-port equivalent on the receive side: when a non-lighthouse peer
// receives a HostUpdateNotificationAck carrying a DiscoveryPort
// piggyback from one of its configured lighthouses, it must store
// the port in the lighthouse's RemoteList AND fire the gossip-changed
// callback so the embedded Coordinator can re-fetch the pubkey at
// the corrected TCP port.
func TestLighthouse_HostUpdateAckRecvStoresDiscoveryPort(t *testing.T) {
	l := test.NewLogger()

	myVpnNet := netip.MustParsePrefix("10.128.0.1/24")
	nt := new(bart.Lite)
	nt.Insert(myVpnNet)
	cs := &CertState{
		myVpnNetworks:      []netip.Prefix{myVpnNet},
		myVpnNetworksTable: nt,
	}

	c := config.NewC(l)
	c.Settings["lighthouse"] = map[string]any{
		"am_lighthouse": false,
		"hosts":         []any{"10.128.0.99"},
	}
	c.Settings["static_host_map"] = map[string]any{
		"10.128.0.99": []any{"203.0.113.99:4242"},
	}
	c.Settings["listen"] = map[string]any{"port": 4242}

	lh, err := NewLightHouseFromConfig(t.Context(), l, c, cs, nil, nil)
	require.NoError(t, err)
	lh.SetPQIdentityCodec(fakeCodec{})
	lh.ifce = &mockEncWriter{}
	lhh := lh.NewRequestHandler()

	var fired []netip.Addr
	lh.SetGossipChangedCallback(func(addr netip.Addr) {
		fired = append(fired, addr)
	})

	lhVpn := netip.MustParseAddr("10.128.0.99")
	lhUdp := netip.MustParseAddrPort("203.0.113.99:4242")

	// Lighthouse-side ack carries DiscoveryPort piggyback (no RP port
	// in this test, to make sure DiscoveryPort alone is enough to
	// store gossip + fire the callback).
	ack := &NebulaMeta{
		Type: NebulaMeta_HostUpdateNotificationAck,
		Details: &NebulaMetaDetails{
			PqPskIdentity: fakeEncode(make([]byte, cert.PqPskBindingLen), 0, 51843),
		},
	}
	b, err := ack.Marshal()
	require.NoError(t, err)
	lhh.HandleRequest(lhUdp, []netip.Addr{lhVpn}, b, &testEncWriter{})

	assert.Equal(t, uint16(51843), lh.LookupGossipedDiscoveryPort(lhVpn),
		"client must store lighthouse's gossiped discovery port from the ack")
	require.Equal(t, []netip.Addr{lhVpn}, fired,
		"first non-zero gossiped discoveryPort from ack must fire the callback")

	// Re-receive: callback must not fire on duplicate.
	lhh.HandleRequest(lhUdp, []netip.Addr{lhVpn}, b, &testEncWriter{})
	assert.Equal(t, []netip.Addr{lhVpn}, fired,
		"duplicate ack must not refire the callback")
}

// gossipSendCaptureEncWriter is a write-only EncWriter that captures
// the most recent NebulaMeta sent via SendMessageToVpnAddr. Used to
// inspect SendUpdate's wire payload without standing up a real
// transport.
type gossipSendCaptureEncWriter struct {
	certState   *CertState
	lastDetails *NebulaMetaDetails
}

func (c *gossipSendCaptureEncWriter) SendVia(*HostInfo, *Relay, []byte, []byte, []byte, bool) {
}
func (c *gossipSendCaptureEncWriter) Handshake(netip.Addr) {}
func (c *gossipSendCaptureEncWriter) SendMessageToHostInfo(header.MessageType, header.MessageSubType, *HostInfo, []byte, []byte, []byte) {
}
func (c *gossipSendCaptureEncWriter) SendMessageToVpnAddr(_ header.MessageType, _ header.MessageSubType, _ netip.Addr, p, _, _ []byte) {
	msg := &NebulaMeta{}
	if err := msg.Unmarshal(p); err != nil {
		panic(err)
	}
	// We capture both HostUpdate (outbound from SendUpdate, used by
	// TestLighthouse_GossipSendIncludesOwnHash) AND
	// HostUpdateNotificationAck (lighthouse-side reply, used by
	// TestLighthouse_HostUpdateAckPiggybacksGossip) so the same
	// fixture can probe either direction by triggering the path it
	// wants and reading lastDetails.
	switch msg.Type {
	case NebulaMeta_HostUpdateNotification, NebulaMeta_HostUpdateNotificationAck:
		// Copy details to insulate from later resetMeta calls.
		d := *msg.Details
		c.lastDetails = &d
	}
}
func (c *gossipSendCaptureEncWriter) GetHostInfo(netip.Addr) *HostInfo { return nil }
func (c *gossipSendCaptureEncWriter) GetCertState() *CertState         { return c.certState }

// gossipStubCert is a minimal cert.Certificate test double for the
// lighthouse gossip path. Only Version(), Networks() and
// PqPskBinding() are consulted by the code under test;
// every other method returns a zero value.
type gossipStubCert struct {
	version  cert.Version
	rpHash   []byte
	networks []netip.Prefix
}

func (s *gossipStubCert) Version() cert.Version                     { return s.version }
func (s *gossipStubCert) Name() string                              { return "" }
func (s *gossipStubCert) Networks() []netip.Prefix                  { return s.networks }
func (s *gossipStubCert) UnsafeNetworks() []netip.Prefix            { return nil }
func (s *gossipStubCert) Groups() []string                          { return nil }
func (s *gossipStubCert) IsCA() bool                                { return false }
func (s *gossipStubCert) NotBefore() time.Time                      { return time.Time{} }
func (s *gossipStubCert) NotAfter() time.Time                       { return time.Time{} }
func (s *gossipStubCert) Issuer() string                            { return "" }
func (s *gossipStubCert) PublicKey() []byte                         { return nil }
func (s *gossipStubCert) MarshalPublicKeyPEM() []byte               { return nil }
func (s *gossipStubCert) Curve() cert.Curve                         { return cert.Curve_CURVE25519 }
func (s *gossipStubCert) PqPskBinding() []byte                      { return s.rpHash }
func (s *gossipStubCert) Signature() []byte                         { return nil }
func (s *gossipStubCert) CheckSignature([]byte) bool                { return false }
func (s *gossipStubCert) Fingerprint() (string, error)              { return "", nil }
func (s *gossipStubCert) Expired(time.Time) bool                    { return false }
func (s *gossipStubCert) VerifyPrivateKey(cert.Curve, []byte) error { return nil }
func (s *gossipStubCert) Marshal() ([]byte, error)                  { return nil, nil }
func (s *gossipStubCert) MarshalForHandshakes() ([]byte, error)     { return nil, nil }
func (s *gossipStubCert) MarshalPEM() ([]byte, error)               { return nil, nil }
func (s *gossipStubCert) MarshalJSON() ([]byte, error)              { return nil, nil }
func (s *gossipStubCert) String() string                            { return "" }
func (s *gossipStubCert) Copy() cert.Certificate                    { c := *s; return &c }
