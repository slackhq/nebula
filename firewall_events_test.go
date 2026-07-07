package nebula

import (
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/gaissmai/bart"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/firewall"
	"github.com/slackhq/nebula/firewall/events"
	"github.com/slackhq/nebula/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// recordingReporter captures every event fired against it. Its methods take
// the conntrack lock implicitly (via the firewall code path that invokes
// them), so we synchronize accumulator mutations with a small mutex to keep
// the race detector happy across goroutines in case a test introduces any.
type recordingReporter struct {
	mu      sync.Mutex
	drops   []recordedDrop
	creates []recordedCreate
	evicts  []recordedEvict
	reloads []recordedReload
}

type recordedDrop struct {
	incoming     bool
	reason       events.DropReason
	remote       netip.Addr
	local        netip.Addr
	peerName     string
	rulesVersion uint16
	ctx          firewall.PacketContext
}

type recordedCreate struct {
	incoming     bool
	remote       netip.Addr
	local        netip.Addr
	peerName     string
	rulesVersion uint16
	ctx          firewall.PacketContext
}

type recordedEvict struct {
	incoming     bool
	remote       netip.Addr
	local        netip.Addr
	rulesVersion uint16
	expired      bool
}

type recordedReload struct {
	oldVersion uint16
	newVersion uint16
}

func (r *recordingReporter) ReportDrop(e events.DropEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()
	name := ""
	if e.PeerCert != nil && e.PeerCert.Certificate != nil {
		name = e.PeerCert.Certificate.Name()
	}
	r.drops = append(r.drops, recordedDrop{
		incoming:     e.Incoming,
		reason:       e.Reason,
		remote:       e.Packet.RemoteAddr,
		local:        e.Packet.LocalAddr,
		peerName:     name,
		rulesVersion: e.RulesVersion,
		ctx:          e.Context,
	})
}

func (r *recordingReporter) ReportFlowCreate(e events.FlowCreateEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()
	name := ""
	if e.PeerCert != nil && e.PeerCert.Certificate != nil {
		name = e.PeerCert.Certificate.Name()
	}
	r.creates = append(r.creates, recordedCreate{
		incoming:     e.Incoming,
		remote:       e.Packet.RemoteAddr,
		local:        e.Packet.LocalAddr,
		peerName:     name,
		rulesVersion: e.RulesVersion,
		ctx:          e.Context,
	})
}

func (r *recordingReporter) ReportFlowEvict(e events.FlowEvictEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.evicts = append(r.evicts, recordedEvict{
		incoming:     e.Incoming,
		remote:       e.Packet.RemoteAddr,
		local:        e.Packet.LocalAddr,
		rulesVersion: e.RulesVersion,
		expired:      e.Expired,
	})
}

func (r *recordingReporter) ReportRulesReload(e events.RulesReloadEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.reloads = append(r.reloads, recordedReload{
		oldVersion: e.OldVersion,
		newVersion: e.NewVersion,
	})
}

// eventFixture builds a Firewall wired to a Control plus a packet/hostinfo
// pair that a test can reuse. By default the ruleset allows the packet;
// callers mutate fw / p / h as needed before invoking Drop.
type eventFixture struct {
	ctl *Control
	fw  *Firewall
	p   firewall.Packet
	h   *HostInfo
	cp  *cert.CAPool
}

func newEventFixture(t *testing.T) *eventFixture {
	t.Helper()
	l := test.NewLogger()

	// myVpnNetworksTable covers our single peer address so buildNetworks takes
	// the "simple case" path (h.networks stays nil); tests that want a populated
	// BART table overwrite h.networks directly.
	vpnNetworks := new(bart.Lite)
	vpnNetworks.Insert(netip.MustParsePrefix("1.2.3.0/24"))

	// Use the same cert for "peer" and "local" endpoints, matching the
	// TestFirewall_Drop fixture style: LocalAddr == RemoteAddr == peer vpn addr.
	c := &dummyCert{
		name:     "host1",
		networks: []netip.Prefix{netip.MustParsePrefix("1.2.3.4/24")},
		groups:   []string{"default-group"},
		issuer:   "signer-shasum",
	}
	h := &HostInfo{
		ConnectionState: &ConnectionState{
			peerCert: &cert.CachedCertificate{
				Certificate:    c,
				InvertedGroups: map[string]struct{}{"default-group": {}},
			},
		},
		vpnAddrs: []netip.Addr{netip.MustParseAddr("1.2.3.4")},
	}
	h.buildNetworks(vpnNetworks, c)

	fw := NewFirewall(l, time.Minute, time.Minute, time.Minute, c)
	require.NoError(t, fw.AddRule(true, firewall.ProtoAny, 0, 0, []string{"any"}, "", "", "", "", ""))
	require.NoError(t, fw.AddRule(false, firewall.ProtoAny, 0, 0, []string{"any"}, "", "", "", "", ""))

	ctl := &Control{
		f: &Interface{firewall: fw},
		l: l,
	}

	return &eventFixture{
		ctl: ctl,
		fw:  fw,
		p: firewall.Packet{
			LocalAddr:  netip.MustParseAddr("1.2.3.4"),
			RemoteAddr: netip.MustParseAddr("1.2.3.4"),
			LocalPort:  10,
			RemotePort: 90,
			Protocol:   firewall.ProtoUDP,
		},
		h:  h,
		cp: cert.NewCAPool(),
	}
}

// firewall() returns the currently-installed firewall. Needed because
// SetFirewallEventReporter replaces it via shallow-copy swap.
func (f *eventFixture) firewall() *Firewall {
	return f.ctl.f.firewall
}

func TestEvents_ReportDrop_InvalidRemoteIP(t *testing.T) {
	f := newEventFixture(t)
	r := &recordingReporter{}
	f.ctl.SetFirewallEventReporter(r)

	// Packet to an address not in the cert's networks.
	f.p.RemoteAddr = netip.MustParseAddr("9.9.9.9")
	assert.Equal(t, ErrInvalidRemoteIP, f.firewall().Drop(f.p, firewall.PacketContext{}, false, f.h, f.cp, nil))

	require.Len(t, r.drops, 1)
	assert.Equal(t, events.DropInvalidRemoteIP, r.drops[0].reason)
	assert.False(t, r.drops[0].incoming)
	assert.Equal(t, "host1", r.drops[0].peerName)
	assert.Empty(t, r.creates)
	assert.Empty(t, r.evicts)
}

func TestEvents_ReportDrop_InvalidLocalIP(t *testing.T) {
	f := newEventFixture(t)
	r := &recordingReporter{}
	f.ctl.SetFirewallEventReporter(r)

	// LocalAddr outside our routable networks.
	f.p.LocalAddr = netip.MustParseAddr("9.9.9.9")
	assert.Equal(t, ErrInvalidLocalIP, f.firewall().Drop(f.p, firewall.PacketContext{}, true, f.h, f.cp, nil))

	require.Len(t, r.drops, 1)
	assert.Equal(t, events.DropInvalidLocalIP, r.drops[0].reason)
	assert.True(t, r.drops[0].incoming)
}

func TestEvents_ReportDrop_NoMatchingRule(t *testing.T) {
	f := newEventFixture(t)
	// Reset to a firewall with no matching rule.
	l := test.NewLogger()
	fw := NewFirewall(l, time.Minute, time.Minute, time.Minute, f.h.ConnectionState.peerCert.Certificate)
	// Rule that won't match (group not in peer's groups).
	require.NoError(t, fw.AddRule(true, firewall.ProtoAny, 0, 0, []string{"nope"}, "", "", "", "", ""))
	require.NoError(t, fw.AddRule(false, firewall.ProtoAny, 0, 0, []string{"nope"}, "", "", "", "", ""))
	f.ctl.f.firewall = fw

	r := &recordingReporter{}
	f.ctl.SetFirewallEventReporter(r)

	assert.Equal(t, ErrNoMatchingRule, f.firewall().Drop(f.p, firewall.PacketContext{}, true, f.h, f.cp, nil))
	require.Len(t, r.drops, 1)
	assert.Equal(t, events.DropNoMatchingRule, r.drops[0].reason)
}

func TestEvents_ReportDrop_PeerRejected(t *testing.T) {
	f := newEventFixture(t)
	// Re-classify the remote as VPNPeer so it triggers DropPeerRejected.
	f.h.networks = new(bart.Table[NetworkType])
	f.h.networks.Insert(netip.MustParsePrefix("1.2.3.0/24"), NetworkTypeVPNPeer)

	r := &recordingReporter{}
	f.ctl.SetFirewallEventReporter(r)

	assert.Equal(t, ErrPeerRejected, f.firewall().Drop(f.p, firewall.PacketContext{}, true, f.h, f.cp, nil))
	require.Len(t, r.drops, 1)
	assert.Equal(t, events.DropPeerRejected, r.drops[0].reason)
}

func TestEvents_ReportDrop_UnknownNetwork(t *testing.T) {
	f := newEventFixture(t)
	// Insert an unrecognized NetworkType value to hit the default branch.
	f.h.networks = new(bart.Table[NetworkType])
	f.h.networks.Insert(netip.MustParsePrefix("1.2.3.0/24"), NetworkTypeUnknown)

	r := &recordingReporter{}
	f.ctl.SetFirewallEventReporter(r)

	assert.Equal(t, ErrUnknownNetworkType, f.firewall().Drop(f.p, firewall.PacketContext{}, true, f.h, f.cp, nil))
	require.Len(t, r.drops, 1)
	assert.Equal(t, events.DropUnknownNetwork, r.drops[0].reason)
}

func TestEvents_ReportFlowCreate_OnceOnly(t *testing.T) {
	f := newEventFixture(t)
	r := &recordingReporter{}
	f.ctl.SetFirewallEventReporter(r)

	// First allowed packet creates the conntrack entry.
	require.NoError(t, f.firewall().Drop(f.p, firewall.PacketContext{}, true, f.h, f.cp, nil))
	// Second matching packet on the same tuple is short-circuited by conntrack
	// and must not fire another FlowCreate.
	require.NoError(t, f.firewall().Drop(f.p, firewall.PacketContext{}, true, f.h, f.cp, nil))

	require.Len(t, r.creates, 1)
	assert.True(t, r.creates[0].incoming)
	assert.Equal(t, f.p.RemoteAddr, r.creates[0].remote)
	assert.Empty(t, r.drops)
}

func TestEvents_ReportFlowEvict_OnReloadPurge(t *testing.T) {
	f := newEventFixture(t)
	r := &recordingReporter{}
	f.ctl.SetFirewallEventReporter(r)

	// Create a flow under the current rules.
	require.NoError(t, f.firewall().Drop(f.p, firewall.PacketContext{}, true, f.h, f.cp, nil))
	require.Len(t, r.creates, 1)

	// Simulate a reload that produces rules the existing flow no longer
	// matches. Bump rulesVersion and replace InRules with an empty table so
	// revalidation fails.
	fw := f.firewall()
	fw.Conntrack.Lock()
	fw.rulesVersion++
	fw.InRules = newFirewallTable()
	fw.Conntrack.Unlock()

	// Next packet triggers re-validation, which fails and evicts the entry.
	err := fw.Drop(f.p, firewall.PacketContext{}, true, f.h, f.cp, nil)
	assert.Equal(t, ErrNoMatchingRule, err)

	require.Len(t, r.evicts, 1)
	assert.False(t, r.evicts[0].expired, "evict from reload purge is not expiration")
	assert.True(t, r.evicts[0].incoming)
}

func TestEvents_ReportFlowEvict_OnTimeout(t *testing.T) {
	f := newEventFixture(t)
	r := &recordingReporter{}
	f.ctl.SetFirewallEventReporter(r)

	require.NoError(t, f.firewall().Drop(f.p, firewall.PacketContext{}, true, f.h, f.cp, nil))
	require.Len(t, r.creates, 1)

	// Force expiration by rewinding the entry's deadline.
	fw := f.firewall()
	fw.Conntrack.Lock()
	c := fw.Conntrack.Conns[f.p]
	require.NotNil(t, c)
	c.Expires = time.Now().Add(-time.Hour)
	fw.evict(f.p)
	fw.Conntrack.Unlock()

	require.Len(t, r.evicts, 1)
	assert.True(t, r.evicts[0].expired)
}

func TestEvents_SetNil_Clears(t *testing.T) {
	f := newEventFixture(t)
	r := &recordingReporter{}
	f.ctl.SetFirewallEventReporter(r)
	require.NoError(t, f.firewall().Drop(f.p, firewall.PacketContext{}, true, f.h, f.cp, nil))
	require.Len(t, r.creates, 1)

	f.ctl.SetFirewallEventReporter(nil)
	resetConntrack(f.firewall())
	require.NoError(t, f.firewall().Drop(f.p, firewall.PacketContext{}, true, f.h, f.cp, nil))
	// No second create should be recorded.
	assert.Len(t, r.creates, 1)
}

func TestEvents_ReporterSurvivesSwap(t *testing.T) {
	f := newEventFixture(t)
	r := &recordingReporter{}
	f.ctl.SetFirewallEventReporter(r)

	// Simulate a reload by swapping in a fresh Firewall that carries the
	// reporter forward. Mirrors what reloadFirewall does with the shared
	// conntrack pointer.
	l := test.NewLogger()
	oldFw := f.firewall()
	newFw := NewFirewall(l, time.Minute, time.Minute, time.Minute, f.h.ConnectionState.peerCert.Certificate)
	require.NoError(t, newFw.AddRule(true, firewall.ProtoAny, 0, 0, []string{"any"}, "", "", "", "", ""))
	require.NoError(t, newFw.AddRule(false, firewall.ProtoAny, 0, 0, []string{"any"}, "", "", "", "", ""))
	newFw.Conntrack = oldFw.Conntrack
	newFw.rulesVersion = oldFw.rulesVersion + 1
	newFw.reporter = oldFw.reporter
	f.ctl.f.firewall = newFw
	newFw.reportRulesReload(oldFw.rulesVersion, newFw.rulesVersion)

	require.Len(t, r.reloads, 1)
	assert.Equal(t, oldFw.rulesVersion, r.reloads[0].oldVersion)
	assert.Equal(t, newFw.rulesVersion, r.reloads[0].newVersion)

	// Events on the new firewall should still reach the same reporter.
	require.NoError(t, newFw.Drop(f.p, firewall.PacketContext{}, true, f.h, f.cp, nil))
	require.Len(t, r.creates, 1)
	assert.Equal(t, newFw.rulesVersion, r.creates[0].rulesVersion)
}

func TestEvents_InstallDoesNotMutateOldFirewall(t *testing.T) {
	f := newEventFixture(t)
	before := f.firewall()

	r := &recordingReporter{}
	f.ctl.SetFirewallEventReporter(r)

	after := f.firewall()
	assert.NotSame(t, before, after, "SetFirewallEventReporter must replace the Firewall pointer")
	assert.Nil(t, before.reporter, "the pre-install Firewall must remain untouched")
	assert.NotNil(t, after.reporter)
}

// --- PacketContext parse tests --------------------------------------------

func mustSerialize(t *testing.T, lrs ...gopacket.SerializableLayer) []byte {
	t.Helper()
	buf := gopacket.NewSerializeBuffer()
	opt := gopacket.SerializeOptions{ComputeChecksums: false, FixLengths: true}
	require.NoError(t, gopacket.SerializeLayers(buf, opt, lrs...))
	return buf.Bytes()
}

func TestPacketContext_IPv4_TCPFlags(t *testing.T) {
	ip := &layers.IPv4{
		Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP,
		SrcIP: net.IPv4(10, 0, 0, 1), DstIP: net.IPv4(10, 0, 0, 2),
	}
	tcp := &layers.TCP{SrcPort: 1234, DstPort: 80, SYN: true, ACK: true}
	require.NoError(t, tcp.SetNetworkLayerForChecksum(ip))
	data := mustSerialize(t, ip, tcp, gopacket.Payload([]byte("hello")))

	var fp firewall.Packet
	var ctx firewall.PacketContext
	require.NoError(t, newPacket(data, true, &fp, &ctx))

	assert.Equal(t, uint8(firewall.ProtoTCP), fp.Protocol)
	// SYN (0x02) + ACK (0x10) = 0x12
	assert.Equal(t, uint8(0x12), ctx.TCPFlags)
	assert.Equal(t, uint16(len(data)), ctx.Length)
	assert.Equal(t, uint8(0), ctx.ICMPType)
	assert.Equal(t, uint8(0), ctx.ICMPCode)
}

func TestPacketContext_IPv4_ICMPTypeCode(t *testing.T) {
	ip := &layers.IPv4{
		Version: 4, TTL: 64, Protocol: layers.IPProtocolICMPv4,
		SrcIP: net.IPv4(10, 0, 0, 1), DstIP: net.IPv4(10, 0, 0, 2),
	}
	// Destination Unreachable, code 3 (port unreachable)
	icmp := &layers.ICMPv4{
		TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeDestinationUnreachable, layers.ICMPv4CodePort),
	}
	data := mustSerialize(t, ip, icmp, gopacket.Payload([]byte{0, 0, 0, 0}))

	var fp firewall.Packet
	var ctx firewall.PacketContext
	require.NoError(t, newPacket(data, true, &fp, &ctx))

	assert.Equal(t, uint8(firewall.ProtoICMP), fp.Protocol)
	assert.Equal(t, uint8(layers.ICMPv4TypeDestinationUnreachable), ctx.ICMPType)
	assert.Equal(t, uint8(layers.ICMPv4CodePort), ctx.ICMPCode)
	assert.Equal(t, uint16(len(data)), ctx.Length)
	assert.Equal(t, uint8(0), ctx.TCPFlags)
}

func TestPacketContext_IPv4_UDPLengthOnly(t *testing.T) {
	ip := &layers.IPv4{
		Version: 4, TTL: 64, Protocol: layers.IPProtocolUDP,
		SrcIP: net.IPv4(10, 0, 0, 1), DstIP: net.IPv4(10, 0, 0, 2),
	}
	udp := &layers.UDP{SrcPort: 1234, DstPort: 53}
	require.NoError(t, udp.SetNetworkLayerForChecksum(ip))
	data := mustSerialize(t, ip, udp, gopacket.Payload([]byte("query")))

	var fp firewall.Packet
	var ctx firewall.PacketContext
	require.NoError(t, newPacket(data, true, &fp, &ctx))

	assert.Equal(t, uint8(firewall.ProtoUDP), fp.Protocol)
	assert.Equal(t, uint16(len(data)), ctx.Length)
	assert.Zero(t, ctx.TCPFlags)
	assert.Zero(t, ctx.ICMPType)
	assert.Zero(t, ctx.ICMPCode)
}

func TestPacketContext_IPv6_TCPFlags(t *testing.T) {
	ip := &layers.IPv6{
		Version: 6, HopLimit: 64, NextHeader: layers.IPProtocolTCP,
		SrcIP: net.ParseIP("fd00::1"), DstIP: net.ParseIP("fd00::2"),
	}
	tcp := &layers.TCP{SrcPort: 1234, DstPort: 443, FIN: true, ACK: true}
	require.NoError(t, tcp.SetNetworkLayerForChecksum(ip))
	data := mustSerialize(t, ip, tcp, gopacket.Payload([]byte("bye")))

	var fp firewall.Packet
	var ctx firewall.PacketContext
	require.NoError(t, newPacket(data, true, &fp, &ctx))

	assert.Equal(t, uint8(firewall.ProtoTCP), fp.Protocol)
	// FIN (0x01) + ACK (0x10) = 0x11
	assert.Equal(t, uint8(0x11), ctx.TCPFlags)
	assert.Equal(t, uint16(len(data)), ctx.Length)
}

func TestPacketContext_IPv6_ICMPv6TypeCode(t *testing.T) {
	ip := &layers.IPv6{
		Version: 6, HopLimit: 64, NextHeader: layers.IPProtocolICMPv6,
		SrcIP: net.ParseIP("fd00::1"), DstIP: net.ParseIP("fd00::2"),
	}
	icmp := &layers.ICMPv6{
		TypeCode: layers.CreateICMPv6TypeCode(layers.ICMPv6TypeDestinationUnreachable, layers.ICMPv6CodePortUnreachable),
	}
	require.NoError(t, icmp.SetNetworkLayerForChecksum(ip))
	data := mustSerialize(t, ip, icmp, gopacket.Payload([]byte{0, 0, 0, 0, 0, 0, 0, 0}))

	var fp firewall.Packet
	var ctx firewall.PacketContext
	require.NoError(t, newPacket(data, true, &fp, &ctx))

	assert.Equal(t, uint8(firewall.ProtoICMPv6), fp.Protocol)
	assert.Equal(t, uint8(layers.ICMPv6TypeDestinationUnreachable), ctx.ICMPType)
	assert.Equal(t, uint8(layers.ICMPv6CodePortUnreachable), ctx.ICMPCode)
	assert.Equal(t, uint16(len(data)), ctx.Length)
}

// TestPacketContext_NilOK confirms a nil context pointer is accepted by
// newPacket (the hot path may elect not to pass one).
func TestPacketContext_NilOK(t *testing.T) {
	ip := &layers.IPv4{
		Version: 4, TTL: 64, Protocol: layers.IPProtocolUDP,
		SrcIP: net.IPv4(10, 0, 0, 1), DstIP: net.IPv4(10, 0, 0, 2),
	}
	udp := &layers.UDP{SrcPort: 1, DstPort: 2}
	require.NoError(t, udp.SetNetworkLayerForChecksum(ip))
	data := mustSerialize(t, ip, udp)

	var fp firewall.Packet
	require.NoError(t, newPacket(data, true, &fp, nil))
}

// TestPacketContext_FlowCreateCarriesContext exercises the full Drop -> addConn
// -> ReportFlowCreate path with a realistic TCP packet and confirms the
// context makes it into the reporter.
func TestPacketContext_FlowCreateCarriesContext(t *testing.T) {
	f := newEventFixture(t)
	r := &recordingReporter{}
	f.ctl.SetFirewallEventReporter(r)

	// Hand-construct a matching TCP packet.
	ctx := firewall.PacketContext{Length: 1500, TCPFlags: 0x12}
	p := f.p
	p.Protocol = firewall.ProtoTCP
	require.NoError(t, f.firewall().Drop(p, ctx, true, f.h, f.cp, nil))

	require.Len(t, r.creates, 1)
	assert.Equal(t, uint16(1500), r.creates[0].ctx.Length)
	assert.Equal(t, uint8(0x12), r.creates[0].ctx.TCPFlags)
}

// --- benchmarks ------------------------------------------------------------

// noopReporter is the cheapest possible reporter. Methods discard the event.
type noopReporter struct{}

func (noopReporter) ReportDrop(events.DropEvent)             {}
func (noopReporter) ReportFlowCreate(events.FlowCreateEvent) {}
func (noopReporter) ReportFlowEvict(events.FlowEvictEvent)   {}
func (noopReporter) ReportRulesReload(events.RulesReloadEvent) {
}

// bufferedReporter demonstrates a realistic zero-alloc reporter: each event
// is forwarded to a value-typed channel. The channel send is a memcpy into
// the channel's pre-allocated ring buffer -- no heap traffic. A background
// goroutine would drain these; the bench skips draining to keep the report
// path pure.
type bufferedReporter struct {
	drops  chan events.DropEvent
	flows  chan events.FlowCreateEvent
	evicts chan events.FlowEvictEvent
}

func newBufferedReporter(cap int) *bufferedReporter {
	return &bufferedReporter{
		drops:  make(chan events.DropEvent, cap),
		flows:  make(chan events.FlowCreateEvent, cap),
		evicts: make(chan events.FlowEvictEvent, cap),
	}
}

func (r *bufferedReporter) ReportDrop(e events.DropEvent) {
	select {
	case r.drops <- e:
	default:
	}
}

func (r *bufferedReporter) ReportFlowCreate(e events.FlowCreateEvent) {
	select {
	case r.flows <- e:
	default:
	}
}

func (r *bufferedReporter) ReportFlowEvict(e events.FlowEvictEvent) {
	select {
	case r.evicts <- e:
	default:
	}
}

func (r *bufferedReporter) ReportRulesReload(events.RulesReloadEvent) {}

// pointerReporter is the anti-pattern: it takes the address of the incoming
// event struct, which forces the callee-side copy onto the heap. Kept for
// comparison so we can see the alloc cost an unwary reporter would incur.
type pointerReporter struct {
	last *events.DropEvent
}

func (r *pointerReporter) ReportDrop(e events.DropEvent) {
	r.last = &e
}

func (r *pointerReporter) ReportFlowCreate(events.FlowCreateEvent) {}
func (r *pointerReporter) ReportFlowEvict(events.FlowEvictEvent)   {}
func (r *pointerReporter) ReportRulesReload(events.RulesReloadEvent) {
}

func newBenchFixture(b *testing.B) *eventFixture {
	b.Helper()
	l := test.NewLogger()

	vpnNetworks := new(bart.Lite)
	vpnNetworks.Insert(netip.MustParsePrefix("1.2.3.0/24"))

	c := &dummyCert{
		name:     "host1",
		networks: []netip.Prefix{netip.MustParsePrefix("1.2.3.4/24")},
		groups:   []string{"default-group"},
		issuer:   "signer-shasum",
	}
	h := &HostInfo{
		ConnectionState: &ConnectionState{
			peerCert: &cert.CachedCertificate{
				Certificate:    c,
				InvertedGroups: map[string]struct{}{"default-group": {}},
			},
		},
		vpnAddrs: []netip.Addr{netip.MustParseAddr("1.2.3.4")},
	}
	h.buildNetworks(vpnNetworks, c)

	fw := NewFirewall(l, time.Minute, time.Minute, time.Minute, c)
	// Inbound rule that matches our packet; outbound has no match so we can
	// also benchmark the no-rule drop path.
	if err := fw.AddRule(true, firewall.ProtoAny, 0, 0, []string{"any"}, "", "", "", "", ""); err != nil {
		b.Fatal(err)
	}

	ctl := &Control{f: &Interface{firewall: fw}, l: l}
	return &eventFixture{
		ctl: ctl,
		fw:  fw,
		p: firewall.Packet{
			LocalAddr:  netip.MustParseAddr("1.2.3.4"),
			RemoteAddr: netip.MustParseAddr("1.2.3.4"),
			LocalPort:  10,
			RemotePort: 90,
			Protocol:   firewall.ProtoUDP,
		},
		h:  h,
		cp: cert.NewCAPool(),
	}
}

// BenchmarkFirewallDropPath measures the cost of Firewall.Drop on a packet
// that reaches the no-matching-rule branch (the longest drop path). Compare
// reporter shapes:
//
//	nilReporter      -- no reporter installed (feature cost when off)
//	noopReporter     -- reporter installed, methods discard args (minimum on-cost)
//	bufferedReporter -- realistic zero-alloc reporter: value-typed channels
//	pointerReporter  -- anti-pattern that takes &composite-literal (allocates)
func BenchmarkFirewallDropPath(b *testing.B) {
	run := func(b *testing.B, install func(*Control)) {
		f := newBenchFixture(b)
		install(f.ctl)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = f.firewall().Drop(f.p, firewall.PacketContext{}, false, f.h, f.cp, nil)
		}
	}

	b.Run("nilReporter", func(b *testing.B) { run(b, func(*Control) {}) })
	b.Run("noopReporter", func(b *testing.B) {
		run(b, func(c *Control) { c.SetFirewallEventReporter(noopReporter{}) })
	})
	b.Run("bufferedReporter", func(b *testing.B) {
		run(b, func(c *Control) { c.SetFirewallEventReporter(newBufferedReporter(1024)) })
	})
	b.Run("pointerReporter", func(b *testing.B) {
		run(b, func(c *Control) { c.SetFirewallEventReporter(&pointerReporter{}) })
	})
}

// BenchmarkConntrackCreate measures Firewall.Drop for an allowed inbound
// packet on a fresh conntrack (so addConn fires each iteration).
func BenchmarkConntrackCreate(b *testing.B) {
	run := func(b *testing.B, install func(*Control)) {
		f := newBenchFixture(b)
		install(f.ctl)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			resetConntrack(f.firewall())
			_ = f.firewall().Drop(f.p, firewall.PacketContext{}, true, f.h, f.cp, nil)
		}
	}
	b.Run("nilReporter", func(b *testing.B) { run(b, func(*Control) {}) })
	b.Run("noopReporter", func(b *testing.B) {
		run(b, func(c *Control) { c.SetFirewallEventReporter(noopReporter{}) })
	})
	b.Run("bufferedReporter", func(b *testing.B) {
		run(b, func(c *Control) { c.SetFirewallEventReporter(newBufferedReporter(1024)) })
	})
}

// BenchmarkConntrackHit measures the hot path where a flow is already in
// conntrack and short-circuits rule evaluation. The reporter slot is checked
// only on create/evict, so this bench should show the reporter having zero
// impact regardless of install state.
func BenchmarkConntrackHit(b *testing.B) {
	b.Run("nilReporter", func(b *testing.B) {
		f := newBenchFixture(b)
		// Prime conntrack.
		require.NoError(b, f.firewall().Drop(f.p, firewall.PacketContext{}, true, f.h, f.cp, nil))
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = f.firewall().Drop(f.p, firewall.PacketContext{}, true, f.h, f.cp, nil)
		}
	})

	b.Run("noopReporter", func(b *testing.B) {
		f := newBenchFixture(b)
		f.ctl.SetFirewallEventReporter(noopReporter{})
		require.NoError(b, f.firewall().Drop(f.p, firewall.PacketContext{}, true, f.h, f.cp, nil))
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = f.firewall().Drop(f.p, firewall.PacketContext{}, true, f.h, f.cp, nil)
		}
	})
}
