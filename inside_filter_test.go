package nebula

import (
	"net/netip"
	"testing"
	"time"

	"github.com/gaissmai/bart"
	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/firewall"
	"github.com/slackhq/nebula/header"
	"github.com/slackhq/nebula/overlay/batch"
	"github.com/slackhq/nebula/overlay/overlaytest"
	"github.com/slackhq/nebula/overlay/tio"
	"github.com/slackhq/nebula/udp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newInsideFilterTestInterface(t *testing.T, allow bool) (*Interface, *HostInfo, *capturingTun) {
	t.Helper()
	local := netip.MustParseAddr("192.0.2.1")
	remote := netip.MustParseAddr("192.0.2.2")
	f, tun := newSelfForwardInterface(local)
	f.inside = overlaytest.NoopTun{}
	f.myVpnNetworksTable = &bart.Lite{}
	f.myVpnNetworksTable.Insert(netip.MustParsePrefix("192.0.2.0/24"))
	f.myBroadcastAddrsTable.Insert(netip.MustParsePrefix("192.0.2.255/32"))
	f.dropLocalBroadcast, f.dropMulticast = true, true
	localCert := &dummyCert{version: cert.Version1, networks: []netip.Prefix{netip.PrefixFrom(local, 24)}}
	peerCert := &dummyCert{version: cert.Version1, networks: []netip.Prefix{netip.PrefixFrom(remote, 24)}}
	f.firewall = NewFirewall(f.l, time.Minute, time.Minute, time.Minute, localCert)
	if allow {
		require.NoError(t, f.firewall.AddRule(false, firewall.ProtoAny, 0, 0, []string{"any"}, "", "", "", "", ""))
	}
	f.pki = &PKI{}
	f.pki.caPool.Store(cert.NewCAPool())
	f.hostMap = newHostMap(f.l)
	f.lightHouse = newTestLighthouse()
	f.lightHouse.amLighthouse = true // Keep destination lookup from probing other remotes.
	f.handshakeManager = NewHandshakeManager(f.l, f.hostMap, f.lightHouse, udp.NoopConn{}, defaultHandshakeConfig)
	f.handshakeManager.f = f
	f.connectionManager = &connectionManager{intf: f}
	h := &HostInfo{
		vpnAddrs: []netip.Addr{remote},
		ConnectionState: &ConnectionState{
			peerCert: &cert.CachedCertificate{Certificate: peerCert},
		},
	}
	f.hostMap.Hosts[remote] = h
	return f, h, tun
}

func TestFilterInsidePacket(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.1")
	remote := netip.MustParseAddr("192.0.2.2")
	for _, tt := range []struct {
		name   string
		packet []byte
		allow  bool
		reject bool
		ready  bool
		writes int
	}{
		{name: "allowed", packet: buildIPv4(local, remote, tcpSyn), allow: true, ready: true},
		{name: "malformed", packet: []byte{0x45}, allow: true},
		{name: "broadcast", packet: buildIPv4(local, netip.MustParseAddr("192.0.2.255"), udpDatagram), allow: true},
		{name: "multicast", packet: buildIPv4(local, netip.MustParseAddr("224.0.0.1"), udpDatagram), allow: true},
		{name: "firewall drop", packet: buildIPv4(local, remote, tcpSyn)},
		{name: "firewall reject", packet: buildIPv4(local, remote, tcpSyn), reject: true, writes: 1},
		{name: "unroutable drop", packet: buildIPv4(local, netip.MustParseAddr("198.51.100.1"), tcpSyn), allow: true},
		{name: "unroutable reject", packet: buildIPv4(local, netip.MustParseAddr("198.51.100.1"), tcpSyn), allow: true, reject: true, writes: 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f, h, tun := newInsideFilterTestInterface(t, tt.allow)
			f.firewall.OutboundSendReject = tt.reject
			fp := &firewall.ParsedPacket{}
			got := f.filterInsidePacket(tio.Packet{Bytes: tt.packet}, fp, make([]byte, mtu), 0, nil)
			if tt.ready {
				require.Same(t, h, got)
				assert.Equal(t, local, fp.LocalAddr)
				assert.Equal(t, remote, fp.RemoteAddr)
			} else {
				require.Nil(t, got)
			}
			assert.Zero(t, h.ConnectionState.messageCounter.Load(), "filtering must not allocate encryption counters")
			assert.False(t, h.sentSinceCheck(), "filtering must not mark outbound traffic")
			require.Len(t, tun.writes, tt.writes)
			if tt.writes > 0 {
				require.GreaterOrEqual(t, len(tun.writes[0]), 40)
				assert.Equal(t, tt.packet[16:20], tun.writes[0][12:16])
				assert.Equal(t, tt.packet[12:16], tun.writes[0][16:20])
				assert.NotZero(t, tun.writes[0][33]&0x04, "reject must carry a TCP reset")
			}
		})
	}
}

func TestFilterInsidePacketSelf(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.1")
	f, _, tun := newInsideFilterTestInterface(t, true)
	pkt := buildIPv4(local, local, tcpSyn)
	require.Nil(t, f.filterInsidePacket(tio.Packet{Bytes: pkt}, &firewall.ParsedPacket{}, nil, 0, nil))
	if immediatelyForwardToSelf {
		require.Len(t, tun.writes, 1)
		assert.Equal(t, pkt, tun.writes[0])
	} else {
		assert.Empty(t, tun.writes)
	}
}

func TestFilterInsidePacketPendingHandshake(t *testing.T) {
	f, h, tun := newInsideFilterTestInterface(t, true)
	remote := h.vpnAddrs[0]
	delete(f.hostMap.Hosts, remote)
	hh := &HandshakeHostInfo{hostinfo: h}
	f.handshakeManager.vpnIps[remote] = hh
	pkt := buildIPv4(netip.MustParseAddr("192.0.2.1"), remote, udpDatagram)
	want := append([]byte(nil), pkt...)
	require.Nil(t, f.filterInsidePacket(tio.Packet{Bytes: pkt}, &firewall.ParsedPacket{}, nil, 0, nil))
	require.Len(t, hh.packetStore, 1)
	clear(pkt)
	assert.Equal(t, want, hh.packetStore[0].packet, "the handshake cache must own its packet")
	assert.Equal(t, header.Message, hh.packetStore[0].messageType)
	assert.Empty(t, tun.writes)
	assert.Zero(t, h.ConnectionState.messageCounter.Load())
}

type insideFilterConn struct {
	udp.NoopConn
	packets [][]byte
}

func (c *insideFilterConn) WriteBatch(bufs [][]byte, _ []netip.AddrPort) (int, error) {
	for _, b := range bufs {
		c.packets = append(c.packets, append([]byte(nil), b...))
	}
	return len(bufs), nil
}

func TestConsumeInsidePacketFilterAndSend(t *testing.T) {
	for _, allow := range []bool{false, true} {
		t.Run(map[bool]string{false: "denied", true: "allowed"}[allow], func(t *testing.T) {
			f, h, _ := newInsideFilterTestInterface(t, allow)
			initR, respR := runTestHandshake(t)
			ci, err := newConnectionStateFromResult(initR)
			require.NoError(t, err)
			rci, err := newConnectionStateFromResult(respR)
			require.NoError(t, err)
			ci.peerCert = h.ConnectionState.peerCert
			h.ConnectionState = ci
			h.remoteIndexId = 100
			remote := netip.MustParseAddrPort("198.51.100.2:4242")
			h.remote.Store(&remote)
			conn := &insideFilterConn{}
			sb := batch.NewSendBatch(conn, 1, mtu)
			pkt := buildIPv4(netip.MustParseAddr("192.0.2.1"), h.vpnAddrs[0], udpDatagram)
			before := ci.messageCounter.Load()
			f.consumeInsidePacket(tio.Packet{Bytes: pkt}, &firewall.ParsedPacket{}, make([]byte, 12), sb, nil, 0, nil)
			_, err = sb.Flush()
			require.NoError(t, err)
			if !allow {
				assert.Empty(t, conn.packets)
				assert.Equal(t, before, ci.messageCounter.Load())
				assert.False(t, h.sentSinceCheck())
				return
			}
			require.Len(t, conn.packets, 1)
			assert.True(t, h.sentSinceCheck())
			hdr := &header.H{}
			require.NoError(t, hdr.Parse(conn.packets[0]))
			assert.Equal(t, header.Message, hdr.Type)
			assert.Equal(t, h.remoteIndexId, hdr.RemoteIndex)
			assert.Equal(t, before+1, hdr.MessageCounter)
			plain, err := rci.Decrypt(f.l, hdr.MessageCounter, conn.packets[0], make([]byte, 12))
			require.NoError(t, err)
			assert.Equal(t, pkt, plain)
		})
	}
}
