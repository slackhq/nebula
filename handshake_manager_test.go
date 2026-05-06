package nebula

import (
	"net/netip"
	"testing"
	"time"

	"github.com/gaissmai/bart"
	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/header"
	"github.com/slackhq/nebula/test"
	"github.com/slackhq/nebula/udp"
	"github.com/stretchr/testify/assert"
)

func Test_NewHandshakeManagerVpnIp(t *testing.T) {
	l := test.NewLogger()
	localrange := netip.MustParsePrefix("10.1.1.1/24")
	ip := netip.MustParseAddr("172.1.1.2")

	preferredRanges := []netip.Prefix{localrange}
	mainHM := newHostMap(l)
	mainHM.preferredRanges.Store(&preferredRanges)

	lh := newTestLighthouse()

	cs := &CertState{
		initiatingVersion: cert.Version1,
		privateKey:        []byte{},
		v1Cert:            &dummyCert{version: cert.Version1},
		v1Credential:      nil,
	}

	blah := NewHandshakeManager(l, mainHM, lh, &udp.NoopConn{}, defaultHandshakeConfig)
	blah.f = &Interface{handshakeManager: blah, pki: &PKI{}, l: l}
	blah.f.pki.cs.Store(cs)

	now := time.Now()
	blah.NextOutboundHandshakeTimerTick(now)

	i := blah.StartHandshake(ip, nil)
	i2 := blah.StartHandshake(ip, nil)
	assert.Same(t, i, i2)

	i.remotes = NewRemoteList([]netip.Addr{}, nil)

	// Adding something to pending should not affect the main hostmap
	assert.Empty(t, mainHM.Hosts)

	// Confirm they are in the pending index list
	assert.Contains(t, blah.vpnIps, ip)

	// Jump ahead `HandshakeRetries` ticks, offset by one to get the sleep logic right
	for i := 1; i <= DefaultHandshakeRetries+1; i++ {
		now = now.Add(time.Duration(i) * DefaultHandshakeTryInterval)
		blah.NextOutboundHandshakeTimerTick(now)
	}

	// Confirm they are still in the pending index list
	assert.Contains(t, blah.vpnIps, ip)

	// Tick 1 more time, a minute will certainly flush it out
	blah.NextOutboundHandshakeTimerTick(now.Add(time.Minute))

	// Confirm they have been removed
	assert.NotContains(t, blah.vpnIps, ip)
}

func testCountTimerWheelEntries(tw *LockingTimerWheel[netip.Addr]) (c int) {
	for _, i := range tw.t.wheel {
		n := i.Head
		for n != nil {
			c++
			n = n.Next
		}
	}
	return c
}

type mockEncWriter struct {
}

func (mw *mockEncWriter) SendMessageToVpnAddr(_ header.MessageType, _ header.MessageSubType, _ netip.Addr, _, _, _ []byte) {
	return
}

func (mw *mockEncWriter) SendVia(_ *HostInfo, _ *Relay, _, _, _ []byte, _ bool) {
	return
}

func (mw *mockEncWriter) SendMessageToHostInfo(_ header.MessageType, _ header.MessageSubType, _ *HostInfo, _, _, _ []byte) {
	return
}

func (mw *mockEncWriter) Handshake(_ netip.Addr) {}

func (mw *mockEncWriter) GetHostInfo(_ netip.Addr) *HostInfo {
	return nil
}

func (mw *mockEncWriter) GetCertState() *CertState {
	return &CertState{initiatingVersion: cert.Version2}
}

func TestValidatePeerCert(t *testing.T) {
	l := test.NewLogger()

	myNetwork := netip.MustParsePrefix("10.0.0.1/24")
	myAddrTable := new(bart.Lite)
	myAddrTable.Insert(netip.PrefixFrom(myNetwork.Addr(), myNetwork.Addr().BitLen()))
	myNetTable := new(bart.Lite)
	myNetTable.Insert(myNetwork.Masked())

	newHM := func() *HandshakeManager {
		hm := NewHandshakeManager(l, newHostMap(l), newTestLighthouse(), &udp.NoopConn{}, defaultHandshakeConfig)
		hm.f = &Interface{
			handshakeManager:   hm,
			pki:                &PKI{},
			l:                  l,
			myVpnAddrsTable:    myAddrTable,
			myVpnNetworksTable: myNetTable,
			lightHouse:         hm.lightHouse,
		}
		return hm
	}

	cached := func(networks ...netip.Prefix) *cert.CachedCertificate {
		return &cert.CachedCertificate{
			Certificate: &dummyCert{name: "peer", networks: networks},
		}
	}

	via := ViaSender{
		UdpAddr:   netip.MustParseAddrPort("198.51.100.7:4242"),
		IsRelayed: true, // skip the remote allow list (covered separately)
	}

	t.Run("addr inside our networks sets anyVpnAddrsInCommon", func(t *testing.T) {
		hm := newHM()
		// 10.0.0.2 falls inside our 10.0.0.0/24
		addrs, common, ok := hm.validatePeerCert(via, cached(netip.MustParsePrefix("10.0.0.2/24")))
		assert.True(t, ok)
		assert.True(t, common)
		assert.Equal(t, []netip.Addr{netip.MustParseAddr("10.0.0.2")}, addrs)
	})

	t.Run("addr outside our networks leaves anyVpnAddrsInCommon false", func(t *testing.T) {
		hm := newHM()
		addrs, common, ok := hm.validatePeerCert(via, cached(netip.MustParsePrefix("192.168.1.5/24")))
		assert.True(t, ok)
		assert.False(t, common)
		assert.Equal(t, []netip.Addr{netip.MustParseAddr("192.168.1.5")}, addrs)
	})

	t.Run("any matching network is enough", func(t *testing.T) {
		hm := newHM()
		addrs, common, ok := hm.validatePeerCert(via, cached(
			netip.MustParsePrefix("192.168.1.5/24"),
			netip.MustParsePrefix("10.0.0.42/24"),
		))
		assert.True(t, ok)
		assert.True(t, common)
		assert.Len(t, addrs, 2)
	})

	t.Run("self-handshake is rejected", func(t *testing.T) {
		hm := newHM()
		// 10.0.0.1 is in myVpnAddrsTable
		addrs, common, ok := hm.validatePeerCert(via, cached(netip.MustParsePrefix("10.0.0.1/24")))
		assert.False(t, ok)
		assert.False(t, common)
		assert.Nil(t, addrs)
	})

	t.Run("cert with no networks is rejected", func(t *testing.T) {
		hm := newHM()
		addrs, common, ok := hm.validatePeerCert(via, cached())
		assert.False(t, ok)
		assert.False(t, common)
		assert.Nil(t, addrs)
	})
}

func TestHandleIncomingDispatch(t *testing.T) {
	l := test.NewLogger()

	newHM := func() *HandshakeManager {
		hm := NewHandshakeManager(l, newHostMap(l), newTestLighthouse(), &udp.NoopConn{}, defaultHandshakeConfig)
		hm.f = &Interface{
			handshakeManager: hm,
			pki:              &PKI{},
			l:                l,
		}
		return hm
	}

	via := ViaSender{
		UdpAddr:   netip.MustParseAddrPort("198.51.100.7:4242"),
		IsRelayed: true, // bypass remote allow list
	}

	// A packet body of zero length is fine for these tests: dispatch is
	// gated on header fields, and we assert that we never reach noise/cert
	// processing for any of the malformed shapes here.
	pkt := make([]byte, header.Len)

	t.Run("unsupported subtype dropped", func(t *testing.T) {
		hm := newHM()
		h := &header.H{Type: header.Handshake, Subtype: header.MessageSubType(99), MessageCounter: 1}
		hm.HandleIncoming(via, pkt, h)
		assert.Empty(t, hm.indexes, "no pending handshake should be created")
	})

	t.Run("stage-1 with non-zero RemoteIndex dropped", func(t *testing.T) {
		hm := newHM()
		h := &header.H{
			Type:           header.Handshake,
			Subtype:        header.HandshakeIXPSK0,
			RemoteIndex:    0xdeadbeef,
			MessageCounter: 1,
		}
		hm.HandleIncoming(via, pkt, h)
		assert.Empty(t, hm.indexes, "spoofed stage-1 must not create a pending machine")
	})

	t.Run("continuation with no matching pending index dropped", func(t *testing.T) {
		hm := newHM()
		h := &header.H{
			Type:           header.Handshake,
			Subtype:        header.HandshakeIXPSK0,
			RemoteIndex:    0xcafef00d,
			MessageCounter: 2,
		}
		hm.HandleIncoming(via, pkt, h)
		assert.Empty(t, hm.indexes, "orphan stage-2 must not create state")
	})
}
