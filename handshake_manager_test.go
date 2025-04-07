package nebula

import (
	"net/netip"
	"testing"
	"time"

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
		v1HandshakeBytes:  []byte{},
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
