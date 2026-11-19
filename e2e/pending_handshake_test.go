//go:build e2e_testing
// +build e2e_testing

package e2e

import (
	"testing"
	"time"

	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/cert_test"
	"github.com/slackhq/nebula/e2e/router"
	"github.com/slackhq/nebula/header"
	"github.com/slackhq/nebula/udp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A responder starts using its new tunnel as soon as it answers a handshake,
// so its traffic can reach the initiator before the answer does (reordering,
// or the answer lost and resent). The initiator has that index only as its
// own handshake in progress. It must drop the packet, not answer it with
// recv_error: the responder would close the tunnel it just made, and the
// initiator, once its handshake completes, would send into a closed index.
// Under load both sides then tear down and rebuild the tunnel over and over.
func TestNoRecvErrorForOwnPendingHandshake(t *testing.T) {
	t.Parallel()
	ca, _, caKey, _ := cert_test.NewTestCaCert(cert.Version1, cert.Curve_CURVE25519, time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{})
	myControl, myVpnIpNet, myUdpAddr, _ := newSimpleServer(cert.Version1, ca, caKey, "me", "10.128.0.1/24", nil)
	theirControl, theirVpnIpNet, theirUdpAddr, _ := newSimpleServer(cert.Version1, ca, caKey, "them", "10.128.0.2/24", nil)
	me, them := myVpnIpNet[0].Addr(), theirVpnIpNet[0].Addr()

	myControl.InjectLightHouseAddr(them, theirUdpAddr)
	myControl.Start()
	theirControl.Start()
	defer myControl.Stop()
	defer theirControl.Stop()

	typeOf := func(p *udp.Packet) header.MessageType {
		t.Helper()
		var h header.H
		require.NoError(t, h.Parse(p.Data))
		return h.Type
	}

	t.Log("I start a handshake; they answer it and have a tunnel now")
	myControl.InjectTunPacket(BuildTunUDPPacket(them, 80, me, 80, []byte("Hi from me")))
	stage0 := myControl.GetFromUDP(true)
	require.Equal(t, header.Handshake, typeOf(stage0))
	theirControl.InjectUDPPacket(stage0)
	stage1 := theirControl.GetFromUDP(true)
	require.Equal(t, header.Handshake, typeOf(stage1))
	require.True(t, theirControl.HasTunnel(me))

	t.Log("They send on the new tunnel; it reaches me before their answer does")
	theirControl.InjectTunPacket(BuildTunUDPPacket(me, 80, them, 80, []byte("early")))
	early := theirControl.GetFromUDP(true)
	require.Equal(t, header.Message, typeOf(early))
	myControl.InjectUDPPacket(early)
	myControl.InjectUDPPacket(stage1)

	t.Log("My next packet out should be my cached one; a recv_error would come first")
	recvErrors := 0
	var cached *udp.Packet
	for cached == nil {
		p := myControl.GetFromUDP(true)
		switch typeOf(p) {
		case header.Handshake:
			// A retransmitted stage 0, from before stage 1 arrived.
		case header.RecvError:
			recvErrors++
			theirControl.InjectUDPPacket(p)
		case header.Message:
			cached = p
		default:
			t.Fatalf("unexpected packet type %v", typeOf(p))
		}
	}
	assert.Zero(t, recvErrors, "I answered traffic for my own pending handshake with recv_error")
	assert.True(t, theirControl.HasTunnel(me), "they closed the tunnel they had just made")
	if t.Failed() {
		// My tunnel points at the index they closed: nothing gets through.
		return
	}

	t.Log("The tunnel I completed is the one they have")
	theirControl.InjectUDPPacket(cached)
	assertUdpPacket(t, []byte("Hi from me"), theirControl.GetFromTun(true), me, them, 80, 80)
	assertHostInfoPair(t, myUdpAddr, theirUdpAddr, myVpnIpNet, theirVpnIpNet, myControl, theirControl)

	r := router.NewR(t, myControl, theirControl)
	defer r.RenderFlow()
	assertTunnel(t, me, them, myControl, theirControl, r)
}
