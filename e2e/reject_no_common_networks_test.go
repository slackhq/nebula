//go:build e2e_testing
// +build e2e_testing

// Reproducer + fix verification for the "no vpnNetworks in common" gap:
// validatePeerCert previously only logged peers whose certificate networks
// were disjoint from our own and still completed the handshake. With the new
// handshakes.reject_on_no_common_networks option, such peers are rejected on
// both the responder path (beginHandshake) and the initiator path
// (continueHandshake stage-2 completion).
package e2e

import (
	"context"
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

// TestRejectOnNoCommonNetworks verifies that enabling
// handshakes.reject_on_no_common_networks refuses handshakes with peers whose
// certificate networks do not overlap ours.
func TestRejectOnNoCommonNetworks(t *testing.T) {
	t.Parallel()
	done := deadline(t, 30)
	defer done()

	ca, _, caKey, _ := cert_test.NewTestCaCert(cert.Version2, cert.Curve_CURVE25519, time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{})

	// "me" enables the reject option and holds only 10.128.0.0/24.
	me, meVpn, _, _ := newSimpleServer(cert.Version2, ca, caKey, "me", "10.128.0.1/24", m{
		"handshakes": m{
			"reject_on_no_common_networks": true,
		},
	})

	// "them" advertises a fully disjoint network and is rejected by "me".
	them, themVpn, _, _ := newSimpleServer(cert.Version2, ca, caKey, "them", "2001::69/24", nil)

	me.InjectLightHouseAddr(themVpn[0].Addr(), them.GetUDPAddr())
	them.InjectLightHouseAddr(meVpn[0].Addr(), me.GetUDPAddr())

	me.Start()
	them.Start()
	defer me.Stop()
	defer them.Stop()

	them.GetF().SendMessageToVpnAddr(header.Test, header.MessageNone, meVpn[0].Addr(), []byte{}, []byte{}, []byte{})

	// Capture the initiator's stage-0 and deliver it to "me". Before the
	// stage-0 is captured we must NOT start routing: the router and this test
	// both drain the initiator's transmit queue, so starting the router early
	// would race the capture below.
	var themStage0 *udp.Packet
	for i := 0; i < 20; i++ {
		if p := them.GetFromUDP(false); p != nil {
			themStage0 = p
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	require.NotNil(t, themStage0, "initiator emits stage-0")
	them.InjectUDPPacket(themStage0)

	r := router.NewR(t, me, them)
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	go func() {
		// Keep routing until cancelled: the reflect loop forwards UDP traffic
		// between both hosts as a side effect on every select iteration.
		for {
			select {
			case <-ctx.Done():
				return
			default:
				r.RouteForAllUntilTxTun(me)
			}
		}
	}()

	// "me" must not respond with a stage-2 completion: poll to confirm nothing
	// ever comes back from the rejector.
	for i := 0; i < 20; i++ {
		if got := me.GetFromUDP(false); got != nil {
			h := &header.H{}
			err := h.Parse(got.Data)
			gotName := "<parse-failed>"
			if err == nil {
				gotName = header.TypeName(h.Type)
			}
			t.Fatal("responder must not respond to a disjoint-network peer when reject_on_no_common_networks is enabled; got:", gotName)
		}
		time.Sleep(100 * time.Millisecond)
	}
	assert.Nil(t, me.GetHostInfoByVpnAddr(themVpn[0].Addr(), false), "disjoint peer must not occupy tunnel state on the rejector")
	assert.Nil(t, them.GetHostInfoByVpnAddr(meVpn[0].Addr(), false), "disjoint peer must not occupy tunnel state on the initiator (no stage-2 ever received)")
}

// TestRejectOnNoCommonNetworksInitiator verifies the same rejection applies on
// the initiator path: an initiator that receives a stage-2 from a disjoint-
// network peer aborts the handshake and sends a CloseTunnel, reclaiming the
// responder's otherwise-orphaned entry.
func TestRejectOnNoCommonNetworksInitiator(t *testing.T) {
	t.Parallel()
	done := deadline(t, 30)
	defer done()

	ca, _, caKey, _ := cert_test.NewTestCaCert(cert.Version2, cert.Curve_CURVE25519, time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{})

	// "them" is the initiator and enables the reject option; "me" is the
	// responder with a disjoint network.
	them, themVpn, _, _ := newSimpleServer(cert.Version2, ca, caKey, "them", "10.128.0.1/24", m{
		"handshakes": m{
			"reject_on_no_common_networks": true,
		},
	})
	me, meVpn, _, _ := newSimpleServer(cert.Version2, ca, caKey, "me", "2001::69/24", nil)

	them.InjectLightHouseAddr(meVpn[0].Addr(), me.GetUDPAddr())
	me.InjectLightHouseAddr(themVpn[0].Addr(), them.GetUDPAddr())

	r := router.NewR(t, me, them)
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	go func() {
		// Keep routing until cancelled: the reflect loop forwards UDP traffic
		// between both hosts as a side effect on every select iteration.
		for {
			select {
			case <-ctx.Done():
				return
			default:
				r.RouteForAllUntilTxTun(me)
			}
		}
	}()

	them.Start()
	me.Start()
	defer them.Stop()
	defer me.Stop()

	them.GetF().SendMessageToVpnAddr(header.Test, header.MessageNone, meVpn[0].Addr(), []byte{}, []byte{}, []byte{})
	themStage0 := them.GetFromUDP(true)
	me.InjectUDPPacket(themStage0)

	// IX semantics: the responder (me) completes on stage-0, before the
	// initiator can reject at stage-2. The initiator rejects, sends a
	// CloseTunnel, and me processes it to delete its orphaned entry.
	time.Sleep(2 * time.Second)
	assert.Nil(t, them.GetHostInfoByVpnAddr(meVpn[0].Addr(), false),
		"initiator must abort the handshake with a disjoint-network peer when reject_on_no_common_networks is enabled")
	assert.Nil(t, me.GetHostInfoByVpnAddr(themVpn[0].Addr(), false),
		"responder's orphaned entry must be reclaimed after the initiator's CloseTunnel is processed")
}
