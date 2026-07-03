//go:build e2e_testing
// +build e2e_testing

package e2e

import (
	"testing"
	"time"

	"github.com/slackhq/nebula"
	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/cert_test"
	"github.com/slackhq/nebula/e2e/router"
	"github.com/slackhq/nebula/header"
	"github.com/slackhq/nebula/udp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func assertTestRequestEchoed(t *testing.T, cipher string) {
	ca, _, caKey, _ := cert_test.NewTestCaCert(cert.Version1, cert.Curve_CURVE25519, time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{})
	over := m{"cipher": cipher}
	a, aNet, aUdp, _ := newSimpleServer(cert.Version1, ca, caKey, "a", "10.128.0.1/24", over)
	b, bNet, bUdp, _ := newSimpleServer(cert.Version1, ca, caKey, "b", "10.128.0.2/24", over)

	a.InjectLightHouseAddr(bNet[0].Addr(), bUdp)
	b.InjectLightHouseAddr(aNet[0].Addr(), aUdp)
	a.Start()
	b.Start()
	t.Cleanup(func() { a.Stop(); b.Stop() })
	r := router.NewR(t, a, b)
	defer r.RenderFlow()

	assertTunnel(t, aNet[0].Addr(), bNet[0].Addr(), a, b, r)
	drainUDPTx(a)
	drainUDPTx(b)

	payload := []byte("a test payload well over sixteen bytes long, wow it's so very long long long!")
	require.Greater(t, len(payload), header.Len)
	a.GetF().SendMessageToVpnAddr(header.Test, header.TestRequest, bNet[0].Addr(), payload, make([]byte, 12, 12), make([]byte, udp.MTU))

	// Deliver A's request to B; B must echo a reply back
	b.InjectUDPPacket(a.GetFromUDP(true))
	reply := nextUDPTxOfType(t, b, header.Test, header.TestReply, 2*time.Second)

	assert.Equal(t, aUdp, reply.To, "the reply must go back to the requester")
	// header + echoed payload + 16-byte AEAD tag: proves the whole payload
	// round-tripped rather than being dropped or truncated.
	assert.Equal(t, header.Len+len(payload)+16, len(reply.Data), "the full payload must be echoed back")
}

func TestTestRequestEchoesLongPayloadAES(t *testing.T) {
	assertTestRequestEchoed(t, "aes")
}

func TestTestRequestEchoesLongPayloadChaChaPoly(t *testing.T) {
	assertTestRequestEchoed(t, "chachapoly")
}

// drainUDPTx empties a control's UDP tx queue without blocking.
func drainUDPTx(c *nebula.Control) {
	for c.GetFromUDP(false) != nil {
	}
}

// nextUDPTxOfType returns the next packet a control transmits whose nebula
// header matches (wantType, wantSub), skipping unrelated packets.
// It fails the test if none arrives within the timeout.
func nextUDPTxOfType(t *testing.T, c *nebula.Control, wantType header.MessageType, wantSub header.MessageSubType, within time.Duration) *udp.Packet {
	t.Helper()
	ch := c.GetUDPTxChan()
	timeout := time.After(within)
	for {
		select {
		case p := <-ch:
			var h header.H
			if err := h.Parse(p.Data); err == nil && h.Type == wantType && h.Subtype == wantSub {
				return p
			}
		case <-timeout:
			t.Fatalf("timed out waiting for a %v/%v packet on the udp tx queue", wantType, wantSub)
			return nil
		}
	}
}
