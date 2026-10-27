package nebula

import (
	"net/netip"
	"testing"
	"time"

	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/cert_test"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/handshake/fragment"
	"github.com/slackhq/nebula/header"
	"github.com/slackhq/nebula/test"
	"github.com/slackhq/nebula/udp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const hybridFragmented = header.HandshakeIXHybridMLKEM1024Fragmented

// hsPacket is a handshake packet of n zero bytes after its header.
func hsPacket(subtype header.MessageSubType, remoteIndex uint32, counter uint64, n int) []byte {
	pkt := header.Encode(make([]byte, header.Len, header.Len+n), header.Version, header.Handshake, subtype, remoteIndex, counter)
	return append(pkt, make([]byte, n)...)
}

func newPQTestManager(t *testing.T) (*HandshakeManager, *captureConn) {
	l := test.NewLogger()
	conn := &captureConn{}
	cfg := defaultHandshakeConfig
	cfg.pq = pqHandshakeConfig{initiate: true, accept: true}
	// Repair fragments go out with the data ones, so a test sees a whole send at once.
	cfg.fragment = fragmentConfig{}
	hm := NewHandshakeManager(l, newHostMap(l), newTestLighthouse(), conn, cfg)
	hm.f = &Interface{
		handshakeManager: hm,
		outside:          conn,
		messageMetrics:   newMessageMetricsOnlyRecvError(),
		pki:              newV3TestPKI(t),
		l:                l,
	}
	return hm, conn
}

// newV3TestPKI holds a version 3 certificate, which post-quantum handshakes need.
func newV3TestPKI(t *testing.T) *PKI {
	t.Helper()
	ca, _, caKey, _ := cert_test.NewTestCaCert(cert.Version3, cert.Curve_CURVE25519, time.Time{}, time.Time{}, nil, nil, nil)
	c, _, keyPEM, _ := cert_test.NewTestCert(cert.Version3, cert.Curve_CURVE25519, ca, caKey, "me", time.Time{}, time.Time{}, []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")}, nil, nil)
	key, _, curve, err := cert.UnmarshalPrivateKeyFromPEM(keyPEM)
	require.NoError(t, err)
	cs, err := newCertState(cert.Version2, nil, cert.V2Form(c), c, false, curve, key, "aes")
	require.NoError(t, err)
	p := &PKI{}
	p.cs.Store(cs)
	return p
}

func TestPQHandleCookie(t *testing.T) {
	cert_test.SkipWithoutPQ(t)
	hm, conn := newPQTestManager(t)
	via := ViaSender{UdpAddr: netip.MustParseAddrPort("192.0.2.1:4242")}

	s, err := fragment.NewSender(hsPacket(header.HandshakeIXHybridMLKEM1024, 0, 1, 2000), 99)
	require.NoError(t, err)
	_, _, err = s.Attempt(2)
	require.NoError(t, err)
	hh := &HandshakeHostInfo{hostinfo: &HostInfo{}, lastRemotes: []netip.AddrPort{via.UdpAddr}, pq: &pqAttempt{index: 99, sender: s, subtype: header.HandshakeIXHybridMLKEM1024}}
	hm.indexes[99] = hh

	reply := make([]byte, header.Len, fragCookieReplyLen)
	header.Encode(reply, header.Version, header.Handshake, hybridFragmented, 99, fragCookieCounter)
	reply = append(reply, bytes16(0xab)...)
	var h header.H
	require.NoError(t, h.Parse(reply))

	hm.handleFragment(via, reply, &h)
	assert.True(t, hh.pq.heard, "a cookie reply shows the peer speaks PQ")
	sent := conn.take()
	require.Len(t, sent, 4, "an immediate resend of fresh symbols")
	for i, p := range sent {
		var ph header.H
		require.NoError(t, ph.Parse(p))
		assert.Equal(t, hybridFragmented, ph.Subtype)
		fh, _, err := fragment.Parse(p[header.Len:])
		require.NoError(t, err)
		assert.True(t, fh.HasCookie())
		assert.Equal(t, fragment.Cookie(bytes16(0xab)), fh.Cookie)
		assert.Equal(t, uint8(4+i), fh.Index)
	}

	hm.handleFragment(via, reply, &h)
	assert.Empty(t, conn.take(), "immediate resends are rate limited")

	t.Run("replies for other indexes are ignored", func(t *testing.T) {
		other := append([]byte(nil), reply...)
		header.Encode(other, header.Version, header.Handshake, hybridFragmented, 98, fragCookieCounter)
		var oh header.H
		require.NoError(t, oh.Parse(other))
		hh.pq.cookieResendAt = time.Time{}
		hm.handleFragment(via, other, &oh)
		assert.Empty(t, conn.take())
	})
}

func TestReloadPQ(t *testing.T) {
	cert_test.SkipWithoutPQ(t)
	l := test.NewLogger()
	c := config.NewC(l)
	require.NoError(t, c.LoadString(`handshakes: {pq: {initiate: false}}`))
	cfg := defaultHandshakeConfig
	cfg.pq = pqHandshakeConfigFrom(c)
	hm := NewHandshakeManager(l, newHostMap(l), newTestLighthouse(), &udp.NoopConn{}, cfg)
	hm.f = &Interface{pki: newV3TestPKI(t)}
	c.RegisterReloadCallback(hm.reloadPQ)

	assert.Equal(t, pqHandshakeConfig{}, *hm.pqConfig())

	require.NoError(t, c.ReloadConfigString(`handshakes: {pq: {initiate: true, accept: true, sticky: true}}`).Err)
	assert.Equal(t, pqHandshakeConfig{initiate: true, accept: true, sticky: true}, *hm.pqConfig())

	before := hm.pqConfig()
	require.NoError(t, c.ReloadConfigString(`handshakes: {try_interval: 1s, pq: {initiate: true, accept: true, sticky: true}}`).Err)
	assert.Same(t, before, hm.pqConfig(), "an unrelated change leaves the settings alone")

	require.NoError(t, c.ReloadConfigString(`handshakes: {}`).Err)
	assert.Equal(t, pqHandshakeConfig{}, *hm.pqConfig(), "removing the section restores the defaults")

	require.NoError(t, c.ReloadConfigString(`handshakes: {pq: {require: true}}`).Err)
	assert.Equal(t, pqHandshakeConfig{initiate: true, accept: true, require: true}, *hm.pqConfig(), "require implies initiate and accept")
}

func TestUsePQ(t *testing.T) {
	cert_test.SkipWithoutPQ(t)
	hm, _ := newPQTestManager(t)
	peer := netip.MustParseAddr("10.1.0.1")
	set := func(cfg pqHandshakeConfig) { hm.pq.Store(&cfg) }

	// attempts plays a run of attempts, given whether each was triggered early,
	// and returns which were PQ.
	attempts := func(triggered ...bool) []bool {
		hh := &HandshakeHostInfo{}
		var out []bool
		for _, tr := range triggered {
			hh.counter++
			hh.lastPQ = hm.usePQ(hh, peer, tr)
			out = append(out, hh.lastPQ)
		}
		return out
	}

	set(pqHandshakeConfig{})
	assert.Equal(t, []bool{false, false, false}, attempts(false, false, false), "off")

	set(pqHandshakeConfig{initiate: true})
	assert.Equal(t, []bool{true, false, true, false}, attempts(false, false, false, false), "timer retries alternate, PQ first")
	assert.Equal(t, []bool{true, true, false, true, false}, attempts(false, true, false, true, false), "an early trigger is a new path, which gets PQ first")
	assert.Equal(t, []bool{true, true, false}, attempts(true, true, false), "a triggered first attempt is PQ")

	t.Run("hearing back stops the classical turns", func(t *testing.T) {
		hh := &HandshakeHostInfo{pq: &pqAttempt{}}
		hh.counter, hh.lastPQ = 1, true
		hh.counter++
		assert.False(t, hm.usePQ(hh, peer, false), "unheard, the classical attempt gets its turn")
		hh.pq.heard = true
		assert.True(t, hm.usePQ(hh, peer, false))
	})

	set(pqHandshakeConfig{initiate: true, accept: true, require: true})
	assert.Equal(t, []bool{true, true, true, true}, attempts(false, false, true, false), "require never offers classical")

	set(pqHandshakeConfig{initiate: true, sticky: true})
	assert.Equal(t, []bool{true, false}, attempts(false, false), "sticky alternates until the peer has done PQ")
	hm.notePQPeer(header.HandshakeIXHybridMLKEM1024, []netip.Addr{peer})
	assert.Equal(t, []bool{true, true, true}, attempts(false, false, false), "then only PQ")
}

// A hybrid msg2 fragment goes to the attempt's post-quantum slots, and only for the post-quantum attempt's index.
func TestPQMsg2(t *testing.T) {
	cert_test.SkipWithoutPQ(t)
	hm, _ := newPQTestManager(t)
	hh := &HandshakeHostInfo{hostinfo: &HostInfo{localIndexId: 41}, pq: &pqAttempt{index: 42}}
	hm.indexes[41] = hh
	hm.indexes[42] = hh

	s, err := fragment.NewSender(hsPacket(header.HandshakeIXHybridMLKEM1024, 42, 2, 9625), 1001)
	require.NoError(t, err)
	now, _, err := s.Attempt(0)
	require.NoError(t, err)
	var h header.H
	require.NoError(t, h.Parse(now[0]))

	hm.handleFragment(ViaSender{}, now[0], &h)
	assert.True(t, hh.pq.heard)
	n, ids := slotsUsed(&HandshakeHostInfo{msg2: hh.pq.msg2})
	assert.Equal(t, 1, n)
	assert.Equal(t, []uint32{1001}, ids)
	n, _ = slotsUsed(hh)
	assert.Zero(t, n, "the classical attempt's slots stay empty")

	t.Run("a hybrid msg2 naming the classical index is dropped", func(t *testing.T) {
		pkt := append([]byte(nil), now[1]...)
		header.Encode(pkt, header.Version, header.Handshake, hybridFragmented, 41, 2)
		var h header.H
		require.NoError(t, h.Parse(pkt))
		before := hh.pq.msg2
		hm.handleFragment(ViaSender{}, pkt, &h)
		assert.Equal(t, before, hh.pq.msg2)
		n, _ := slotsUsed(hh)
		assert.Zero(t, n)
	})

	t.Run("a classical msg2 naming the post-quantum index is dropped", func(t *testing.T) {
		pkt := msg2Fragments(t, make([]byte, 2000), 1001)[0]
		header.Encode(pkt, header.Version, header.Handshake, header.HandshakeIXPSK0Fragmented, 42, 2)
		var h header.H
		require.NoError(t, h.Parse(pkt))
		hm.handleFragment(ViaSender{}, pkt, &h)
		n, _ := slotsUsed(hh)
		assert.Zero(t, n)
	})
}

// Post-quantum handshakes are hybrid only, so without a version 3 certificate
// there is nothing to initiate and require is refused.
func TestPQNeedsV3(t *testing.T) {
	l := test.NewLogger()
	ca, _, caKey, _ := cert_test.NewTestCaCert(cert.Version2, cert.Curve_CURVE25519, time.Time{}, time.Time{}, nil, nil, nil)
	c2, _, keyPEM, _ := cert_test.NewTestCert(cert.Version2, cert.Curve_CURVE25519, ca, caKey, "me", time.Time{}, time.Time{}, []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")}, nil, nil)
	key, _, curve, err := cert.UnmarshalPrivateKeyFromPEM(keyPEM)
	require.NoError(t, err)
	cs, err := newCertState(cert.Version2, nil, c2, nil, false, curve, key, "aes")
	require.NoError(t, err)
	v2PKI := &PKI{}
	v2PKI.cs.Store(cs)

	hm := NewHandshakeManager(l, newHostMap(l), newTestLighthouse(), &udp.NoopConn{}, defaultHandshakeConfig)
	hm.f = &Interface{pki: v2PKI}
	hm.pq.Store(&pqHandshakeConfig{initiate: true, accept: true})
	assert.False(t, hm.usePQ(&HandshakeHostInfo{counter: 1}, netip.MustParseAddr("10.0.0.2"), false), "no v3 certificate, no hybrid attempt")

	conf := config.NewC(l)
	require.NoError(t, conf.LoadString(`handshakes: {pq: {initiate: true}}`))
	conf.RegisterReloadCallback(hm.reloadPQ)
	require.NoError(t, conf.ReloadConfigString(`handshakes: {pq: {require: true}}`).Err)
	assert.False(t, hm.pqConfig().require, "require without a v3 certificate is refused on reload")

	// And when loading the pki.
	certPEM, err := c2.MarshalPEM()
	require.NoError(t, err)
	conf = config.NewC(l)
	conf.Settings["pki"] = map[string]any{"cert": string(certPEM), "key": string(keyPEM)}
	conf.Settings["handshakes"] = map[string]any{"pq": map[string]any{"require": true}}
	_, err = newCertStateFromConfig(test.NewLogger(), conf, "aes")
	require.ErrorContains(t, err, "handshakes.pq.require needs a version 3 certificate")
}

// After answering a peer's hybrid msg1, its classical msg1s go unanswered for
// four retry intervals, and only for that peer.
func TestHybridCrossingWindow(t *testing.T) {
	cert_test.SkipWithoutPQ(t)
	hm, _ := newPQTestManager(t)
	peer := []netip.Addr{netip.MustParseAddr("10.1.0.1")}
	other := []netip.Addr{netip.MustParseAddr("10.1.0.2")}
	now := time.Unix(1000, 0)
	w := 4 * hm.config.tryInterval
	assert.Equal(t, w, hm.hybridWindow())

	assert.False(t, hm.crossesHybrid(peer, now))
	hm.noteHybridMsg1(peer, now)
	assert.True(t, hm.crossesHybrid(peer, now.Add(w-time.Millisecond)))
	assert.False(t, hm.crossesHybrid(peer, now.Add(w)))
	assert.False(t, hm.crossesHybrid(other, now))

	hm.expireHybridResponders(now.Add(w))
	hm.hybrid.answeredMu.Lock()
	assert.Empty(t, hm.hybrid.answered, "expired windows are forgotten")
	hm.hybrid.answeredMu.Unlock()
}

// A node whose only certificate is a v3 one without a v2 form has nothing to answer a classical handshake with, so it
// speaks hybrid handshakes only, initiating and accepting them whatever handshakes.pq says.
func TestPQRequiredWithoutV2Form(t *testing.T) {
	cert_test.SkipWithoutPQ(t)
	hm, _ := newPQTestManager(t)
	assert.False(t, hm.pqRequired(), "a v3 certificate with a v2 form still speaks classical")

	ca, _, caKey, _ := cert_test.NewTestV3CaCertWithoutV2Form(cert.Curve_CURVE25519, time.Time{}, time.Time{}, nil, nil, nil)
	c, _, keyPEM, _ := cert_test.NewTestCert(cert.Version3, cert.Curve_CURVE25519, ca, caKey, "me", time.Time{}, time.Time{}, []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")}, nil, nil)
	key, _, curve, err := cert.UnmarshalPrivateKeyFromPEM(keyPEM)
	require.NoError(t, err)
	cs, err := newCertState(cert.Version3, nil, nil, c, false, curve, key, "aes")
	require.NoError(t, err)
	hm.f.pki.cs.Store(cs)

	hm.pq.Store(&pqHandshakeConfig{})
	assert.True(t, hm.pqRequired())
	peer := netip.MustParseAddr("10.0.0.2")
	for _, hh := range []*HandshakeHostInfo{{counter: 1}, {counter: 2, lastPQ: true}, {counter: 3, noPQ: true}} {
		assert.True(t, hm.usePQ(hh, peer, false), "every attempt is post-quantum")
	}
}

// A hybrid handshake travels as fragments whatever handshakes.fragment says: with never, a hybrid msg1 still reaches
// the fragment table and a hybrid response still goes as fragments.
func TestHybridIgnoresFragmentNever(t *testing.T) {
	cert_test.SkipWithoutPQ(t)
	hm, conn := newPQTestManager(t)
	hm.frag.Store(&fragmentConfig{mode: fragmentNever})
	via := ViaSender{UdpAddr: netip.MustParseAddrPort("192.0.2.1:4242")}

	s, err := fragment.NewSender(hsPacket(header.HandshakeIXHybridMLKEM1024, 0, 1, 8000), 77)
	require.NoError(t, err)
	now, _, err := s.Attempt(0)
	require.NoError(t, err)
	var h header.H
	require.NoError(t, h.Parse(now[0]))
	hm.HandleIncoming(via, now[0], &h)
	assert.Equal(t, 1, hm.fragTable.Len(), "the hybrid msg1 fragment is kept for reassembly")

	t.Run("an unfragmented hybrid message is dropped", func(t *testing.T) {
		pkt := make([]byte, header.Len, header.Len+100)
		header.Encode(pkt, header.Version, header.Handshake, header.HandshakeIXHybridMLKEM1024, 0, 1)
		pkt = append(pkt, make([]byte, 100)...)
		var h header.H
		require.NoError(t, h.Parse(pkt))
		hm.HandleIncoming(via, pkt, &h)
		assert.Equal(t, 1, hm.fragTable.Len())
	})

	msg2 := make([]byte, header.Len, header.Len+300)
	header.Encode(msg2, header.Version, header.Handshake, header.HandshakeIXHybridMLKEM1024, 77, 2)
	msg2 = append(msg2, make([]byte, 300)...)
	hostinfo := &HostInfo{localIndexId: 5, remoteIndexId: 77, HandshakePacket: map[uint8][]byte{handshakePacketStage0: make([]byte, 8000)}}
	hm.sendHandshakeResponse(via, msg2, hostinfo, false, msg1Info{fragmented: true, validated: true})
	sent := conn.take()
	require.NotEmpty(t, sent)
	for _, p := range sent {
		var ph header.H
		require.NoError(t, ph.Parse(p))
		assert.Equal(t, hybridFragmented, ph.Subtype)
	}
}

// With handshakes.pq.require a classical msg1 goes unanswered, fragmented or not.
func TestPQRequireDropsClassical(t *testing.T) {
	cert_test.SkipWithoutPQ(t)
	hm, conn := newPQTestManager(t)
	hm.pq.Store(&pqHandshakeConfig{initiate: true, accept: true, require: true})
	via := ViaSender{UdpAddr: netip.MustParseAddrPort("192.0.2.1:4242")}

	s, err := fragment.NewSender(hsPacket(header.HandshakeIXPSK0, 0, 1, 3000), 78)
	require.NoError(t, err)
	now, _, err := s.Attempt(0)
	require.NoError(t, err)
	var h header.H
	require.NoError(t, h.Parse(now[0]))
	hm.HandleIncoming(via, now[0], &h)
	assert.Zero(t, hm.fragTable.Len(), "a fragmented classical msg1 is not reassembled")
	assert.Empty(t, conn.take())
}
