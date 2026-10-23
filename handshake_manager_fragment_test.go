package nebula

import (
	"math/rand/v2"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/rcrowley/go-metrics"
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

// recordingConn captures what is written to it.
type recordingConn struct {
	udp.NoopConn
	sync.Mutex
	sent [][]byte
}

func (c *recordingConn) WriteTo(b []byte, _ netip.AddrPort) error {
	c.Lock()
	defer c.Unlock()
	c.sent = append(c.sent, append([]byte(nil), b...))
	return nil
}

func (c *recordingConn) take() [][]byte {
	c.Lock()
	defer c.Unlock()
	s := c.sent
	c.sent = nil
	return s
}

func newFragTestManager(t *testing.T) (*HandshakeManager, *recordingConn) {
	t.Helper()
	l := test.NewLogger()
	conn := &recordingConn{}
	cfg := defaultHandshakeConfig
	// Repair fragments go out with the data ones, so a test sees a whole send at once.
	cfg.fragment = fragmentConfig{}
	hm := NewHandshakeManager(l, newHostMap(l), newTestLighthouse(), conn, cfg)
	ca, _, caKey, _ := cert_test.NewTestCaCert(cert.Version2, cert.Curve_CURVE25519, time.Time{}, time.Time{}, nil, nil, nil)
	c, _, keyPEM, _ := cert_test.NewTestCert(cert.Version2, cert.Curve_CURVE25519, ca, caKey, "me", time.Time{}, time.Time{}, []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")}, nil, nil)
	key, _, curve, err := cert.UnmarshalPrivateKeyFromPEM(keyPEM)
	require.NoError(t, err)
	cs, err := newCertState(cert.Version2, nil, c, false, curve, key, "aes")
	require.NoError(t, err)
	p := &PKI{}
	p.cs.Store(cs)
	hm.f = &Interface{
		handshakeManager: hm,
		outside:          conn,
		messageMetrics:   newMessageMetricsOnlyRecvError(),
		pki:              p,
		l:                l,
	}
	return hm, conn
}

// fragmentIndexes checks every packet is a fragment of the expected response and returns their symbol indexes.
func fragmentIndexes(t *testing.T, pkts [][]byte, fragID, remoteIndex uint32) []int {
	t.Helper()
	var out []int
	for _, p := range pkts {
		require.LessOrEqual(t, len(p), fragment.MaxPacketLen)
		var h header.H
		require.NoError(t, h.Parse(p))
		assert.Equal(t, header.HandshakeIXPSK0Fragmented, h.Subtype)
		assert.Equal(t, remoteIndex, h.RemoteIndex)
		assert.Equal(t, uint64(2), h.MessageCounter)
		fh, _, err := fragment.Parse(p[header.Len:])
		require.NoError(t, err)
		assert.Equal(t, fragID, fh.FragID)
		out = append(out, int(fh.Index))
	}
	return out
}

// testMsg2 is a msg2 packet of n random bytes after its header, as the handshake Machine writes it.
func testMsg2(n int, seed uint64) []byte {
	msg := make([]byte, header.Len, header.Len+n)
	header.Encode(msg, header.Version, header.Handshake, header.HandshakeIXPSK0, 5, 2)
	r := rand.New(rand.NewPCG(seed, seed))
	for range n {
		msg = append(msg, byte(r.Uint32()))
	}
	return msg
}

func TestFragmentConfig(t *testing.T) {
	for s, want := range map[string]fragmentMode{"auto": fragmentAuto, "always": fragmentAlways, "never": fragmentNever} {
		c := config.NewC(test.NewLogger())
		require.NoError(t, c.LoadString("handshakes: {fragment: "+s+"}"))
		cfg, err := fragmentConfigFrom(c, DefaultHandshakeTryInterval)
		require.NoError(t, err)
		assert.Equal(t, want, cfg.mode)
		assert.Equal(t, s, cfg.mode.String())
		assert.Equal(t, 10*time.Millisecond, cfg.repairDelay, "a tenth of the default retry interval")
	}

	c := config.NewC(test.NewLogger())
	cfg, err := fragmentConfigFrom(c, DefaultHandshakeTryInterval)
	require.NoError(t, err)
	assert.Equal(t, fragmentAuto, cfg.mode, "auto by default")

	cfg, err = fragmentConfigFrom(c, 300*time.Millisecond)
	require.NoError(t, err)
	assert.Equal(t, 30*time.Millisecond, cfg.repairDelay, "the default repair delay follows the retry interval")

	require.NoError(t, c.LoadString("handshakes: {repair_delay: 7ms}"))
	cfg, err = fragmentConfigFrom(c, 300*time.Millisecond)
	require.NoError(t, err)
	assert.Equal(t, 7*time.Millisecond, cfg.repairDelay, "a configured repair delay overrides it")

	for _, bad := range []string{"handshakes: {fragment: sometimes}", "handshakes: {repair_delay: -1ms}"} {
		c := config.NewC(test.NewLogger())
		require.NoError(t, c.LoadString(bad))
		_, err := fragmentConfigFrom(c, DefaultHandshakeTryInterval)
		require.Error(t, err, bad)
	}

	t.Run("reload", func(t *testing.T) {
		hm, _ := newFragTestManager(t)
		c := config.NewC(test.NewLogger())
		require.NoError(t, c.LoadString("handshakes: {fragment: auto}"))
		c.RegisterReloadCallback(hm.reloadFragment)

		res := c.ReloadConfigString("handshakes: {fragment: always, repair_delay: 25ms}")
		require.NoError(t, res.Err)
		assert.False(t, res.Failed)
		assert.Equal(t, fragmentConfig{mode: fragmentAlways, repairDelay: 25 * time.Millisecond}, *hm.fragConfig())

		res = c.ReloadConfigString("handshakes: {fragment: always}")
		require.NoError(t, res.Err)
		assert.Equal(t, hm.config.tryInterval/repairDelayDivisor, hm.fragConfig().repairDelay, "unset, it follows the retry interval in effect")

		res = c.ReloadConfigString("handshakes: {fragment: sometimes}")
		require.NoError(t, res.Err)
		assert.True(t, res.Failed, "a bad mode fails the reload")
		assert.Equal(t, fragmentAlways, hm.fragConfig().mode, "and keeps what was running")
	})
}

func TestShouldFragment(t *testing.T) {
	hm, _ := newFragTestManager(t)
	small, big := fragment.MaxPacketLen, fragment.MaxPacketLen+1
	for _, tc := range []struct {
		mode               fragmentMode
		msgLen             int
		answeringFragments bool
		want               bool
	}{
		{fragmentAuto, small, false, false},
		{fragmentAuto, big, false, true},
		{fragmentAuto, small, true, true},
		{fragmentAlways, small, false, true},
		{fragmentNever, big, false, false},
		{fragmentNever, small, true, false},
	} {
		hm.frag.Store(&fragmentConfig{mode: tc.mode})
		assert.Equal(t, tc.want, hm.shouldFragment(tc.msgLen, tc.answeringFragments), "%+v", tc)
	}
}

func TestReassembledIsUnfragmented(t *testing.T) {
	pkt := make([]byte, header.Len+3)
	h := &header.H{Subtype: header.HandshakeIXPSK0Fragmented, RemoteIndex: 9, MessageCounter: 2}
	got := reassembled(h, pkt)
	var gh header.H
	require.NoError(t, gh.Parse(got))
	assert.Equal(t, header.HandshakeIXPSK0, gh.Subtype, "the Machine sees the pattern it was built for")
	assert.Equal(t, uint32(9), gh.RemoteIndex)
	assert.Equal(t, uint64(2), gh.MessageCounter)
	assert.Len(t, got, header.Len+3)
}

func TestFragmentResponse(t *testing.T) {
	hostinfo := &HostInfo{localIndexId: 77}

	// A 2000 byte message is 2 symbols of 1000, so packets of 1024 bytes.
	msg := testMsg2(2000, 1)
	const pktLen = header.Len + fragment.HeaderLen + 1000

	indexes := func(budget int) []int {
		t.Helper()
		now, later, err := fragmentResponse(msg, hostinfo, budget)
		require.NoError(t, err)
		return fragmentIndexes(t, append(now, later...), 77, 5)
	}

	t.Run("first send", func(t *testing.T) {
		assert.Equal(t, []int{0, 1, 2, 3}, indexes(-1))
	})

	t.Run("a repeat is answered at once with fresh symbols", func(t *testing.T) {
		assert.Equal(t, []int{4, 5, 6, 7}, indexes(10*pktLen))
	})

	t.Run("amplification budget trims repair", func(t *testing.T) {
		assert.Equal(t, []int{8, 9, 10}, indexes(3*pktLen))
	})

	t.Run("amplification budget below the data refuses", func(t *testing.T) {
		_, _, err := fragmentResponse(msg, hostinfo, pktLen)
		require.ErrorIs(t, err, errOverBudget)
	})
}

// A response that should go as fragments but is more than its msg1's amplification budget allows is held back for a
// cookie reply naming the initiator. The msg1's quiet period ends, so the initiator's resend with the cookie is
// reassembled at once rather than after it.
func TestResponseOverBudgetAsksForCookie(t *testing.T) {
	hm, conn := newFragTestManager(t)
	via := ViaSender{UdpAddr: netip.MustParseAddrPort("192.0.2.1:4242")}
	msg1 := []byte("a small msg1")
	hostinfo := &HostInfo{localIndexId: 77, remoteIndexId: 1234, HandshakePacket: map[uint8][]byte{handshakePacketStage0: msg1}, ConnectionState: &ConnectionState{}}
	msg2 := testMsg2(4000, 2)

	// The msg1 came as one fragment, which completed it and quieted its key.
	key, src := fragKeyFor(via, hostinfo.remoteIndexId)
	s, err := fragment.NewSender(testMsg1(msg1), hostinfo.remoteIndexId)
	require.NoError(t, err)
	addMsg1 := func() *fragment.Result {
		t.Helper()
		pkts, _, err := s.Attempt(0)
		require.NoError(t, err)
		require.Len(t, pkts, 1)
		fh, sym, err := fragment.Parse(pkts[0][header.Len:])
		require.NoError(t, err)
		res, err := hm.fragTable.Add(key, src, time.Now(), fh, sym)
		require.NoError(t, err)
		return res
	}
	require.NotNil(t, addMsg1())
	require.Nil(t, addMsg1(), "the key is quiet")

	hm.sendHandshakeResponse(via, msg2, hostinfo, false, msg1Info{received: 300})
	sent := conn.take()
	require.Len(t, sent, 1)
	var h header.H
	require.NoError(t, h.Parse(sent[0]))
	assert.Len(t, sent[0], fragCookieReplyLen)
	assert.Equal(t, header.HandshakeIXPSK0Fragmented, h.Subtype)
	assert.Equal(t, uint64(fragCookieCounter), h.MessageCounter)
	assert.Equal(t, uint32(1234), h.RemoteIndex, "the reply names the initiator by its index")
	assert.NotNil(t, addMsg1(), "the resend with the cookie is reassembled at once")

	// The cookie validates the address, so the retry gets the whole response.
	hm.sendHandshakeResponse(via, msg2, hostinfo, true, msg1Info{fragmented: true, validated: true, received: 300})
	assert.NotEmpty(t, fragmentIndexes(t, conn.take(), 77, 5))

	// A response that fits one packet goes as one, whatever the budget.
	small := testMsg2(500, 3)
	hm.sendHandshakeResponse(via, small, hostinfo, false, msg1Info{received: 10})
	sent = conn.take()
	require.Len(t, sent, 1)
	assert.Equal(t, small, sent[0])
}

func TestFragKeyFor(t *testing.T) {
	k1, s1 := fragKeyFor(ViaSender{UdpAddr: netip.MustParseAddrPort("192.0.2.1:4242")}, 9)
	k2, s2 := fragKeyFor(ViaSender{UdpAddr: netip.MustParseAddrPort("192.0.2.1:4243")}, 9)
	assert.NotEqual(t, k1, k2, "different ports are different messages")
	assert.Equal(t, s1, s2, "but share an IPv4 /32 quota")

	_, s3 := fragKeyFor(ViaSender{UdpAddr: netip.MustParseAddrPort("[2001:db8::1]:1")}, 9)
	_, s4 := fragKeyFor(ViaSender{UdpAddr: netip.MustParseAddrPort("[2001:db8::ffff]:1")}, 9)
	assert.Equal(t, s3, s4, "an IPv6 /64 shares a quota")

	_, s5 := fragKeyFor(ViaSender{UdpAddr: netip.MustParseAddrPort("[::ffff:192.0.2.1]:1")}, 9)
	assert.Equal(t, s1, s5, "v4-mapped addresses count as IPv4")
}

func TestFragCookies(t *testing.T) {
	now := time.Unix(1000, 0)
	c := newFragCookies(now)
	key := fragKey{addr: netip.MustParseAddrPort("192.0.2.1:4242"), fragID: 9}

	cookie := c.make(key, now)
	assert.True(t, c.valid(key, cookie, now))

	for _, other := range []fragKey{
		{addr: netip.MustParseAddrPort("192.0.2.2:4242"), fragID: 9},
		{addr: netip.MustParseAddrPort("192.0.2.1:4243"), fragID: 9},
		{addr: netip.MustParseAddrPort("192.0.2.1:4242"), fragID: 10},
		{addr: netip.MustParseAddrPort("192.0.2.1:4242"), relay: 1, fragID: 9},
	} {
		assert.False(t, c.valid(other, cookie, now), "%+v", other)
	}

	now = now.Add(fragCookieRotate)
	assert.True(t, c.valid(key, cookie, now), "the previous secret is still accepted")
	assert.NotEqual(t, cookie, c.make(key, now), "new cookies come from the new secret")

	now = now.Add(fragCookieRotate)
	assert.False(t, c.valid(key, cookie, now), "two rotations retire a cookie")

	t.Run("an idle stretch still retires cookies on time", func(t *testing.T) {
		now := time.Unix(1000, 0)
		c := newFragCookies(now)
		cookie := c.make(key, now)
		// Nothing is made or checked for a long while, but the handshake manager ticks every retry interval.
		for end := now.Add(10 * fragCookieRotate); now.Before(end); now = now.Add(DefaultHandshakeTryInterval) {
			c.tick(now)
		}
		assert.False(t, c.valid(key, cookie, now))
	})
}

// Fragmented handshake packets have counters of their own, so they neither land in other nor inflate the
// single-packet handshake counts.
func TestFragmentedMessageMetrics(t *testing.T) {
	mm := newMessageMetrics()
	count := func(name string) int64 { return metrics.GetOrRegisterCounter(name, nil).Count() }
	names := []string{
		"messages.tx.handshake_ixpsk0", "messages.tx.handshake_ixpsk0_fragmented", "messages.tx.handshake_xxpsk0_fragmented",
		"messages.rx.handshake_ixpsk0_fragmented", "messages.tx.other",
	}
	before := map[string]int64{}
	for _, n := range names {
		before[n] = count(n)
	}

	mm.Tx(header.Handshake, header.HandshakeIXPSK0Fragmented, 5)
	mm.Tx(header.Handshake, header.HandshakeXXPSK0Fragmented, 2)
	mm.Rx(header.Handshake, header.HandshakeIXPSK0Fragmented, 3)
	mm.Tx(header.Handshake, header.HandshakeIXPSK0, 1)
	mm.Tx(header.Handshake, header.HandshakeXXPSK0, 1)
	mm.Tx(header.Handshake, 0x7f, 1)

	delta := func(n string) int64 { return count(n) - before[n] }
	assert.Equal(t, int64(5), delta("messages.tx.handshake_ixpsk0_fragmented"))
	assert.Equal(t, int64(2), delta("messages.tx.handshake_xxpsk0_fragmented"))
	assert.Equal(t, int64(3), delta("messages.rx.handshake_ixpsk0_fragmented"))
	assert.Equal(t, int64(1), delta("messages.tx.handshake_ixpsk0"))
	assert.Equal(t, int64(2), delta("messages.tx.other"), "subtypes without a counter, xx_psk0 among them")
}

// testMsg1 is a msg1 packet carrying msg after its header, as the handshake Machine writes it.
func testMsg1(msg []byte) []byte {
	pkt := header.Encode(make([]byte, header.Len, header.Len+len(msg)), header.Version, header.Handshake, header.HandshakeIXPSK0, 0, 1)
	return append(pkt, msg...)
}

// msg1Fragment builds the first fragment of a msg1, optionally with a cookie.
func msg1Fragment(t *testing.T, fragID uint32, cookie *fragment.Cookie) ([]byte, *header.H) {
	t.Helper()
	s, err := fragment.NewSender(testMsg1(make([]byte, 2000)), fragID)
	require.NoError(t, err)
	if cookie != nil {
		s.SetCookie(*cookie)
	}
	pkts, _, err := s.Attempt(0)
	require.NoError(t, err)
	var h header.H
	require.NoError(t, h.Parse(pkts[0]))
	return pkts[0], &h
}

// fillFragTable puts the responder's msg1 table at the cookie threshold.
func fillFragTable(t *testing.T, hm *HandshakeManager) {
	t.Helper()
	now := time.Now()
	for i := 0; hm.fragTable.Load() < fragCookieLoad; i++ {
		p, _ := msg1Fragment(t, uint32(i+1), nil)
		fh, sym, err := fragment.Parse(p[header.Len:])
		require.NoError(t, err)
		addr := netip.AddrPortFrom(netip.AddrFrom4([4]byte{198, 18, byte(i >> 8), byte(i)}), 4242)
		key, src := fragKeyFor(ViaSender{UdpAddr: addr}, fh.FragID)
		_, err = hm.fragTable.Add(key, src, now, fh, sym)
		require.NoError(t, err)
	}
}

func TestFragCookieUnderLoad(t *testing.T) {
	hm, conn := newFragTestManager(t)
	via := ViaSender{UdpAddr: netip.MustParseAddrPort("192.0.2.1:4242")}

	t.Run("no cookie needed below the threshold", func(t *testing.T) {
		p, h := msg1Fragment(t, 5000, nil)
		before := hm.fragTable.Len()
		hm.handleFragment(via, p, h)
		assert.Empty(t, conn.take())
		assert.Equal(t, before+1, hm.fragTable.Len())
	})

	fillFragTable(t, hm)

	var cookie fragment.Cookie
	t.Run("a fragment without a cookie gets one and leaves no state", func(t *testing.T) {
		p, h := msg1Fragment(t, 7, nil)
		before := hm.fragTable.Len()
		hm.handleFragment(via, p, h)
		assert.Equal(t, before, hm.fragTable.Len())

		sent := conn.take()
		require.Len(t, sent, 1)
		reply := sent[0]
		require.Len(t, reply, fragCookieReplyLen)
		var rh header.H
		require.NoError(t, rh.Parse(reply))
		assert.Equal(t, header.Handshake, rh.Type)
		assert.Equal(t, header.HandshakeIXPSK0Fragmented, rh.Subtype)
		assert.Equal(t, uint32(7), rh.RemoteIndex, "the reply names the initiator's FragID")
		assert.Equal(t, uint64(fragCookieCounter), rh.MessageCounter)
		copy(cookie[:], reply[header.Len:])
	})

	t.Run("a forged cookie gets a fresh one", func(t *testing.T) {
		bad := cookie
		bad[0] ^= 1
		p, h := msg1Fragment(t, 7, &bad)
		before := hm.fragTable.Len()
		hm.handleFragment(via, p, h)
		assert.Equal(t, before, hm.fragTable.Len())
		assert.Len(t, conn.take(), 1)
	})

	t.Run("the cookie gets the fragment in", func(t *testing.T) {
		p, h := msg1Fragment(t, 7, &cookie)
		before := hm.fragTable.Len()
		hm.handleFragment(via, p, h)
		assert.Equal(t, before+1, hm.fragTable.Len())
		assert.Empty(t, conn.take())
	})

	t.Run("a cookie is bound to its address", func(t *testing.T) {
		p, h := msg1Fragment(t, 7, &cookie)
		hm.handleFragment(ViaSender{UdpAddr: netip.MustParseAddrPort("192.0.2.99:4242")}, p, h)
		assert.Len(t, conn.take(), 1, "another address gets its own cookie instead")
	})

	t.Run("a reply never outgrows what prompted it", func(t *testing.T) {
		p, h := msg1Fragment(t, 8, nil)
		hm.sendCookie(via, header.HandshakeIXPSK0, 8, fragKey{}, fragCookieReplyLen-1, time.Now())
		assert.Empty(t, conn.take())
		hm.handleFragment(via, p, h)
		assert.Len(t, conn.take(), 1)
	})
}

// never turns fragment support off: msg1 fragments and cookie replies are dropped unread, as a node without it would.
func TestNeverDropsFragments(t *testing.T) {
	hm, conn := newFragTestManager(t)
	via := ViaSender{UdpAddr: netip.MustParseAddrPort("192.0.2.1:4242")}
	hh := &HandshakeHostInfo{ready: true, hostinfo: &HostInfo{localIndexId: 99, HandshakePacket: map[uint8][]byte{handshakePacketStage0: make([]byte, header.Len+600)}}}
	hm.indexes[99] = hh

	hm.frag.Store(&fragmentConfig{mode: fragmentNever})
	p, h := msg1Fragment(t, 7, nil)
	hm.HandleIncoming(via, p, h)
	assert.Zero(t, hm.fragTable.Len())
	reply, rh := cookieReply(t, 99, 0xab)
	hm.HandleIncoming(via, reply, rh)
	assert.Nil(t, hh.sender)
	assert.Empty(t, conn.take())

	hm.frag.Store(&fragmentConfig{mode: fragmentAuto})
	hm.HandleIncoming(via, p, h)
	assert.Equal(t, 1, hm.fragTable.Len(), "auto reassembles")
}

// cookieReply builds a responder's cookie reply naming index.
func cookieReply(t *testing.T, index uint32, cookie byte) ([]byte, *header.H) {
	t.Helper()
	reply := make([]byte, header.Len, fragCookieReplyLen)
	header.Encode(reply, header.Version, header.Handshake, header.HandshakeIXPSK0Fragmented, index, fragCookieCounter)
	reply = append(reply, bytes16(cookie)...)
	var h header.H
	require.NoError(t, h.Parse(reply))
	return reply, &h
}

func TestHandleCookie(t *testing.T) {
	hm, conn := newFragTestManager(t)
	via := ViaSender{UdpAddr: netip.MustParseAddrPort("192.0.2.1:4242")}

	// A msg1 that was going as one packet switches to fragments, since only a fragment carries a cookie.
	stage0 := make([]byte, header.Len, header.Len+600)
	header.Encode(stage0, header.Version, header.Handshake, header.HandshakeIXPSK0, 0, 1)
	stage0 = append(stage0, make([]byte, 600)...)
	hh := &HandshakeHostInfo{
		ready:       true,
		hostinfo:    &HostInfo{localIndexId: 99, HandshakePacket: map[uint8][]byte{handshakePacketStage0: stage0}},
		lastRemotes: []netip.AddrPort{via.UdpAddr},
	}
	hm.indexes[99] = hh

	reply, h := cookieReply(t, 99, 0xab)
	hm.handleFragment(via, reply, h)
	require.NotNil(t, hh.sender)
	sent := conn.take()
	require.NotEmpty(t, sent, "an immediate resend")
	for _, p := range sent {
		var ph header.H
		require.NoError(t, ph.Parse(p))
		assert.Equal(t, header.HandshakeIXPSK0Fragmented, ph.Subtype)
		assert.Equal(t, uint64(1), ph.MessageCounter)
		fh, _, err := fragment.Parse(p[header.Len:])
		require.NoError(t, err)
		assert.True(t, fh.HasCookie())
		assert.Equal(t, fragment.Cookie(bytes16(0xab)), fh.Cookie)
		assert.Equal(t, uint32(99), fh.FragID, "named by the initiator's index, as the cookie is")
	}

	hm.handleFragment(via, reply, h)
	assert.Empty(t, conn.take(), "immediate resends are rate limited")

	t.Run("replies for other indexes are ignored", func(t *testing.T) {
		other, oh := cookieReply(t, 98, 0xab)
		hh.cookieResendAt = time.Time{}
		hm.handleFragment(via, other, oh)
		assert.Empty(t, conn.take())
	})

	t.Run("a reply of the wrong size is ignored", func(t *testing.T) {
		hh.cookieResendAt = time.Time{}
		hm.handleFragment(via, reply[:len(reply)-1], h)
		assert.Empty(t, conn.take())
	})

	t.Run("a reply from an address the attempt was not sent to only sets the cookie", func(t *testing.T) {
		// Anyone who knows the index can forge a reply, so its source may be a victim's address.
		elsewhere := ViaSender{UdpAddr: netip.MustParseAddrPort("198.51.100.7:4242")}
		forged, fh := cookieReply(t, 99, 0xcd)
		hh.cookieResendAt = time.Time{}
		hm.handleFragment(elsewhere, forged, fh)
		assert.Empty(t, conn.take(), "no resend to it")

		// The cookie still rides on the next attempt.
		now, later, err := hh.stage0Packets()
		require.NoError(t, err)
		fragH, _, err := fragment.Parse(append(now, later...)[0][header.Len:])
		require.NoError(t, err)
		assert.Equal(t, fragment.Cookie(bytes16(0xcd)), fragH.Cookie)
	})
}

func bytes16(b byte) []byte {
	out := make([]byte, 16)
	for i := range out {
		out[i] = b
	}
	return out
}

func msg2Fragments(t *testing.T, msg []byte, fragID uint32) [][]byte {
	t.Helper()
	pkt := header.Encode(make([]byte, header.Len, header.Len+len(msg)), header.Version, header.Handshake, header.HandshakeIXPSK0, 7, 2)
	s, err := fragment.NewSender(append(pkt, msg...), fragID)
	require.NoError(t, err)
	now, later, err := s.Attempt(fragment.DefaultRepair(s.Layout().K))
	require.NoError(t, err)
	return append(now, later...)
}

// feedMsg2 puts one packet through an attempt's slots.
func feedMsg2(t *testing.T, hh *HandshakeHostInfo, p []byte) (*fragment.Assembly, fragment.Header, bool) {
	t.Helper()
	fh, sym, err := fragment.Parse(p[header.Len:])
	require.NoError(t, err)
	a := hh.slotFor(fh)
	require.NotNil(t, a)
	ready, err := a.Add(fh, sym)
	require.NoError(t, err)
	return a, fh, ready
}

func slotsUsed(hh *HandshakeHostInfo) (n int, ids []uint32) {
	for _, s := range hh.msg2 {
		if s.a != nil {
			n++
			ids = append(ids, s.fragID)
		}
	}
	return n, ids
}

// TestMsg2Slots interleaves two responders' msg2 bursts, the shape two hosts answering the same msg1 produce on a LAN,
// and checks each fills its own slot.
func TestMsg2Slots(t *testing.T) {
	msgB := make([]byte, 9625) // k = 9
	msgC := make([]byte, 9625)
	for i := range msgB {
		msgB[i], msgC[i] = 'b', 'c'
	}
	pktsB := msg2Fragments(t, msgB, 1001)
	pktsC := msg2Fragments(t, msgC, 2002)
	require.Len(t, pktsB, 12)

	// B0 B1 C0 B2 B3 B4 C1 C2 B5 B6 B7 B8 C3: no run of one FragID reaches nine, so a single slot emptied on every
	// change would never complete.
	order := []struct {
		fromC bool
		i     int
	}{{false, 0}, {false, 1}, {true, 0}, {false, 2}, {false, 3}, {false, 4}, {true, 1}, {true, 2}, {false, 5}, {false, 6}, {false, 7}, {false, 8}, {true, 3}}

	hh := &HandshakeHostInfo{}
	var got []byte
	for n, o := range order {
		p := pktsB[o.i]
		if o.fromC {
			p = pktsC[o.i]
		}
		a, _, ready := feedMsg2(t, hh, p)
		if !ready {
			continue
		}
		require.Equal(t, 11, n, "B completes on its ninth symbol")
		msg, err := a.Decode(nil)
		require.NoError(t, err)
		got = msg
		hh.dropSlot(a)
	}
	require.Equal(t, msgB, got)

	n, ids := slotsUsed(hh)
	assert.Equal(t, 1, n)
	assert.Equal(t, []uint32{2002}, ids, "B's slot was released, C's kept")

	// C's four symbols survived B's completion, so five more finish it.
	var c *fragment.Assembly
	var ready bool
	for i := 4; i < 9; i++ {
		c, _, ready = feedMsg2(t, hh, pktsC[i])
		assert.Equal(t, i == 8, ready, "symbol %d", i)
	}
	msg, err := c.Decode(nil)
	require.NoError(t, err)
	assert.Equal(t, msgC, msg)

	t.Run("a third responder takes the slot holding the least", func(t *testing.T) {
		hh := &HandshakeHostInfo{}
		feedMsg2(t, hh, pktsB[0])
		feedMsg2(t, hh, pktsB[1])
		feedMsg2(t, hh, pktsC[0])
		pktsD := msg2Fragments(t, msgC, 3003)
		d, fh, _ := feedMsg2(t, hh, pktsD[0])
		_, ids := slotsUsed(hh)
		assert.ElementsMatch(t, []uint32{1001, 3003}, ids)

		l, err := fh.Layout()
		require.NoError(t, err)
		b, _, _ := feedMsg2(t, hh, pktsB[2])
		assert.Equal(t, 3*l.SymbolSize, b.Stored(), "B kept its symbols")
		assert.Equal(t, l.SymbolSize, d.Stored())
	})

	t.Run("a different MsgLen under the same FragID starts the slot over", func(t *testing.T) {
		hh := &HandshakeHostInfo{}
		feedMsg2(t, hh, pktsB[0])
		feedMsg2(t, hh, pktsB[1])
		shorter := msg2Fragments(t, msgB[:9000], 1001)
		a, fh, _ := feedMsg2(t, hh, shorter[0])
		l, err := fh.Layout()
		require.NoError(t, err)
		assert.Equal(t, l.SymbolSize, a.Stored())
		n, ids := slotsUsed(hh)
		assert.Equal(t, 1, n)
		assert.Equal(t, []uint32{1001}, ids)
	})

	t.Run("fragments for a handshake no longer pending take no slot", func(t *testing.T) {
		hm, _ := newFragTestManager(t)
		hh := &HandshakeHostInfo{hostinfo: &HostInfo{localIndexId: 42}}
		fh, sym, err := fragment.Parse(pktsB[0][header.Len:])
		require.NoError(t, err)
		hm.continueFragmented(ViaSender{}, hh, &header.H{RemoteIndex: 42, MessageCounter: 2}, fh, sym)
		n, _ := slotsUsed(hh)
		assert.Zero(t, n)
	})
}
