package nebula

import (
	"crypto/sha256"
	"math/rand/v2"
	"net/netip"
	"sync"
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

func newPQTestManager(t *testing.T) (*HandshakeManager, *recordingConn) {
	l := test.NewLogger()
	conn := &recordingConn{}
	cfg := defaultHandshakeConfig
	cfg.pq = pqHandshakeConfig{initiate: true, accept: true}
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

// fragmentIndexes checks every packet is a fragment of the expected response and
// returns their symbol indexes.
func fragmentIndexes(t *testing.T, pkts [][]byte, fragID, remoteIndex uint32) []int {
	t.Helper()
	var out []int
	for _, p := range pkts {
		require.LessOrEqual(t, len(p), fragment.MaxPacketLen)
		var h header.H
		require.NoError(t, h.Parse(p))
		assert.Equal(t, header.HandshakeIXHybridMLKEM1024, h.Subtype)
		assert.Equal(t, remoteIndex, h.RemoteIndex)
		assert.Equal(t, uint64(2), h.MessageCounter)
		fh, _, err := fragment.Parse(p[header.Len:])
		require.NoError(t, err)
		assert.Equal(t, fragID, fh.FragID)
		out = append(out, int(fh.Index))
	}
	return out
}

func TestSendFragmentedResponse(t *testing.T) {
	hm, conn := newPQTestManager(t)
	via := ViaSender{UdpAddr: netip.MustParseAddrPort("192.0.2.1:4242")}
	hostinfo := &HostInfo{localIndexId: 77}

	// A 2000 byte message is 2 symbols of 1000, so packets of 1024 bytes.
	msg := make([]byte, header.Len, header.Len+2000)
	header.Encode(msg, header.Version, header.Handshake, header.HandshakeIXHybridMLKEM1024, 5, 2)
	r := rand.New(rand.NewPCG(1, 1))
	for range 2000 {
		msg = append(msg, byte(r.Uint32()))
	}
	const pktLen = header.Len + fragment.HeaderLen + 1000

	t.Run("first send", func(t *testing.T) {
		require.NoError(t, hm.sendFragmentedResponse(via, msg, hostinfo, false, 0))
		assert.Equal(t, []int{0, 1, 2, 3}, fragmentIndexes(t, conn.take(), 77, 5))
	})

	t.Run("resends are rate limited", func(t *testing.T) {
		require.Error(t, hm.sendFragmentedResponse(via, msg, hostinfo, true, 10*pktLen))
		assert.Empty(t, conn.take())
	})

	allowResend := func() {
		hostinfo.handshakeResendAt.Store(time.Now().Add(-time.Second).UnixNano())
	}

	t.Run("resend offers fresh symbols", func(t *testing.T) {
		allowResend()
		require.NoError(t, hm.sendFragmentedResponse(via, msg, hostinfo, true, 10*pktLen))
		assert.Equal(t, []int{4, 5, 6, 7}, fragmentIndexes(t, conn.take(), 77, 5))
	})

	t.Run("amplification budget trims repair", func(t *testing.T) {
		allowResend()
		// 3x of a little over one packet allows 3 packets: both data and 1 repair.
		require.NoError(t, hm.sendFragmentedResponse(via, msg, hostinfo, true, pktLen+10))
		assert.Equal(t, []int{8, 9, 10}, fragmentIndexes(t, conn.take(), 77, 5))
	})

	t.Run("amplification budget below the data refuses", func(t *testing.T) {
		allowResend()
		require.Error(t, hm.sendFragmentedResponse(via, msg, hostinfo, true, pktLen/2))
		assert.Empty(t, conn.take())
	})
}

func TestPQAnswered(t *testing.T) {
	now := time.Unix(1000, 0)
	a := newPQAnswered(5 * time.Second)
	hi := &HostInfo{}

	assert.Nil(t, a.lookup(sha256.Sum256([]byte("msg1")), now))
	a.add([]byte("msg1"), hi, now)
	assert.Same(t, hi, a.lookup(sha256.Sum256([]byte("msg1")), now.Add(time.Second)))
	assert.Nil(t, a.lookup(sha256.Sum256([]byte("other")), now))
	assert.Nil(t, a.lookup(sha256.Sum256([]byte("msg1")), now.Add(6*time.Second)), "stale entries are not answered")

	a.expire(now.Add(6 * time.Second))
	assert.Empty(t, a.entries)

	for i := range pqAnsweredMax + 10 {
		a.add([]byte{byte(i), byte(i >> 8)}, hi, now)
	}
	assert.Len(t, a.entries, pqAnsweredMax)
}

func TestPQFragKeyFor(t *testing.T) {
	k1, s1 := pqFragKeyFor(ViaSender{UdpAddr: netip.MustParseAddrPort("192.0.2.1:4242")}, 9)
	k2, s2 := pqFragKeyFor(ViaSender{UdpAddr: netip.MustParseAddrPort("192.0.2.1:4243")}, 9)
	assert.NotEqual(t, k1, k2, "different ports are different messages")
	assert.Equal(t, s1, s2, "but share an IPv4 /32 quota")

	_, s3 := pqFragKeyFor(ViaSender{UdpAddr: netip.MustParseAddrPort("[2001:db8::1]:1")}, 9)
	_, s4 := pqFragKeyFor(ViaSender{UdpAddr: netip.MustParseAddrPort("[2001:db8::ffff]:1")}, 9)
	assert.Equal(t, s3, s4, "an IPv6 /64 shares a quota")

	_, s5 := pqFragKeyFor(ViaSender{UdpAddr: netip.MustParseAddrPort("[::ffff:192.0.2.1]:1")}, 9)
	assert.Equal(t, s1, s5, "v4-mapped addresses count as IPv4")
}

func TestPQCookies(t *testing.T) {
	now := time.Unix(1000, 0)
	c := newPQCookies(now)
	key := pqFragKey{addr: netip.MustParseAddrPort("192.0.2.1:4242"), fragID: 9}

	cookie := c.make(key, now)
	assert.True(t, c.valid(key, cookie, now))

	for _, other := range []pqFragKey{
		{addr: netip.MustParseAddrPort("192.0.2.2:4242"), fragID: 9},
		{addr: netip.MustParseAddrPort("192.0.2.1:4243"), fragID: 9},
		{addr: netip.MustParseAddrPort("192.0.2.1:4242"), fragID: 10},
		{addr: netip.MustParseAddrPort("192.0.2.1:4242"), relay: 1, fragID: 9},
	} {
		assert.False(t, c.valid(other, cookie, now), "%+v", other)
	}

	now = now.Add(pqCookieRotate)
	assert.True(t, c.valid(key, cookie, now), "the previous secret is still accepted")
	assert.NotEqual(t, cookie, c.make(key, now), "new cookies come from the new secret")

	now = now.Add(pqCookieRotate)
	assert.False(t, c.valid(key, cookie, now), "two rotations retire a cookie")
}

// pqMsg1Fragment builds the first fragment of a msg1, optionally with a cookie.
func pqMsg1Fragment(t *testing.T, fragID uint32, cookie *fragment.Cookie) ([]byte, *header.H) {
	t.Helper()
	s, err := fragment.NewSender(make([]byte, 2000), header.HandshakeIXHybridMLKEM1024, 0, 1, fragID)
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

// fillPQTable puts the responder's msg1 table at the cookie threshold.
func fillPQTable(t *testing.T, hm *HandshakeManager) {
	t.Helper()
	now := time.Now()
	for i := 0; hm.pqTable.Load() < pqCookieLoad; i++ {
		p, _ := pqMsg1Fragment(t, uint32(i+1), nil)
		fh, sym, err := fragment.Parse(p[header.Len:])
		require.NoError(t, err)
		addr := netip.AddrPortFrom(netip.AddrFrom4([4]byte{198, 18, byte(i >> 8), byte(i)}), 4242)
		key, src := pqFragKeyFor(ViaSender{UdpAddr: addr}, fh.FragID)
		_, err = hm.pqTable.Add(key, src, now, fh, sym)
		require.NoError(t, err)
	}
}

func TestPQCookieUnderLoad(t *testing.T) {
	hm, conn := newPQTestManager(t)
	via := ViaSender{UdpAddr: netip.MustParseAddrPort("192.0.2.1:4242")}

	t.Run("no cookie needed below the threshold", func(t *testing.T) {
		p, h := pqMsg1Fragment(t, 5000, nil)
		before := hm.pqTable.Len()
		hm.handleFragment(via, p, h)
		assert.Empty(t, conn.take())
		assert.Equal(t, before+1, hm.pqTable.Len())
	})

	fillPQTable(t, hm)

	var cookie fragment.Cookie
	t.Run("a fragment without a cookie gets one and leaves no state", func(t *testing.T) {
		p, h := pqMsg1Fragment(t, 7, nil)
		before := hm.pqTable.Len()
		hm.handleFragment(via, p, h)
		assert.Equal(t, before, hm.pqTable.Len())

		sent := conn.take()
		require.Len(t, sent, 1)
		reply := sent[0]
		require.Len(t, reply, pqCookieReplyLen)
		var rh header.H
		require.NoError(t, rh.Parse(reply))
		assert.Equal(t, header.Handshake, rh.Type)
		assert.Equal(t, header.HandshakeIXHybridMLKEM1024, rh.Subtype)
		assert.Equal(t, uint32(7), rh.RemoteIndex, "the reply names the initiator's FragID")
		assert.Equal(t, uint64(pqCookieCounter), rh.MessageCounter)
		copy(cookie[:], reply[header.Len:])
	})

	t.Run("a forged cookie gets a fresh one", func(t *testing.T) {
		bad := cookie
		bad[0] ^= 1
		p, h := pqMsg1Fragment(t, 7, &bad)
		before := hm.pqTable.Len()
		hm.handleFragment(via, p, h)
		assert.Equal(t, before, hm.pqTable.Len())
		assert.Len(t, conn.take(), 1)
	})

	t.Run("the cookie gets the fragment in", func(t *testing.T) {
		p, h := pqMsg1Fragment(t, 7, &cookie)
		before := hm.pqTable.Len()
		hm.handleFragment(via, p, h)
		assert.Equal(t, before+1, hm.pqTable.Len())
		assert.Empty(t, conn.take())
	})

	t.Run("a cookie is bound to its address", func(t *testing.T) {
		p, h := pqMsg1Fragment(t, 7, &cookie)
		hm.handleFragment(ViaSender{UdpAddr: netip.MustParseAddrPort("192.0.2.99:4242")}, p, h)
		assert.Len(t, conn.take(), 1, "another address gets its own cookie instead")
	})

	t.Run("a reply never outgrows what prompted it", func(t *testing.T) {
		p, h := pqMsg1Fragment(t, 8, nil)
		hm.sendCookie(via, header.HandshakeIXHybridMLKEM1024, fragment.Header{FragID: 8}, pqFragKey{}, pqCookieReplyLen-1, time.Now())
		assert.Empty(t, conn.take())
		hm.handleFragment(via, p, h)
		assert.Len(t, conn.take(), 1)
	})
}

func TestPQHandleCookie(t *testing.T) {
	hm, conn := newPQTestManager(t)
	via := ViaSender{UdpAddr: netip.MustParseAddrPort("192.0.2.1:4242")}

	s, err := fragment.NewSender(make([]byte, 2000), header.HandshakeIXHybridMLKEM1024, 0, 1, 99)
	require.NoError(t, err)
	_, _, err = s.Attempt(2)
	require.NoError(t, err)
	hh := &HandshakeHostInfo{hostinfo: &HostInfo{}, pq: &pqAttempt{index: 99, sender: s}}
	hm.indexes[99] = hh

	reply := make([]byte, header.Len, pqCookieReplyLen)
	header.Encode(reply, header.Version, header.Handshake, header.HandshakeIXHybridMLKEM1024, 99, pqCookieCounter)
	reply = append(reply, bytes16(0xab)...)
	var h header.H
	require.NoError(t, h.Parse(reply))

	hm.handleFragment(via, reply, &h)
	assert.True(t, hh.pq.heard, "a cookie reply shows the peer speaks PQ")
	sent := conn.take()
	require.Len(t, sent, 4, "an immediate resend of fresh symbols")
	for i, p := range sent {
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
		header.Encode(other, header.Version, header.Handshake, header.HandshakeIXHybridMLKEM1024, 98, pqCookieCounter)
		var oh header.H
		require.NoError(t, oh.Parse(other))
		hh.pq.cookieResendAt = time.Time{}
		hm.handleFragment(via, other, &oh)
		assert.Empty(t, conn.take())
	})
}

func bytes16(b byte) []byte {
	out := make([]byte, 16)
	for i := range out {
		out[i] = b
	}
	return out
}

func TestReloadPQ(t *testing.T) {
	l := test.NewLogger()
	c := config.NewC(l)
	require.NoError(t, c.LoadString(`handshakes: {pq: {initiate: false}}`))
	cfg := defaultHandshakeConfig
	cfg.pq = pqHandshakeConfigFrom(c)
	hm := NewHandshakeManager(l, newHostMap(l), newTestLighthouse(), &udp.NoopConn{}, cfg)
	hm.f = &Interface{pki: newV3TestPKI(t)}
	c.RegisterReloadCallback(hm.reloadPQ)

	assert.Equal(t, pqHandshakeConfig{repairDelay: DefaultPQRepairDelay}, *hm.pqConfig())

	require.NoError(t, c.ReloadConfigString(`handshakes: {pq: {initiate: true, accept: true, sticky: true, repair_delay: 25ms}}`))
	assert.Equal(t, pqHandshakeConfig{initiate: true, accept: true, sticky: true, repairDelay: 25 * time.Millisecond}, *hm.pqConfig())

	before := hm.pqConfig()
	require.NoError(t, c.ReloadConfigString(`handshakes: {try_interval: 1s, pq: {initiate: true, accept: true, sticky: true, repair_delay: 25ms}}`))
	assert.Same(t, before, hm.pqConfig(), "an unrelated change leaves the settings alone")

	require.NoError(t, c.ReloadConfigString(`handshakes: {}`))
	assert.Equal(t, pqHandshakeConfig{repairDelay: DefaultPQRepairDelay}, *hm.pqConfig(), "removing the section restores the defaults")

	require.NoError(t, c.ReloadConfigString(`handshakes: {pq: {require: true}}`))
	assert.Equal(t, pqHandshakeConfig{initiate: true, accept: true, require: true, repairDelay: DefaultPQRepairDelay}, *hm.pqConfig(), "require implies initiate and accept")
}

func TestUsePQ(t *testing.T) {
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

// msg2Fragments returns one attempt's packets carrying msg as a responder's msg2
// under fragID, data symbols first and then repair.
func msg2Fragments(t *testing.T, msg []byte, fragID uint32) [][]byte {
	t.Helper()
	s, err := fragment.NewSender(msg, header.HandshakeIXHybridMLKEM1024, 7, 2, fragID)
	require.NoError(t, err)
	now, later, err := s.Attempt(fragment.DefaultRepair(s.Layout().K))
	require.NoError(t, err)
	return append(now, later...)
}

// feedMsg2 puts one packet through an attempt's slots.
func feedMsg2(t *testing.T, pq *pqAttempt, p []byte) (*fragment.Assembly, fragment.Header, bool) {
	t.Helper()
	fh, sym, err := fragment.Parse(p[header.Len:])
	require.NoError(t, err)
	a := pq.slotFor(fh)
	require.NotNil(t, a)
	ready, err := a.Add(fh, sym)
	require.NoError(t, err)
	return a, fh, ready
}

func slotsUsed(pq *pqAttempt) (n int, ids []uint32) {
	for _, s := range pq.msg2 {
		if s.a != nil {
			n++
			ids = append(ids, s.fragID)
		}
	}
	return n, ids
}

// TestPQMsg2Slots interleaves two responders' msg2 bursts, the shape two hosts
// answering the same msg1 produce on a LAN, and checks each fills its own slot.
func TestPQMsg2Slots(t *testing.T) {
	msgB := make([]byte, 9625) // the hybrid msg2: k = 9
	msgC := make([]byte, 9625)
	for i := range msgB {
		msgB[i], msgC[i] = 'b', 'c'
	}
	pktsB := msg2Fragments(t, msgB, 1001)
	pktsC := msg2Fragments(t, msgC, 2002)
	require.Len(t, pktsB, 12)

	// B0 B1 C0 B2 B3 B4 C1 C2 B5 B6 B7 B8 C3: no run of one FragID reaches nine,
	// so a single slot emptied on every change would never complete.
	order := []struct {
		fromC bool
		i     int
	}{{false, 0}, {false, 1}, {true, 0}, {false, 2}, {false, 3}, {false, 4}, {true, 1}, {true, 2}, {false, 5}, {false, 6}, {false, 7}, {false, 8}, {true, 3}}

	pq := &pqAttempt{}
	var got []byte
	for n, o := range order {
		p := pktsB[o.i]
		if o.fromC {
			p = pktsC[o.i]
		}
		a, _, ready := feedMsg2(t, pq, p)
		if !ready {
			continue
		}
		require.Equal(t, 11, n, "B completes on its ninth symbol")
		msg, err := a.Decode()
		require.NoError(t, err)
		got = msg
		pq.dropSlot(a)
	}
	require.Equal(t, msgB, got)

	n, ids := slotsUsed(pq)
	assert.Equal(t, 1, n)
	assert.Equal(t, []uint32{2002}, ids, "B's slot was released, C's kept")

	// C's four symbols survived B's completion, so five more finish it.
	var c *fragment.Assembly
	var ready bool
	for i := 4; i < 9; i++ {
		c, _, ready = feedMsg2(t, pq, pktsC[i])
		assert.Equal(t, i == 8, ready, "symbol %d", i)
	}
	msg, err := c.Decode()
	require.NoError(t, err)
	assert.Equal(t, msgC, msg)

	t.Run("a third responder takes the slot holding the least", func(t *testing.T) {
		pq := &pqAttempt{}
		feedMsg2(t, pq, pktsB[0])
		feedMsg2(t, pq, pktsB[1])
		feedMsg2(t, pq, pktsC[0])
		pktsD := msg2Fragments(t, msgC, 3003)
		d, fh, _ := feedMsg2(t, pq, pktsD[0])
		_, ids := slotsUsed(pq)
		assert.ElementsMatch(t, []uint32{1001, 3003}, ids)

		l, err := fh.Layout()
		require.NoError(t, err)
		b, _, _ := feedMsg2(t, pq, pktsB[2])
		assert.Equal(t, 3*l.SymbolSize, b.Stored(), "B kept its symbols")
		assert.Equal(t, l.SymbolSize, d.Stored())
	})

	t.Run("a different MsgLen under the same FragID starts the slot over", func(t *testing.T) {
		pq := &pqAttempt{}
		feedMsg2(t, pq, pktsB[0])
		feedMsg2(t, pq, pktsB[1])
		shorter := msg2Fragments(t, msgB[:9000], 1001)
		a, fh, _ := feedMsg2(t, pq, shorter[0])
		l, err := fh.Layout()
		require.NoError(t, err)
		assert.Equal(t, l.SymbolSize, a.Stored())
		n, ids := slotsUsed(pq)
		assert.Equal(t, 1, n)
		assert.Equal(t, []uint32{1001}, ids)
	})

	t.Run("an oversize claim is dropped before it takes a slot", func(t *testing.T) {
		hm, _ := newPQTestManager(t)
		hh := &HandshakeHostInfo{hostinfo: &HostInfo{}, pq: &pqAttempt{index: 42}}
		hm.indexes[42] = hh
		fh := fragment.Header{FragID: 1001, MsgLen: pqMaxMsgLen + 1}
		l, err := fh.Layout()
		require.NoError(t, err)
		hm.continuePQ(ViaSender{}, hh, &header.H{RemoteIndex: 42, MessageCounter: 2}, fh, make([]byte, l.SymbolSize))
		n, _ := slotsUsed(hh.pq)
		assert.Zero(t, n)
		assert.False(t, hh.pq.heard)
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
	require.NoError(t, conf.ReloadConfigString(`handshakes: {pq: {require: true}}`))
	assert.False(t, hm.pqConfig().require, "require without a v3 certificate is refused on reload")

	// And when loading the pki.
	certPEM, err := c2.MarshalPEM()
	require.NoError(t, err)
	conf = config.NewC(l)
	conf.Settings["pki"] = map[string]any{"cert": string(certPEM), "key": string(keyPEM)}
	conf.Settings["handshakes"] = map[string]any{"pq": map[string]any{"require": true}}
	_, err = newCertStateFromConfig(conf, "aes")
	require.ErrorContains(t, err, "handshakes.pq.require needs a version 3 certificate")
}

// After answering a peer's hybrid msg1, its classical msg1s go unanswered for
// four retry intervals, and only for that peer.
func TestHybridCrossingWindow(t *testing.T) {
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
