package nebula

import (
	"math/rand/v2"
	"net/netip"
	"sync"
	"testing"
	"time"

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
		l:                l,
	}
	return hm, conn
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
		assert.Equal(t, pqSubtype, h.Subtype)
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
	header.Encode(msg, header.Version, header.Handshake, pqSubtype, 5, 2)
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

	assert.Nil(t, a.lookup([]byte("msg1"), now))
	a.add([]byte("msg1"), hi, now)
	assert.Same(t, hi, a.lookup([]byte("msg1"), now.Add(time.Second)))
	assert.Nil(t, a.lookup([]byte("other"), now))
	assert.Nil(t, a.lookup([]byte("msg1"), now.Add(6*time.Second)), "stale entries are not answered")

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
