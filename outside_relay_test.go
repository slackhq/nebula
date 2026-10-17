package nebula

import (
	"bytes"
	"net/netip"
	"sync"
	"testing"

	"github.com/flynn/noise"
	"github.com/gaissmai/bart"
	"github.com/rcrowley/go-metrics"
	"github.com/slackhq/nebula/header"
	"github.com/slackhq/nebula/noiseutil"
	"github.com/slackhq/nebula/overlay/batch"
	"github.com/slackhq/nebula/test"
	"github.com/slackhq/nebula/udp"
	"github.com/stretchr/testify/require"
)

type relayBatchWrite struct {
	packets [][]byte
	remotes []netip.AddrPort
	batched bool
}

type relayBatchConn struct {
	udp.NoopConn
	read   func(udp.EncReader, func())
	writes []relayBatchWrite
}

func (c *relayBatchConn) ListenOut(r udp.EncReader, flush func()) error {
	c.read(r, flush)
	return nil
}

func (c *relayBatchConn) WriteBatch(bufs [][]byte, addrs []netip.AddrPort) (int, error) {
	w := relayBatchWrite{remotes: append([]netip.AddrPort(nil), addrs...), batched: true}
	for _, b := range bufs {
		w.packets = append(w.packets, bytes.Clone(b))
	}
	c.writes = append(c.writes, w)
	return len(bufs), nil
}

func (c *relayBatchConn) WriteTo(b []byte, addr netip.AddrPort) error {
	c.writes = append(c.writes, relayBatchWrite{packets: [][]byte{bytes.Clone(b)}, remotes: []netip.AddrPort{addr}})
	return nil
}

func (c *relayBatchConn) packets() [][]byte {
	var packets [][]byte
	for _, w := range c.writes {
		packets = append(packets, w.packets...)
	}
	return packets
}

type relayBatchPath struct {
	f                  *Interface
	conn               *relayBatchConn
	source, target     *HostInfo
	incoming, outgoing *Relay
	sourceKey          noiseutil.CipherState
	cipher             noise.CipherFunc
	counter            uint64
}

// Separate cipher instances let the reference SendVia path use the same keys and
// counters without rewinding an AEAD instance (including FIPS nonce checks).
func relayBatchKey(cipher noise.CipherFunc, id byte) noiseutil.CipherState {
	suite := noise.NewCipherSuite(noise.DH25519, cipher, noise.HashSHA256)
	return noiseutil.NewCipherState(noise.UnsafeNewCipherState(suite, [32]byte{id}, 0), cipher)
}

func newRelayBatchPath(t *testing.T, cipher noise.CipherFunc) *relayBatchPath {
	t.Helper()
	l := test.NewLogger()
	conn := &relayBatchConn{}
	f := &Interface{
		ctx: t.Context(), l: l, hostMap: newHostMap(l), outside: conn,
		writers: []udp.Conn{conn}, lightHouse: &LightHouse{l: l},
		myVpnNetworksTable: &bart.Lite{}, metricTxDropped: metrics.NewCounter(),
		batchers: []*batch.MultiCoalescer{batch.NewMultiCoalescer(&capturingTun{}, l)},
	}
	f.connectionManager = &connectionManager{
		intf: f, relayUsed: map[uint32]struct{}{}, relayUsedLock: &sync.RWMutex{},
	}
	newHost := func(addr string, remote string, id byte) *HostInfo {
		h := &HostInfo{
			vpnAddrs: []netip.Addr{netip.MustParseAddr(addr)},
			ConnectionState: &ConnectionState{
				eKey: relayBatchKey(cipher, id), dKey: relayBatchKey(cipher, id), window: NewBits(ReplayWindow),
			},
			relayState: RelayState{relayForByAddr: map[netip.Addr]*Relay{}, relayForByIdx: map[uint32]*Relay{}},
		}
		u := netip.MustParseAddrPort(remote)
		h.remote.Store(&u)
		f.hostMap.Hosts[h.vpnAddrs[0]] = h
		return h
	}
	source := newHost("192.0.2.1", "198.51.100.1:4242", 1)
	target := newHost("192.0.2.2", "198.51.100.2:4242", 2)
	incoming := &Relay{Type: ForwardingType, State: Established, LocalIndex: 301, RemoteIndex: 302, PeerAddr: target.vpnAddrs[0]}
	outgoing := &Relay{Type: ForwardingType, State: Established, LocalIndex: 303, RemoteIndex: 304, PeerAddr: source.vpnAddrs[0]}
	source.relayState.InsertRelay(incoming.PeerAddr, incoming.LocalIndex, incoming)
	target.relayState.InsertRelay(outgoing.PeerAddr, outgoing.LocalIndex, outgoing)
	f.hostMap.Relays[incoming.LocalIndex] = source
	f.hostMap.Indexes[100] = source
	return &relayBatchPath{f: f, conn: conn, source: source, target: target, incoming: incoming, outgoing: outgoing, sourceKey: relayBatchKey(cipher, 1), cipher: cipher}
}

func (p *relayBatchPath) wrap(t *testing.T, payload []byte) []byte {
	t.Helper()
	p.counter++
	b := header.Encode(make([]byte, header.Len), header.Version, header.Message, header.MessageRelay, p.incoming.LocalIndex, p.counter)
	b = append(b, payload...)
	b, err := p.sourceKey.EncryptDanger(b, b, nil, p.counter, make([]byte, 12))
	require.NoError(t, err)
	return b
}

func (p *relayBatchPath) reference(payloads [][]byte) [][]byte {
	conn := &relayBatchConn{}
	f := &Interface{writers: []udp.Conn{conn}, connectionManager: p.f.connectionManager, l: p.f.l}
	h := &HostInfo{ConnectionState: &ConnectionState{eKey: relayBatchKey(p.cipher, 2)}}
	u := p.target.GetRemote()
	h.remote.Store(&u)
	for _, payload := range payloads {
		f.SendVia(h, p.outgoing, payload, make([]byte, 12), make([]byte, 0, len(payload)+header.MaxOverhead), false, 0)
	}
	return conn.packets()
}

func TestRelayReceiveBatch(t *testing.T) {
	for _, cipher := range []noise.CipherFunc{noiseutil.CipherAESGCM, noise.CipherChaChaPoly} {
		t.Run(cipher.CipherName(), func(t *testing.T) {
			p := newRelayBatchPath(t, cipher)
			const count = 8
			var payloads, wire [][]byte
			for i := range count * 2 {
				payload := bytes.Repeat([]byte{byte(i)}, 64)
				payloads = append(payloads, payload)
				wire = append(wire, p.wrap(t, payload))
			}
			want := p.reference(payloads)
			// Model a listener reusing the same slots for the next receive batch.
			buffers := make([][]byte, count)
			for i := range buffers {
				buffers[i] = make([]byte, len(wire[i]))
			}
			p.conn.read = func(r udp.EncReader, flush func()) {
				for b := range 2 {
					for i := range count {
						copy(buffers[i], wire[b*count+i])
						r(p.source.GetRemote(), buffers[i])
						require.Len(t, p.conn.writes, b, "forwarding waits for the batch boundary")
					}
					flush()
					require.Len(t, p.conn.writes, b+1, "flush must send before receive slots are reused")
					for _, buffer := range buffers {
						clear(buffer)
					}
				}
			}
			p.f.listenOut(0)
			require.Equal(t, want, p.conn.packets())
			for _, w := range p.conn.writes {
				require.True(t, w.batched)
				require.Len(t, w.packets, count)
				for _, remote := range w.remotes {
					require.Equal(t, p.target.GetRemote(), remote)
				}
			}
		})
	}
}

func TestRelayBatchDestinationChange(t *testing.T) {
	p := newRelayBatchPath(t, noise.CipherChaChaPoly)
	first, second := p.target.GetRemote(), netip.MustParseAddrPort("198.51.100.3:4242")
	remotes := []netip.AddrPort{first, first, second, second, first}
	var payloads, wire [][]byte
	for i := range remotes {
		payload := []byte{byte(i)}
		payloads = append(payloads, payload)
		wire = append(wire, p.wrap(t, payload))
	}
	want := p.reference(payloads)
	p.conn.read = func(r udp.EncReader, flush func()) {
		for i, remote := range remotes {
			p.target.remote.Store(&remote)
			r(p.source.GetRemote(), wire[i])
		}
		flush()
	}
	p.f.listenOut(0)
	require.Equal(t, want, p.conn.packets())
	require.Len(t, p.conn.writes, 3)
	for i, wantRemotes := range [][]netip.AddrPort{{first, first}, {second, second}, {first}} {
		require.Equal(t, wantRemotes, p.conn.writes[i].remotes)
	}
}

func TestRelayBatchCapacity(t *testing.T) {
	p := newRelayBatchPath(t, noise.CipherChaChaPoly)
	p.conn.read = func(r udp.EncReader, flush func()) {
		for i := range batch.SendBatchCap + 1 {
			r(p.source.GetRemote(), p.wrap(t, []byte{byte(i)}))
		}
		require.Len(t, p.conn.writes, 1)
		require.Len(t, p.conn.writes[0].packets, batch.SendBatchCap)
		flush()
	}
	p.f.listenOut(0)
	require.Len(t, p.conn.writes, 2)
	require.Len(t, p.conn.writes[1].packets, 1)
}

func TestRelayBatchBeforeResponse(t *testing.T) {
	for _, unknownRelay := range []bool{false, true} {
		name := "test request"
		if unknownRelay {
			name = "unknown relay"
		}
		t.Run(name, func(t *testing.T) {
			p := newRelayBatchPath(t, noise.CipherChaChaPoly)
			first, last := p.wrap(t, []byte("first")), p.wrap(t, []byte("last"))
			p.counter++
			request := header.Encode(make([]byte, header.Len), header.Version, header.Test, header.TestRequest, 100, p.counter)
			request, err := p.sourceKey.EncryptDanger(request, request, []byte("ping"), p.counter, make([]byte, 12))
			require.NoError(t, err)
			if unknownRelay {
				request = header.Encode(make([]byte, header.Len), header.Version, header.Message, header.MessageRelay, 999, p.counter)
			}
			p.conn.read = func(r udp.EncReader, flush func()) {
				r(p.source.GetRemote(), first)
				require.Empty(t, p.conn.writes)
				r(p.source.GetRemote(), request)
				require.Len(t, p.conn.writes, 2)
				r(p.source.GetRemote(), last)
				flush()
			}
			p.f.listenOut(0)
			require.Len(t, p.conn.writes, 3)
			require.True(t, p.conn.writes[0].batched)
			require.False(t, p.conn.writes[1].batched)
			require.True(t, p.conn.writes[2].batched)
			require.Equal(t, p.source.GetRemote(), p.conn.writes[1].remotes[0])
			h := &header.H{}
			require.NoError(t, h.Parse(p.conn.writes[1].packets[0]))
			if unknownRelay {
				require.Equal(t, header.RecvError, h.Type)
				require.EqualValues(t, 999, h.RemoteIndex)
			} else {
				require.Equal(t, header.Test, h.Type)
				require.Equal(t, header.TestReply, h.Subtype)
				reply := p.conn.writes[1].packets[0]
				out, err := p.sourceKey.DecryptDanger(nil, reply[:header.Len], reply[header.Len:], h.MessageCounter, make([]byte, 12))
				require.NoError(t, err)
				require.Equal(t, []byte("ping"), out)
			}
		})
	}
}

func TestRelayBatchRemovedTarget(t *testing.T) {
	for _, remove := range []string{"host", "relay", "disestablished"} {
		t.Run(remove, func(t *testing.T) {
			p := newRelayBatchPath(t, noise.CipherChaChaPoly)
			first, removed := p.wrap(t, []byte("first")), p.wrap(t, []byte("removed"))
			want := p.reference([][]byte{[]byte("first")})
			p.conn.read = func(r udp.EncReader, flush func()) {
				r(p.source.GetRemote(), first)
				switch remove {
				case "host":
					delete(p.f.hostMap.Hosts, p.target.vpnAddrs[0])
				case "relay":
					delete(p.target.relayState.relayForByAddr, p.source.vpnAddrs[0])
				case "disestablished":
					p.target.relayState.UpdateRelayForByIpState(p.source.vpnAddrs[0], Disestablished)
				}
				r(p.source.GetRemote(), removed)
				flush()
			}
			p.f.listenOut(0)
			require.Len(t, p.conn.writes, 1)
			require.Equal(t, want, p.conn.packets(), "only the packet accepted before removal is sent")
		})
	}
}
