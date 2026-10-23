package nebula

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/handshake/fragment"
	"github.com/slackhq/nebula/header"
)

// A handshake message too big for one packet, a certificate carrying many groups, names or networks say, travels as
// fragments: Reed-Solomon coded symbols of at most fragment.MaxPacketLen bytes each, marked by
// header.HandshakeFragmented on the subtype, so it never relies on IP fragmentation. See handshake/fragment for the
// wire format. The handshake itself is unchanged: a fragmented message is reassembled into the packet the handshake
// Machine would have received unfragmented.

const (
	// DefaultHandshakeRepairDelay is how long repair fragments trail the data fragments.
	DefaultHandshakeRepairDelay = 10 * time.Millisecond

	// fragAmplification bounds what a responder sends in reply to an unvalidated address, as a multiple of what it
	// received from it.
	fragAmplification = 3

	// fragMaxMsgLen bounds the fragmented handshake messages a node reassembles, msg1 in the responder's table and
	// msg2 in an initiator's slots: the most a fragment header's MsgLen can say.
	fragMaxMsgLen = 65535

	// fragMsg2Slots is how many responders' msg2s one attempt reassembles at once.
	fragMsg2Slots = 2
)

// fragmentMode says when this node sends its own handshake messages as fragments. It always reassembles fragments
// from others, whatever the mode.
type fragmentMode int

const (
	// fragmentAuto fragments a message too big for one packet, and answers a fragmented msg1 in fragments.
	fragmentAuto fragmentMode = iota
	// fragmentAlways fragments every handshake message.
	fragmentAlways
	// fragmentNever sends every message as one packet, as big as it is, relying on IP fragmentation.
	fragmentNever
)

func (m fragmentMode) String() string {
	switch m {
	case fragmentAlways:
		return "always"
	case fragmentNever:
		return "never"
	default:
		return "auto"
	}
}

// fragmentConfig is the handshakes.fragment settings.
type fragmentConfig struct {
	mode        fragmentMode
	repairDelay time.Duration
}

func fragmentConfigFrom(c *config.C) (fragmentConfig, error) {
	cfg := fragmentConfig{repairDelay: c.GetDuration("handshakes.repair_delay", DefaultHandshakeRepairDelay)}
	switch s := c.GetString("handshakes.fragment", "auto"); s {
	case "auto":
		cfg.mode = fragmentAuto
	case "always":
		cfg.mode = fragmentAlways
	case "never":
		cfg.mode = fragmentNever
	default:
		return cfg, fmt.Errorf("handshakes.fragment must be auto, always or never, not %q", s)
	}
	if cfg.repairDelay < 0 {
		return cfg, fmt.Errorf("handshakes.repair_delay must not be negative")
	}
	return cfg, nil
}

// fragConfig returns the fragment settings in effect.
func (hm *HandshakeManager) fragConfig() *fragmentConfig {
	return hm.frag.Load()
}

// reloadFragment applies changed fragment settings to the next message sent.
func (hm *HandshakeManager) reloadFragment(c *config.C, r *config.Reload) {
	if !c.HasChanged("handshakes.fragment") && !c.HasChanged("handshakes.repair_delay") {
		return
	}
	cfg, err := fragmentConfigFrom(c)
	if err != nil {
		hm.l.Error("Failed to reload handshake fragment settings, keeping the previous ones", "error", err)
		r.Failed()
		return
	}
	old := hm.fragConfig()
	hm.frag.Store(&cfg)
	hm.l.Info("Handshake fragment settings changed",
		"fragment", cfg.mode.String(), "oldFragment", old.mode.String(),
		"repairDelay", cfg.repairDelay, "oldRepairDelay", old.repairDelay,
	)
}

// shouldFragment decides whether a handshake message goes as fragments: always or never as configured, and otherwise
// when it does not fit one packet or answers a msg1 that came as fragments, whose sender can reassemble them. A
// message to a peer that can not reassemble goes as fragments anyway when it does not fit, since a packet that size
// would need IP fragmentation, which too many paths drop.
func (hm *HandshakeManager) shouldFragment(msgLen int, answeringFragments bool) bool {
	switch hm.fragConfig().mode {
	case fragmentAlways:
		return true
	case fragmentNever:
		return false
	default:
		return answeringFragments || msgLen > fragment.MaxPacketLen
	}
}

// fragTableConfig bounds the responder's reassembly of msg1 fragments from senders that have not authenticated yet.
var fragTableConfig = fragment.TableConfig{
	MaxBytes:     4 << 20,
	MaxEntries:   1024,
	MaxPerSource: 4,
	MaxMsgLen:    fragMaxMsgLen,
	TTL:          3 * time.Second,
}

// msg2Slot reassembles one responder's msg2.
type msg2Slot struct {
	fragID uint32
	msgLen uint16
	a      *fragment.Assembly
}

// slotFor returns the assembly collecting msg2 fragments with fh's FragID, starting one if there is none. A responder
// never changes its FragID or MsgLen, so a fragment whose MsgLen disagrees with its slot is a stray or a forgery and
// starts that slot over. When every slot is taken the one holding the least is replaced: a third responder is
// vanishingly rare, and a forged FragID could already spoil an attempt. It returns nil if no assembly can be made for
// fh.
func (hh *HandshakeHostInfo) slotFor(fh fragment.Header) *fragment.Assembly {
	victim := -1
	for i := range hh.msg2 {
		s := &hh.msg2[i]
		if s.a != nil && s.fragID == fh.FragID {
			if s.msgLen == fh.MsgLen {
				return s.a
			}
			victim = i
			break
		}
	}
	if victim < 0 {
		for i := range hh.msg2 {
			if hh.msg2[i].a == nil {
				victim = i
				break
			}
		}
	}
	if victim < 0 {
		victim = 0
		for i := 1; i < len(hh.msg2); i++ {
			if hh.msg2[i].a.Stored() < hh.msg2[victim].a.Stored() {
				victim = i
			}
		}
	}

	a, err := fragment.NewAssembly(fh)
	if err != nil {
		return nil
	}
	hh.msg2[victim] = msg2Slot{fragID: fh.FragID, msgLen: fh.MsgLen, a: a}
	return a
}

// dropSlot releases the slot holding a.
func (hh *HandshakeHostInfo) dropSlot(a *fragment.Assembly) {
	for i := range hh.msg2 {
		if hh.msg2[i].a == a {
			hh.msg2[i] = msg2Slot{}
		}
	}
}

// fragKey identifies one msg1 being reassembled.
type fragKey struct {
	addr   netip.AddrPort
	relay  uint32
	fragID uint32
}

// fragSource groups msg1 reassemblies for the per-source quota: an IPv4 /32, an IPv6 /64, or one relay channel.
type fragSource struct {
	prefix netip.Prefix
	relay  uint32
}

func fragKeyFor(via ViaSender, fragID uint32) (fragKey, fragSource) {
	if via.IsRelayed {
		return fragKey{relay: via.relay.LocalIndex, fragID: fragID},
			fragSource{relay: via.relay.LocalIndex}
	}
	addr := via.UdpAddr.Addr().Unmap()
	bits := 64
	if addr.Is4() {
		bits = 32
	}
	prefix, _ := addr.Prefix(bits)
	return fragKey{addr: via.UdpAddr, fragID: fragID}, fragSource{prefix: prefix}
}

// reassembled turns a decoded message into the packet the handshake Machine expects, unfragmented: the header of one
// of its fragments, less the fragmented flag, in the header.Len bytes left for it in front of the message.
func reassembled(h *header.H, pkt []byte) []byte {
	return header.Encode(pkt, header.Version, header.Handshake, header.HandshakePattern(h.Subtype), h.RemoteIndex, h.MessageCounter)[:len(pkt)]
}

// fragmentStage0 prepares the initiator's msg1 as fragments, named by its local index, when it should travel so.
func (hm *HandshakeManager) fragmentStage0(hh *HandshakeHostInfo, msg []byte) error {
	hh.sender = nil
	if !hm.shouldFragment(len(msg), false) {
		return nil
	}
	return hm.useFragments(hh, msg)
}

// useFragments makes the initiator's msg1 travel as fragments from now on.
func (hm *HandshakeManager) useFragments(hh *HandshakeHostInfo, msg []byte) error {
	var h header.H
	if err := h.Parse(msg); err != nil {
		return err
	}
	s, err := fragment.NewSender(msg[header.Len:], h.Subtype|header.HandshakeFragmented, h.RemoteIndex, h.MessageCounter, hh.hostinfo.localIndexId)
	if err != nil {
		return err
	}
	hh.sender = s
	return nil
}

// stage0Packets returns the packets of one attempt at the initiator's msg1: the single packet, or a fresh set of
// fragments, now immediately and later after the repair delay.
func (hh *HandshakeHostInfo) stage0Packets() (now, later [][]byte, err error) {
	if hh.sender == nil {
		return [][]byte{hh.hostinfo.HandshakePacket[handshakePacketStage0]}, nil, nil
	}
	return hh.sender.Attempt(fragment.DefaultRepair(hh.sender.Layout().K))
}

// handleFragment takes a fragment of a handshake message, or a cookie reply.
func (hm *HandshakeManager) handleFragment(via ViaSender, packet []byte, h *header.H) {
	if h.MessageCounter == fragCookieCounter {
		hm.handleCookie(via, packet, h)
		return
	}

	fh, sym, err := fragment.Parse(packet[header.Len:])
	if err != nil {
		hm.l.Debug("dropping malformed handshake fragment", "from", via, "error", err)
		return
	}

	switch h.MessageCounter {
	case 1:
		if h.RemoteIndex != 0 {
			hm.l.Debug("dropping stage-1 handshake with non-zero RemoteIndex",
				"from", via, "remoteIndex", h.RemoteIndex)
			return
		}
		now := time.Now()
		key, src := fragKeyFor(via, fh.FragID)
		validated := via.IsRelayed || (fh.HasCookie() && hm.cookies.valid(key, fh.Cookie, now))
		if hm.fragTable.Load() >= fragCookieLoad && !validated {
			hm.sendCookie(via, h.Subtype, fh.FragID, key, len(packet), now)
			return
		}
		res, err := hm.fragTable.Add(key, src, now, fh, sym)
		if err != nil {
			hm.l.Debug("dropping handshake fragment", "from", via, "error", err)
			return
		}
		if res == nil {
			return
		}
		in := msg1Info{fragmented: true, validated: validated, received: res.Received}
		if existing := hm.answered.lookup(res.Hash, now); existing != nil && !hm.stillAnswering(existing) {
			// The responder that answered is gone, timed out, failed or evicted: its msg2 would lead the initiator
			// into a tunnel no one holds. Answer afresh.
			hm.answered.forget(res.Hash)
		} else if existing != nil {
			// Already answered: resend with fresh symbols on the path this copy came by.
			if msg := existing.HandshakePacket[handshakePacketStage2]; msg != nil {
				hm.sendHandshakeResponse(via, msg, existing, true, in)
			}
			hm.fragTable.Answered(key, res, now)
			return
		}
		if res.Repeat {
			// Answered once, but long enough ago to be forgotten: start over.
			hm.fragTable.Forget(key)
			return
		}
		hm.beginHandshake(via, reassembled(h, res.Packet), h, in)
		if hm.answered.lookup(res.Hash, now) != nil {
			hm.fragTable.Answered(key, res, now)
		}

	case 2:
		if hh := hm.queryIndex(h.RemoteIndex); hh != nil {
			hm.continueFragmented(via, hh, h, fh, sym)
		}
	}
}

// continueFragmented collects msg2 fragments for an initiator's attempt, one slot per responder FragID, and processes
// the first msg2 to complete.
func (hm *HandshakeManager) continueFragmented(via ViaSender, hh *HandshakeHostInfo, h *header.H, fh fragment.Header, sym []byte) {
	if int(fh.MsgLen) > fragMaxMsgLen {
		return
	}

	hh.Lock()
	if cur := hm.queryIndex(hh.hostinfo.localIndexId); cur != hh {
		hh.Unlock()
		return
	}
	a := hh.slotFor(fh)
	if a == nil {
		hh.Unlock()
		return
	}
	ready, err := a.Add(fh, sym)
	if err != nil || !ready {
		hh.Unlock()
		return
	}
	pkt, err := a.Decode(make([]byte, header.Len))
	hh.dropSlot(a)
	hh.Unlock()
	if err != nil {
		hm.l.Debug("failed to decode handshake fragments", "from", via, "error", err)
		return
	}
	hm.continueHandshake(via, hh, reassembled(h, pkt))
}

// sendFragmented sends packets to a peer: now immediately and later after the repair delay. It returns the first error
// from the immediate sends; errors from delayed sends are only logged.
func (hm *HandshakeManager) sendFragmented(now, later [][]byte, send func([]byte) error) error {
	var first error
	for _, p := range now {
		if err := send(p); err != nil && first == nil {
			first = err
		}
	}
	sendLater := func() {
		for _, p := range later {
			if err := send(p); err != nil {
				hm.l.Debug("Failed to send handshake repair fragment", "error", err)
			}
		}
	}
	switch delay := hm.fragConfig().repairDelay; {
	case len(later) == 0:
	case delay <= 0:
		sendLater()
	default:
		time.AfterFunc(delay, sendLater)
	}
	return first
}

// msg1Info describes the msg1 a responder answers, for the fragment transport.
type msg1Info struct {
	fragmented bool // it came as fragments, so its sender reassembles them
	validated  bool // it came by a relay, or with a valid cookie, so its address is known to receive
	received   int  // the bytes it took, which bound the answer to an address not validated
}

// budget is how many bytes may answer the msg1 before its address is validated: any number for a validated one, -1,
// and fragAmplification times what it took otherwise.
func (in msg1Info) budget() int {
	if in.validated {
		return -1
	}
	return fragAmplification * in.received
}

// errOverBudget is a response bigger than its amplification budget allows.
var errOverBudget = errors.New("handshake response exceeds the amplification budget")

// sendFragmentedResponse sends the responder's msg2 as fragments, each send offering symbols the hostinfo has not sent
// before. The clock on resends is per path and lives in the fragment table: a copy of msg1 arriving by a second path
// (the other address family, a relay) is answered on that path at once, which carries the handshake when the first
// path only works one way, and a retry on a path is reported as a repeat at most once per retry interval. budget
// bounds the bytes sent before the address is validated, -1 for none; a response that does not fit it at all returns
// errOverBudget.
func (hm *HandshakeManager) sendFragmentedResponse(via ViaSender, msg []byte, hostinfo *HostInfo, budget int) error {
	var h header.H
	if err := h.Parse(msg); err != nil {
		return err
	}
	s, err := fragment.NewSender(msg[header.Len:], h.Subtype|header.HandshakeFragmented, h.RemoteIndex, h.MessageCounter, hostinfo.localIndexId)
	if err != nil {
		return err
	}

	l := s.Layout()
	repair := fragment.DefaultRepair(l.K)
	if budget >= 0 {
		pktLen := header.Len + fragment.HeaderLen + l.SymbolSize
		packets := budget / pktLen
		if packets < l.K {
			return errOverBudget
		}
		repair = min(repair, packets-l.K)
	}

	n := uint32(l.K + repair)
	s.SetNext(int(hostinfo.handshakeNextSymbol.Add(n) - n))
	pkts, later, err := s.Attempt(repair)
	if err != nil {
		return err
	}

	if via.IsRelayed {
		if via.relay == nil {
			return errors.New("both addr and via.relay are nil")
		}
		// We received a valid handshake on this relay, so make sure the relay
		// state reflects that, in case it had been marked Disestablished.
		hostinfo.relayState.InsertRelayTo(via.relayHI.vpnAddrs[0])
		via.relayHI.relayState.UpdateRelayForByIdxState(via.relay.LocalIndex, Established)
	}
	hm.f.messageMetrics.Tx(header.Handshake, h.Subtype|header.HandshakeFragmented, int64(len(pkts)+len(later)))
	return hm.sendFragmented(pkts, later, hm.sendTo(via))
}

// stillAnswering reports whether the hostinfo that answered a msg1 still holds its index as an established tunnel, so
// resending its msg2 can still lead somewhere.
func (hm *HandshakeManager) stillAnswering(hostinfo *HostInfo) bool {
	return hm.mainHostMap.QueryIndex(hostinfo.localIndexId) == hostinfo
}

// fragAnswered remembers the msg1s a responder recently answered, keyed by hash, so a repeat is recognised before any
// noise or certificate work. Repeats are routine: the trailing repair fragments of an attempt rebuild a msg1 that its
// data fragments already completed, and a retrying initiator offers fresh symbols for the same msg1. Entries only exist
// for completed handshakes, which need a valid certificate, and live as long as an initiator keeps retrying.
type fragAnswered struct {
	sync.Mutex
	ttl     time.Duration
	entries map[[sha256.Size]byte]fragAnsweredEntry
}

type fragAnsweredEntry struct {
	hostinfo *HostInfo
	at       time.Time
}

const fragAnsweredMax = 4096

func newFragAnswered(ttl time.Duration) *fragAnswered {
	return &fragAnswered{ttl: ttl, entries: map[[sha256.Size]byte]fragAnsweredEntry{}}
}

func (a *fragAnswered) add(msg1 []byte, hostinfo *HostInfo, now time.Time) {
	a.Lock()
	defer a.Unlock()
	if len(a.entries) >= fragAnsweredMax {
		for k := range a.entries {
			delete(a.entries, k)
			break
		}
	}
	a.entries[sha256.Sum256(msg1)] = fragAnsweredEntry{hostinfo: hostinfo, at: now}
}

// lookup finds the hostinfo that answered the msg1 with this hash.
func (a *fragAnswered) lookup(hash [sha256.Size]byte, now time.Time) *HostInfo {
	a.Lock()
	defer a.Unlock()
	e, ok := a.entries[hash]
	if !ok || now.Sub(e.at) > a.ttl {
		return nil
	}
	return e.hostinfo
}

// forget drops the entry for the msg1 with this hash.
func (a *fragAnswered) forget(hash [sha256.Size]byte) {
	a.Lock()
	defer a.Unlock()
	delete(a.entries, hash)
}

func (a *fragAnswered) expire(now time.Time) {
	a.Lock()
	defer a.Unlock()
	for k, e := range a.entries {
		if now.Sub(e.at) > a.ttl {
			delete(a.entries, k)
		}
	}
}

// A responder stops keeping state for senders that have not shown they receive at their address while its msg1 table
// is under load, and before sending one more than its amplification budget allows. It answers with a cookie reply and
// keeps nothing; the initiator resends msg1 as fragments with the cookie attached. This is WireGuard's under-load
// cookie, QUIC's Retry and SCTP's state cookie: one extra round trip, only when needed.
const (
	// fragCookieLoad is the table load above which msg1 fragments need a cookie.
	fragCookieLoad = 0.5

	// fragCookieCounter marks a cookie reply in the header's message counter. Handshake messages count from 1.
	fragCookieCounter = 0

	// fragCookieRotate is how often the cookie secret changes. A cookie stays valid for between one and two rotations.
	fragCookieRotate = 2 * time.Minute

	fragCookieReplyLen = header.Len + fragment.CookieLen
)

// fragCookies mints and checks cookies: an HMAC-SHA-512 over the sender's address (or relay channel) and FragID under
// a rotating secret, with the previous secret still accepted.
type fragCookies struct {
	sync.Mutex
	secrets   [2][64]byte
	rotatedAt time.Time
}

func newFragCookies(now time.Time) *fragCookies {
	c := &fragCookies{rotatedAt: now}
	_, _ = rand.Read(c.secrets[0][:])
	_, _ = rand.Read(c.secrets[1][:])
	return c
}

func (c *fragCookies) rotate(now time.Time) {
	if now.Sub(c.rotatedAt) < fragCookieRotate {
		return
	}
	c.secrets[1] = c.secrets[0]
	_, _ = rand.Read(c.secrets[0][:])
	c.rotatedAt = now
}

func cookieMAC(secret []byte, key fragKey) fragment.Cookie {
	mac := hmac.New(sha512.New, secret)
	addr := key.addr.Addr().As16()
	mac.Write(addr[:])
	var b [10]byte
	binary.BigEndian.PutUint16(b[0:], key.addr.Port())
	binary.BigEndian.PutUint32(b[2:], key.relay)
	binary.BigEndian.PutUint32(b[6:], key.fragID)
	mac.Write(b[:])
	var c fragment.Cookie
	copy(c[:], mac.Sum(nil))
	return c
}

func (c *fragCookies) make(key fragKey, now time.Time) fragment.Cookie {
	c.Lock()
	defer c.Unlock()
	c.rotate(now)
	return cookieMAC(c.secrets[0][:], key)
}

func (c *fragCookies) valid(key fragKey, cookie fragment.Cookie, now time.Time) bool {
	c.Lock()
	defer c.Unlock()
	c.rotate(now)
	for _, s := range c.secrets {
		want := cookieMAC(s[:], key)
		if hmac.Equal(want[:], cookie[:]) {
			return true
		}
	}
	return false
}

// sendCookie answers a msg1 with a cookie reply, naming the initiator by fragID. The reply is never larger than what
// triggered it, and replies are rate limited as a whole.
func (hm *HandshakeManager) sendCookie(via ViaSender, subtype header.MessageSubType, fragID uint32, key fragKey, received int, now time.Time) {
	if received < fragCookieReplyLen {
		return
	}
	if _, ok := hm.cookieLimiter.Allow(); !ok {
		return
	}
	c := hm.cookies.make(key, now)
	reply := make([]byte, header.Len, fragCookieReplyLen)
	header.Encode(reply, header.Version, header.Handshake, subtype|header.HandshakeFragmented, fragID, fragCookieCounter)
	reply = append(reply, c[:]...)
	hm.f.messageMetrics.Tx(header.Handshake, subtype|header.HandshakeFragmented, 1)
	if err := hm.sendTo(via)(reply); err != nil {
		hm.l.Debug("Failed to send handshake cookie", "to", via, "error", err)
	}
}

// handleCookie attaches a responder's cookie to the attempt it names, switching msg1 to fragments if it was a single
// packet, since only a fragment carries a cookie, and resends right away, at most once per retry interval, rather
// than waiting for the next attempt.
func (hm *HandshakeManager) handleCookie(via ViaSender, packet []byte, h *header.H) {
	if len(packet) != fragCookieReplyLen {
		return
	}
	hh := hm.queryIndex(h.RemoteIndex)
	if hh == nil {
		return
	}
	hh.Lock()
	defer hh.Unlock()
	if hm.queryIndex(hh.hostinfo.localIndexId) != hh || !hh.ready {
		return
	}
	if hh.sender == nil {
		if err := hm.useFragments(hh, hh.hostinfo.HandshakePacket[handshakePacketStage0]); err != nil {
			hm.l.Debug("Failed to fragment handshake for a cookie", "to", via, "error", err)
			return
		}
	}
	var c fragment.Cookie
	copy(c[:], packet[header.Len:])
	hh.sender.SetCookie(c)

	now := time.Now()
	if now.Sub(hh.cookieResendAt) < hm.config.tryInterval {
		return
	}
	hh.cookieResendAt = now
	pkts, later, err := hh.stage0Packets()
	if err != nil {
		return
	}
	hm.messageMetrics.Tx(header.Handshake, h.Subtype, int64(len(pkts)+len(later)))
	if err := hm.sendFragmented(pkts, later, hm.sendTo(via)); err != nil {
		hm.l.Debug("Failed to resend handshake with cookie", "to", via, "error", err)
	}
}

// sendTo returns a function sending a packet back the way via came: directly, or through the relay it arrived on.
func (hm *HandshakeManager) sendTo(via ViaSender) func([]byte) error {
	f := hm.f
	if !via.IsRelayed {
		return func(p []byte) error {
			return f.outside.WriteTo(p, via.UdpAddr)
		}
	}
	return func(p []byte) error {
		if via.relay == nil {
			return errors.New("both addr and via.relay are nil")
		}
		f.sendHandshakeVia(via.relayHI, via.relay, p)
		return nil
	}
}

// sendHandshakeVia sends a handshake packet through a relay, with buffers sized for the packet rather than the mtu:
// an unfragmented handshake message may be bigger than one.
func (f *Interface) sendHandshakeVia(via *HostInfo, relay *Relay, p []byte) {
	out := make([]byte, header.Len+len(p)+via.ConnectionState.eKey.Overhead())
	f.SendVia(via, relay, p, make([]byte, 12), out, false, 0)
}
