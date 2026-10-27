package nebula

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/handshake"
	"github.com/slackhq/nebula/handshake/fragment"
	"github.com/slackhq/nebula/header"
)

// A handshake message too big for one packet, a certificate carrying many groups, names or networks say, travels as
// fragments: Reed-Solomon coded symbols of at most fragment.MaxPacketLen bytes each, marked by the fragmented form of
// the handshake subtype, such as header.HandshakeIXPSK0Fragmented, so it never relies on IP fragmentation. See
// handshake/fragment for the wire format. The handshake itself is unchanged: a fragmented message is reassembled into
// the packet the handshake Machine would have received unfragmented.

const (
	// repairDelayDivisor sets the default handshakes.repair_delay, how long repair fragments trail the data fragments,
	// as a fraction of the retry interval: 10ms at the default 100ms. It keeps the repair fragments well inside the
	// quiet period of half a retry interval that follows a completed msg1, see fragment.TableConfig.Quiet.
	repairDelayDivisor = 10

	// fragAmplification bounds what a responder sends in reply to an unvalidated address, as a multiple of what it
	// received from it.
	fragAmplification = 3

	// fragMsg2Slots is how many responders' msg2s one attempt reassembles at once.
	fragMsg2Slots = 2
)

// fragmentMode says when this node sends its own handshake messages as fragments. It reassembles fragments from others
// unless the mode is never.
type fragmentMode int

const (
	// fragmentAuto fragments a message too big for one packet, and answers a fragmented msg1 in fragments.
	fragmentAuto fragmentMode = iota
	// fragmentAlways fragments every handshake message.
	fragmentAlways
	// fragmentNever sends every message as one packet, as big as it is, relying on IP fragmentation, and drops
	// fragments from others unread, as a node without fragment support does.
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

// fragmentConfigFrom reads the fragment settings. handshakes.repair_delay, when unset, follows tryInterval, the retry
// interval in effect.
func fragmentConfigFrom(c *config.C, tryInterval time.Duration) (fragmentConfig, error) {
	cfg := fragmentConfig{repairDelay: c.GetDuration("handshakes.repair_delay", tryInterval/repairDelayDivisor)}
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
	// A responder drops a completed msg1's fragments for half a retry interval. Repair fragments trailing by more than
	// that open an entry that never completes and holds a quota slot until it expires.
	if cfg.repairDelay >= tryInterval/2 {
		return cfg, fmt.Errorf("handshakes.repair_delay must be under half of handshakes.try_interval (%v), not %v",
			tryInterval/2, cfg.repairDelay)
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
	// handshakes.try_interval does not reload, so the default repair delay follows the one in effect.
	cfg, err := fragmentConfigFrom(c, hm.config.tryInterval)
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
	MaxPerSource: 32,
	TTL:          3 * time.Second,
}

// msg2Slot reassembles one responder's msg2.
type msg2Slot struct {
	fragID uint32
	msgLen uint16
	a      *fragment.Assembly
}

// msg2Slots reassembles the msg2s answering one attempt, a slot per responder. An array, not a map: one slot is used
// nearly always.
type msg2Slots [fragMsg2Slots]msg2Slot

// slotFor returns the assembly collecting msg2 fragments with fh's FragID, starting one if there is none. A responder
// never changes its FragID or MsgLen, so a fragment whose MsgLen disagrees with its slot is a stray or a forgery and
// starts that slot over. When every slot is taken the one holding the least is replaced: a third responder is
// vanishingly rare, and a forged FragID could already spoil an attempt. It returns nil if no assembly can be made for
// fh.
func (slots *msg2Slots) slotFor(fh fragment.Header) *fragment.Assembly {
	victim := -1
	for i := range slots {
		s := &slots[i]
		if s.a != nil && s.fragID == fh.FragID {
			if s.msgLen == fh.MsgLen {
				return s.a
			}
			victim = i
			break
		}
	}
	if victim < 0 {
		for i := range slots {
			if slots[i].a == nil {
				victim = i
				break
			}
		}
	}
	if victim < 0 {
		victim = 0
		for i := 1; i < len(slots); i++ {
			if slots[i].a.Stored() < slots[victim].a.Stored() {
				victim = i
			}
		}
	}

	a, err := fragment.NewAssembly(fh)
	if err != nil {
		return nil
	}
	slots[victim] = msg2Slot{fragID: fh.FragID, msgLen: fh.MsgLen, a: a}
	return a
}

// drop releases the slot holding a.
func (slots *msg2Slots) drop(a *fragment.Assembly) {
	for i := range slots {
		if slots[i].a == a {
			slots[i] = msg2Slot{}
		}
	}
}

// fragKey identifies one msg1 being reassembled.
type fragKey struct {
	addr   netip.AddrPort
	relay  uint32
	fragID uint32
}

// fragSource groups msg1 reassemblies for the per-source quota: an IPv4 /32, an IPv6 /64, or one relay channel, and
// for a sender that showed a cookie, its own address and port.
type fragSource struct {
	prefix netip.Prefix
	addr   netip.AddrPort
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

// handshakePattern returns the handshake pattern a subtype names: itself, or the one its fragmented form carries.
func handshakePattern(st header.MessageSubType) header.MessageSubType {
	if pattern, ok := header.FragmentedPattern(st); ok {
		return pattern
	}
	return st
}

// reassembled turns a decoded message into the packet the handshake Machine expects, unfragmented: the header of one
// of its fragments, less the fragmented flag, in the header.Len bytes left for it in front of the message.
func reassembled(h *header.H, pkt []byte) []byte {
	// Only a fragmented subtype reaches here.
	pattern, _ := header.FragmentedPattern(h.Subtype)
	return header.Encode(pkt, header.Version, header.Handshake, pattern, h.RemoteIndex, h.MessageCounter)[:len(pkt)]
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
	s, err := fragment.NewSender(msg, hh.hostinfo.localIndexId)
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
		if handshake.IsHybrid(h.Subtype) && !hm.acceptHybrid(via, h) {
			return
		}
		if h.RemoteIndex != 0 {
			hm.l.Debug("dropping stage-1 handshake with non-zero RemoteIndex",
				"from", via, "remoteIndex", h.RemoteIndex)
			return
		}
		now := time.Now()
		key, src := fragKeyFor(via, fh.FragID)
		validated := via.IsRelayed || (fh.HasCookie() && hm.cookies.valid(key, fh.Cookie, now))
		if validated && !via.IsRelayed {
			// A cookie proves the address, so it counts against a quota of its own: whatever the rest of its prefix
			// sends, real or spoofed, can not crowd it out.
			src = fragSource{addr: via.UdpAddr}
		}
		if hm.fragTable.Load() >= fragCookieLoad && !validated {
			hm.sendCookie(via, h.Subtype, fh.FragID, key, len(packet), now)
			return
		}
		res, err := hm.fragTable.Add(key, src, now, fh, sym)
		if errors.Is(err, fragment.ErrSourceQuota) && !validated {
			// The prefix is full, which anyone sharing it can arrange with a few fragments. Ask for a cookie, as under
			// load, rather than turn every handshake from the prefix away.
			hm.sendCookie(via, h.Subtype, fh.FragID, key, len(packet), now)
			return
		}
		if err != nil {
			hm.l.Debug("dropping handshake fragment", "from", via, "error", err)
			return
		}
		if res == nil {
			return
		}
		// A retry is handled as an unfragmented one is: the handshake finds the tunnel this msg1 already made and
		// resends its cached response on the path this copy came by.
		in := msg1Info{fragmented: true, validated: validated, received: res.Received}
		hm.beginHandshake(via, reassembled(h, res.Packet), h, in)

	case 2:
		hh := hm.queryIndex(h.RemoteIndex)
		switch {
		case hh == nil:
		case handshake.IsHybrid(h.Subtype):
			hm.continuePQ(via, hh, h, fh, sym)
		default:
			hm.continueFragmented(via, hh, h, fh, sym)
		}

	case 3:
		if handshake.IsHybrid(h.Subtype) {
			hm.continueHybridResponder(via, h, fh, sym)
		}
	}
}

// continueFragmented collects msg2 fragments for an initiator's attempt, one slot per responder FragID, and processes
// the first msg2 to complete.
func (hm *HandshakeManager) continueFragmented(via ViaSender, hh *HandshakeHostInfo, h *header.H, fh fragment.Header, sym []byte) {
	hh.Lock()
	// The index may be a post-quantum attempt's, which takes only hybrid messages.
	if cur := hm.queryIndex(hh.hostinfo.localIndexId); cur != hh || h.RemoteIndex != hh.hostinfo.localIndexId {
		hh.Unlock()
		return
	}
	a := hh.msg2.slotFor(fh)
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
	hh.msg2.drop(a)
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
	return hm.sendFragmentedAfter(now, later, send, hm.fragConfig().repairDelay)
}

// sendFragmentedAfter is sendFragmented with the given repair delay.
func (hm *HandshakeManager) sendFragmentedAfter(now, later [][]byte, send func([]byte) error, delay time.Duration) error {
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
	switch {
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

// fragmentResponse builds the responder's msg2 as fragments, now to send immediately and later after the repair delay,
// each call offering symbols the hostinfo has not sent before, so an initiator still holding some from an earlier send
// completes sooner. budget bounds the bytes sent before the address is validated, -1 for none; a response that does
// not fit it at all returns errOverBudget.
func fragmentResponse(msg []byte, hostinfo *HostInfo, budget int) (now, later [][]byte, err error) {
	s, err := fragment.NewSender(msg, hostinfo.localIndexId)
	if err != nil {
		return nil, nil, err
	}

	l := s.Layout()
	repair := fragment.DefaultRepair(l.K)
	if budget >= 0 {
		pktLen := header.Len + fragment.HeaderLen + l.SymbolSize
		packets := budget / pktLen
		if packets < l.K {
			return nil, nil, errOverBudget
		}
		repair = min(repair, packets-l.K)
	}

	n := uint32(l.K + repair)
	s.SetNext(int(hostinfo.handshakeNextSymbol.Add(n) - n))
	return s.Attempt(repair)
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

// tick rotates the secret when it is due, so cookies expire on time however rarely they are made or checked.
func (c *fragCookies) tick(now time.Time) {
	c.Lock()
	defer c.Unlock()
	c.rotate(now)
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

// sendCookie answers a msg1 with a cookie reply of the fragmented subtype given, naming the initiator by fragID. The
// reply is never larger than what triggered it, so it reflects nothing and needs no rate limit.
func (hm *HandshakeManager) sendCookie(via ViaSender, subtype header.MessageSubType, fragID uint32, key fragKey, received int, now time.Time) {
	if received < fragCookieReplyLen {
		return
	}
	send, err := hm.sendTo(via)
	if err != nil {
		hm.l.Debug("Failed to send handshake cookie", "to", via, "error", err)
		return
	}
	c := hm.cookies.make(key, now)
	reply := make([]byte, header.Len, fragCookieReplyLen)
	header.Encode(reply, header.Version, header.Handshake, subtype, fragID, fragCookieCounter)
	reply = append(reply, c[:]...)
	hm.f.messageMetrics.Tx(header.Handshake, subtype, 1)
	if err := send(reply); err != nil {
		hm.l.Debug("Failed to send handshake cookie", "to", via, "error", err)
	}
}

// handleCookie attaches a responder's cookie to the attempt it names, switching msg1 to fragments if it was a single
// packet, since only a fragment carries a cookie. When the reply came from an address the last attempt was sent to, or
// through a relay, it resends right away, at most once per retry interval, rather than waiting for the next attempt.
// A reply from anywhere else only sets the cookie: anyone who knows the attempt's index can forge one, and an immediate
// resend to its source would aim the whole msg1 at whatever address it claims.
func (hm *HandshakeManager) handleCookie(via ViaSender, packet []byte, h *header.H) {
	if len(packet) != fragCookieReplyLen {
		return
	}
	hh := hm.queryIndex(h.RemoteIndex)
	if hh == nil {
		return
	}
	if handshake.IsHybrid(h.Subtype) {
		hm.handlePQCookie(via, hh, packet, h)
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

	if !via.IsRelayed && !slices.Contains(hh.lastRemotes, via.UdpAddr) {
		return
	}
	now := time.Now()
	if now.Sub(hh.cookieResendAt) < hm.config.tryInterval {
		return
	}
	hh.cookieResendAt = now
	pkts, later, err := hh.stage0Packets()
	if err != nil {
		return
	}
	send, err := hm.sendTo(via)
	if err != nil {
		hm.l.Debug("Failed to resend handshake with cookie", "to", via, "error", err)
		return
	}
	hm.messageMetrics.Tx(header.Handshake, h.Subtype, int64(len(pkts)+len(later)))
	if err := hm.sendFragmented(pkts, later, send); err != nil {
		hm.l.Debug("Failed to resend handshake with cookie", "to", via, "error", err)
	}
}

// sendTo returns a function sending a packet back the way via came: directly, or through the relay it arrived on. It
// fails when via claims a relay it does not name, so a caller that gets a function may also use via's relay.
func (hm *HandshakeManager) sendTo(via ViaSender) (func([]byte) error, error) {
	f := hm.f
	if !via.IsRelayed {
		return func(p []byte) error {
			return f.outside.WriteTo(p, via.UdpAddr)
		}, nil
	}
	if via.relay == nil {
		return nil, errors.New("both addr and via.relay are nil")
	}
	return func(p []byte) error {
		f.sendHandshakeVia(via.relayHI, via.relay, p)
		return nil
	}, nil
}

// sendHandshakeVia sends a handshake packet through a relay, with buffers sized for the packet rather than the mtu:
// an unfragmented handshake message may be bigger than one.
func (f *Interface) sendHandshakeVia(via *HostInfo, relay *Relay, p []byte) {
	out := make([]byte, header.Len+len(p)+via.ConnectionState.eKey.Overhead())
	f.SendVia(via, relay, p, make([]byte, 12), out, false, 0)
}
