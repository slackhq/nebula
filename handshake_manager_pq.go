package nebula

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/handshake"
	"github.com/slackhq/nebula/handshake/fragment"
	"github.com/slackhq/nebula/header"
)

const (
	// pqSubtype is the post-quantum handshake this node speaks.
	pqSubtype = header.HandshakeIXPSK2MLKEM1024

	// DefaultPQRepairDelay is how long repair fragments trail the data fragments.
	DefaultPQRepairDelay = 10 * time.Millisecond

	// pqAmplification bounds what a responder sends in reply to an unvalidated
	// address, as a multiple of what it received from it.
	pqAmplification = 3
)

// pqTableConfig bounds the responder's reassembly of msg1 fragments from senders
// that have not authenticated yet.
var pqTableConfig = fragment.TableConfig{
	MaxBytes:     4 << 20,
	MaxEntries:   1024,
	MaxPerSource: 4,
	MaxMsgLen:    16384,
	TTL:          3 * time.Second,
}

type pqHandshakeConfig struct {
	initiate    bool          // start PQ handshakes
	accept      bool          // answer PQ handshakes
	sticky      bool          // never fall back to classical for a peer that completed PQ
	repairDelay time.Duration // delay between data and repair fragments
}

func pqHandshakeConfigFrom(c *config.C) pqHandshakeConfig {
	return pqHandshakeConfig{
		initiate:    c.GetBool("handshakes.pq.initiate", false),
		accept:      c.GetBool("handshakes.pq.accept", false),
		sticky:      c.GetBool("handshakes.pq.sticky", false),
		repairDelay: c.GetDuration("handshakes.pq.repair_delay", DefaultPQRepairDelay),
	}
}

// pqConfig returns the post-quantum settings in effect.
func (hm *HandshakeManager) pqConfig() *pqHandshakeConfig {
	return hm.pq.Load()
}

// reloadPQ applies changed post-quantum settings. Handshakes already in flight
// keep going; the new settings apply to the next attempt and packet.
func (hm *HandshakeManager) reloadPQ(c *config.C) {
	if !c.HasChanged("handshakes.pq") {
		return
	}
	old := hm.pqConfig()
	cfg := pqHandshakeConfigFrom(c)
	hm.pq.Store(&cfg)
	hm.l.Info("Post-quantum handshake settings changed",
		"initiate", cfg.initiate, "oldInitiate", old.initiate,
		"accept", cfg.accept, "oldAccept", old.accept,
		"sticky", cfg.sticky, "oldSticky", old.sticky,
		"repairDelay", cfg.repairDelay, "oldRepairDelay", old.repairDelay,
	)
}

// pqAttempt is the initiator's post-quantum attempt for a pending handshake. It
// lives alongside the classical attempt in HandshakeHostInfo and has its own
// local index, so whichever answer arrives first wins.
type pqAttempt struct {
	machine        *handshake.Machine
	index          uint32
	sender         *fragment.Sender
	msg2           *fragment.Assembly
	cookieResendAt time.Time // last resend prompted by a cookie reply
}

// pqFragKey identifies one msg1 being reassembled.
type pqFragKey struct {
	addr   netip.AddrPort
	relay  uint32
	fragID uint32
}

// pqFragSource groups msg1 reassemblies for the per-source quota: an IPv4 /32,
// an IPv6 /64, or one relay channel.
type pqFragSource struct {
	prefix netip.Prefix
	relay  uint32
}

func pqFragKeyFor(via ViaSender, fragID uint32) (pqFragKey, pqFragSource) {
	if via.IsRelayed {
		return pqFragKey{relay: via.relay.LocalIndex, fragID: fragID},
			pqFragSource{relay: via.relay.LocalIndex}
	}
	addr := via.UdpAddr.Addr().Unmap()
	bits := 64
	if addr.Is4() {
		bits = 32
	}
	prefix, _ := addr.Prefix(bits)
	return pqFragKey{addr: via.UdpAddr, fragID: fragID}, pqFragSource{prefix: prefix}
}

// reassembled rebuilds the packet the handshake Machine expects from the header
// of a fragment and the decoded message.
func reassembled(h *header.H, msg []byte) []byte {
	p := make([]byte, header.Len, header.Len+len(msg))
	header.Encode(p, header.Version, header.Handshake, h.Subtype, h.RemoteIndex, h.MessageCounter)
	return append(p, msg...)
}

// usePQ decides whether this outbound attempt is post-quantum. Attempts
// alternate, starting with PQ, because a peer that does not speak PQ silently
// drops it. A peer that already completed a PQ handshake never gets a classical
// attempt when sticky is on.
func (hm *HandshakeManager) usePQ(hh *HandshakeHostInfo, vpnIp netip.Addr) bool {
	cfg := hm.pqConfig()
	if !cfg.initiate {
		return false
	}
	if cfg.sticky {
		if _, ok := hm.pqPeers.Load(vpnIp); ok {
			return true
		}
	}
	return hh.counter%2 == 1
}

// buildPQAttempt creates the initiator's PQ Machine and msg1 sender.
func (hm *HandshakeManager) buildPQAttempt(hh *HandshakeHostInfo) bool {
	cs := hm.f.pki.getCertState()
	v := hm.initiatingVersion(hh, cs)
	if cs.GetCredential(v) == nil {
		hm.f.l.Error("Unable to handshake with host because no certificate is available",
			"vpnAddrs", hh.hostinfo.vpnAddrs, "certVersion", v)
		return false
	}

	pq := &pqAttempt{}
	machine, err := handshake.NewMachine(
		v, cs.GetCredential,
		hm.certVerifier(), func() (uint32, error) { return hm.allocatePQIndex(hh, pq) },
		true, pqSubtype,
	)
	if err != nil {
		hm.f.l.Error("Failed to create handshake machine",
			"vpnAddrs", hh.hostinfo.vpnAddrs, "error", err)
		return false
	}

	msg, err := machine.Initiate(nil)
	if err != nil {
		hm.f.l.Error("Failed to initiate handshake",
			"vpnAddrs", hh.hostinfo.vpnAddrs, "error", err)
		hm.releasePQIndex(hh, pq)
		return false
	}

	sender, err := fragment.NewSender(msg[header.Len:], pqSubtype, 0, 1, pq.index)
	if err != nil {
		hm.f.l.Error("Failed to fragment handshake",
			"vpnAddrs", hh.hostinfo.vpnAddrs, "error", err)
		hm.releasePQIndex(hh, pq)
		return false
	}

	pq.machine = machine
	pq.sender = sender
	hh.pq = pq
	return true
}

// allocatePQIndex registers a local index for the PQ attempt. Unlike
// allocateIndex it leaves hostinfo.localIndexId alone; that is settled when one
// of the attempts completes.
func (hm *HandshakeManager) allocatePQIndex(hh *HandshakeHostInfo, pq *pqAttempt) (uint32, error) {
	hm.mainHostMap.RLock()
	defer hm.mainHostMap.RUnlock()
	hm.Lock()
	defer hm.Unlock()

	for range 32 {
		index, err := generateIndex(hm.l)
		if err != nil {
			return 0, err
		}

		_, inPending := hm.indexes[index]
		_, inMain := hm.mainHostMap.Indexes[index]

		if !inMain && !inPending {
			pq.index = index
			hm.indexes[index] = hh
			return index, nil
		}
	}

	return 0, errors.New("failed to generate unique localIndexId")
}

func (hm *HandshakeManager) releasePQIndex(hh *HandshakeHostInfo, pq *pqAttempt) {
	hm.Lock()
	defer hm.Unlock()
	if pq.index != 0 && hm.indexes[pq.index] == hh {
		delete(hm.indexes, pq.index)
	}
}

// settleIndex makes winner the hostinfo's local index and releases the index of
// the attempt that lost.
func (hm *HandshakeManager) settleIndex(hh *HandshakeHostInfo, winner uint32) {
	hm.Lock()
	defer hm.Unlock()
	for _, idx := range []uint32{hh.hostinfo.localIndexId, hh.pqIndex()} {
		if idx != 0 && idx != winner && hm.indexes[idx] == hh {
			delete(hm.indexes, idx)
		}
	}
	hh.hostinfo.localIndexId = winner
}

func (hh *HandshakeHostInfo) pqIndex() uint32 {
	if hh.pq == nil {
		return 0
	}
	return hh.pq.index
}

// handleFragment routes one fragment of a PQ handshake message.
func (hm *HandshakeManager) handleFragment(via ViaSender, packet []byte, h *header.H) {
	if h.MessageCounter == pqCookieCounter {
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
		if !hm.pqConfig().accept {
			hm.l.Debug("dropping post-quantum handshake, not accepting them", "from", via)
			return
		}
		if h.RemoteIndex != 0 {
			hm.l.Debug("dropping stage-1 handshake with non-zero RemoteIndex",
				"from", via, "remoteIndex", h.RemoteIndex)
			return
		}
		now := time.Now()
		key, src := pqFragKeyFor(via, fh.FragID)
		if hm.pqTable.Load() >= pqCookieLoad && !(fh.HasCookie() && hm.pqCookies.valid(key, fh.Cookie, now)) {
			hm.sendCookie(via, fh, key, len(packet), now)
			return
		}
		res, err := hm.pqTable.Add(key, src, now, fh, sym)
		if err != nil {
			hm.l.Debug("dropping handshake fragment", "from", via, "error", err)
			return
		}
		if res == nil {
			return
		}
		if existing := hm.pqAnswered.lookup(res.Msg, time.Now()); existing != nil {
			// Already answered: resend, rate limited, with fresh symbols.
			if msg := existing.HandshakePacket[handshakePacketStage2]; msg != nil {
				hm.sendHandshakeResponse(via, msg, existing, true, res.Received)
			}
			return
		}
		hm.beginHandshake(via, reassembled(h, res.Msg), h, res.Received)

	case 2:
		if hh := hm.queryIndex(h.RemoteIndex); hh != nil {
			hm.continuePQ(via, hh, h, fh, sym)
		}
	}
}

// continuePQ collects msg2 fragments for the initiator's PQ attempt.
func (hm *HandshakeManager) continuePQ(via ViaSender, hh *HandshakeHostInfo, h *header.H, fh fragment.Header, sym []byte) {
	hh.Lock()
	defer hh.Unlock()

	pq := hh.pq
	if pq == nil || pq.index != h.RemoteIndex || !hm.stillPending(hh, pq.index) {
		return
	}

	if pq.msg2 == nil {
		a, err := fragment.NewAssembly(fh)
		if err != nil {
			return
		}
		pq.msg2 = a
	}
	ready, err := pq.msg2.Add(fh, sym)
	if errors.Is(err, fragment.ErrMismatch) {
		// The responder's FragID and MsgLen never change, so this is a stray or a
		// forgery. Start over from this fragment rather than wedge.
		pq.msg2 = nil
		return
	}
	if err != nil || !ready {
		return
	}

	msg, err := pq.msg2.Decode()
	pq.msg2 = nil
	if err != nil {
		hm.l.Debug("failed to decode handshake fragments", "from", via, "error", err)
		return
	}
	hm.processResponse(via, hh, pq.machine, reassembled(h, msg))
}

// sendFragmented sends packets to a peer: now immediately and later after the
// repair delay. It returns the first error from the immediate sends; errors from
// delayed sends are only logged.
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
	delay := hm.pqConfig().repairDelay
	switch {
	case len(later) == 0:
	case delay <= 0:
		sendLater()
	default:
		time.AfterFunc(delay, sendLater)
	}
	return first
}

// sendFragmentedResponse sends the responder's msg2 as fragments. A resend of a
// cached response (cached) offers fresh symbols and is rate limited to one per
// retry interval. received is how many bytes the triggering msg1 took, which
// bounds what may be sent back before the address is validated.
func (hm *HandshakeManager) sendFragmentedResponse(via ViaSender, msg []byte, hostinfo *HostInfo, cached bool, received int) error {
	now := time.Now()
	if cached {
		last := hostinfo.handshakeResendAt.Load()
		if now.UnixNano()-last < int64(hm.config.tryInterval) ||
			!hostinfo.handshakeResendAt.CompareAndSwap(last, now.UnixNano()) {
			return errors.New("handshake response resend rate limited")
		}
	} else {
		hostinfo.handshakeResendAt.Store(now.UnixNano())
	}

	var h header.H
	if err := h.Parse(msg); err != nil {
		return err
	}
	s, err := fragment.NewSender(msg[header.Len:], h.Subtype, h.RemoteIndex, h.MessageCounter, hostinfo.localIndexId)
	if err != nil {
		return err
	}

	l := s.Layout()
	repair := fragment.DefaultRepair(l.K)
	if received > 0 {
		pktLen := header.Len + fragment.HeaderLen + l.SymbolSize
		budget := pqAmplification * received / pktLen
		if budget < l.K {
			return errors.New("handshake response exceeds the amplification budget")
		}
		repair = min(repair, budget-l.K)
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
	hm.f.messageMetrics.Tx(header.Handshake, h.Subtype, int64(len(pkts)+len(later)))
	return hm.sendFragmented(pkts, later, hm.sendTo(via))
}

// notePQPeer remembers peers that completed a PQ handshake, for sticky mode.
func (hm *HandshakeManager) notePQPeer(subtype header.MessageSubType, vpnAddrs []netip.Addr) {
	if !hm.pqConfig().sticky || subtype != pqSubtype {
		return
	}
	for _, a := range vpnAddrs {
		hm.pqPeers.Store(a, struct{}{})
	}
	if hm.l.Enabled(context.Background(), slog.LevelDebug) {
		hm.l.Debug("Remembering post-quantum peer", "vpnAddrs", vpnAddrs)
	}
}

// pqAnswered remembers the msg1s a responder recently answered, keyed by hash,
// so a repeat is recognised before any noise, KEM or certificate work. Repeats
// are routine: the trailing repair fragments of an attempt rebuild a msg1 that
// its data fragments already completed, and a retrying initiator offers fresh
// symbols for the same msg1. Entries only exist for completed handshakes, which
// need a valid certificate, and live as long as an initiator keeps retrying.
type pqAnswered struct {
	sync.Mutex
	ttl     time.Duration
	entries map[[sha256.Size]byte]pqAnsweredEntry
}

type pqAnsweredEntry struct {
	hostinfo *HostInfo
	at       time.Time
}

const pqAnsweredMax = 4096

func newPQAnswered(ttl time.Duration) *pqAnswered {
	return &pqAnswered{ttl: ttl, entries: map[[sha256.Size]byte]pqAnsweredEntry{}}
}

func (a *pqAnswered) add(msg1 []byte, hostinfo *HostInfo, now time.Time) {
	a.Lock()
	defer a.Unlock()
	if len(a.entries) >= pqAnsweredMax {
		for k := range a.entries {
			delete(a.entries, k)
			break
		}
	}
	a.entries[sha256.Sum256(msg1)] = pqAnsweredEntry{hostinfo: hostinfo, at: now}
}

func (a *pqAnswered) lookup(msg1 []byte, now time.Time) *HostInfo {
	a.Lock()
	defer a.Unlock()
	e, ok := a.entries[sha256.Sum256(msg1)]
	if !ok || now.Sub(e.at) > a.ttl {
		return nil
	}
	return e.hostinfo
}

func (a *pqAnswered) expire(now time.Time) {
	a.Lock()
	defer a.Unlock()
	for k, e := range a.entries {
		if now.Sub(e.at) > a.ttl {
			delete(a.entries, k)
		}
	}
}

// A responder whose msg1 table is under load stops keeping state for senders
// that have not shown they receive at their address. It answers a fragment
// without a valid cookie with a cookie reply and keeps nothing; the initiator
// resends with the cookie attached. This is WireGuard's under-load cookie, QUIC's
// Retry and SCTP's state cookie: one extra round trip, only while under attack.
const (
	// pqCookieLoad is the table load above which msg1 fragments need a cookie.
	pqCookieLoad = 0.5

	// pqCookieCounter marks a cookie reply in the header's message counter.
	// Handshake messages count from 1.
	pqCookieCounter = 0

	// pqCookieRotate is how often the cookie secret changes. A cookie stays
	// valid for between one and two rotations.
	pqCookieRotate = 2 * time.Minute

	pqCookieReplyLen = header.Len + fragment.CookieLen
)

// pqCookies mints and checks cookies: an HMAC over the sender's address (or relay
// channel) and FragID under a rotating secret, with the previous secret still
// accepted.
type pqCookies struct {
	sync.Mutex
	secrets   [2][32]byte
	rotatedAt time.Time
}

func newPQCookies(now time.Time) *pqCookies {
	c := &pqCookies{rotatedAt: now}
	_, _ = rand.Read(c.secrets[0][:])
	_, _ = rand.Read(c.secrets[1][:])
	return c
}

func (c *pqCookies) rotate(now time.Time) {
	if now.Sub(c.rotatedAt) < pqCookieRotate {
		return
	}
	c.secrets[1] = c.secrets[0]
	_, _ = rand.Read(c.secrets[0][:])
	c.rotatedAt = now
}

func cookieMAC(secret []byte, key pqFragKey) fragment.Cookie {
	mac := hmac.New(sha256.New, secret)
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

func (c *pqCookies) make(key pqFragKey, now time.Time) fragment.Cookie {
	c.Lock()
	defer c.Unlock()
	c.rotate(now)
	return cookieMAC(c.secrets[0][:], key)
}

func (c *pqCookies) valid(key pqFragKey, cookie fragment.Cookie, now time.Time) bool {
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

// sendCookie answers a msg1 fragment that arrived without a valid cookie while
// under load. The reply is never larger than what triggered it, and replies are
// rate limited as a whole.
func (hm *HandshakeManager) sendCookie(via ViaSender, fh fragment.Header, key pqFragKey, received int, now time.Time) {
	if received < pqCookieReplyLen {
		return
	}
	if _, ok := hm.pqCookieLimiter.Allow(); !ok {
		return
	}
	c := hm.pqCookies.make(key, now)
	reply := make([]byte, header.Len, pqCookieReplyLen)
	header.Encode(reply, header.Version, header.Handshake, pqSubtype, fh.FragID, pqCookieCounter)
	reply = append(reply, c[:]...)
	hm.f.messageMetrics.Tx(header.Handshake, pqSubtype, 1)
	if err := hm.sendTo(via)(reply); err != nil {
		hm.l.Debug("Failed to send handshake cookie", "to", via, "error", err)
	}
}

// handleCookie attaches a responder's cookie to the PQ attempt it names and
// resends right away, at most once per retry interval, rather than waiting for
// the next attempt.
func (hm *HandshakeManager) handleCookie(via ViaSender, packet []byte, h *header.H) {
	if len(packet) != pqCookieReplyLen {
		return
	}
	hh := hm.queryIndex(h.RemoteIndex)
	if hh == nil {
		return
	}
	hh.Lock()
	defer hh.Unlock()

	pq := hh.pq
	if pq == nil || pq.index != h.RemoteIndex || !hm.stillPending(hh, pq.index) {
		return
	}
	var c fragment.Cookie
	copy(c[:], packet[header.Len:])
	pq.sender.SetCookie(c)

	now := time.Now()
	if now.Sub(pq.cookieResendAt) < hm.config.tryInterval {
		return
	}
	pq.cookieResendAt = now
	pkts, later, err := pq.sender.Attempt(fragment.DefaultRepair(pq.sender.Layout().K))
	if err != nil {
		return
	}
	hm.messageMetrics.Tx(header.Handshake, pqSubtype, int64(len(pkts)+len(later)))
	if err := hm.sendFragmented(pkts, later, hm.sendTo(via)); err != nil {
		hm.l.Debug("Failed to resend handshake with cookie", "to", via, "error", err)
	}
}

// sendTo returns a function sending a packet back the way via came: directly, or
// through the relay it arrived on.
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
		f.SendVia(via.relayHI, via.relay, p, make([]byte, 12), make([]byte, mtu), false, 0)
		return nil
	}
}
