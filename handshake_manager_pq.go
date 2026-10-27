package nebula

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"slices"
	"time"

	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/handshake"
	"github.com/slackhq/nebula/handshake/fragment"
	"github.com/slackhq/nebula/header"
)

type pqHandshakeConfig struct {
	initiate bool // start PQ handshakes
	accept   bool // answer PQ handshakes
	require  bool // only PQ handshakes, in either direction
	sticky   bool // never fall back to classical for a peer that completed PQ
}

func pqHandshakeConfigFrom(c *config.C) pqHandshakeConfig {
	cfg := pqHandshakeConfig{
		initiate: c.GetBool("handshakes.pq.initiate", false),
		accept:   c.GetBool("handshakes.pq.accept", false),
		require:  c.GetBool("handshakes.pq.require", false),
		sticky:   c.GetBool("handshakes.pq.sticky", false),
	}
	if cfg.require {
		cfg.initiate = true
		cfg.accept = true
	}
	return cfg
}

// pqConfig returns the post-quantum settings in effect.
func (hm *HandshakeManager) pqConfig() *pqHandshakeConfig {
	return hm.pq.Load()
}

// pqRequired reports whether every handshake must be post-quantum: by handshakes.pq.require, or because this node holds
// only a v3 certificate without a v2 form, which has nothing to answer a classical handshake with. Such a node also
// initiates and accepts post-quantum handshakes whatever handshakes.pq says.
func (hm *HandshakeManager) pqRequired() bool {
	if hm.pqConfig().require {
		return true
	}
	return hm.f != nil && hm.f.pki != nil && !hm.f.pki.getCertState().classicalCapable()
}

// warnPQWithoutV3 says so when post-quantum settings are on but the node has no
// version 3 certificate: post-quantum handshakes are hybrid only, so they do
// nothing until it has one. require is refused outright when loading pki.
func warnPQWithoutV3(l *slog.Logger, cfg pqHandshakeConfig, cs *CertState) {
	if _, ok := cs.hybridSubtype(); ok || !(cfg.initiate || cfg.accept || cfg.sticky) {
		return
	}
	l.Warn("handshakes.pq has no effect without a version 3 certificate in pki.cert",
		"initiate", cfg.initiate, "accept", cfg.accept, "sticky", cfg.sticky)
}

// reloadPQ applies changed post-quantum settings. Handshakes already in flight
// keep going; the new settings apply to the next attempt and packet.
func (hm *HandshakeManager) reloadPQ(c *config.C, _ *config.Reload) {
	if !c.HasChanged("handshakes.pq") {
		return
	}
	old := hm.pqConfig()
	cfg := pqHandshakeConfigFrom(c)
	cs := hm.f.pki.getCertState()
	if _, ok := cs.hybridSubtype(); cfg.require && !ok {
		hm.l.Error("Refusing handshakes.pq.require without a version 3 certificate in pki.cert, keeping the previous settings")
		return
	}
	warnPQWithoutV3(hm.l, cfg, cs)
	hm.pq.Store(&cfg)
	hm.l.Info("Post-quantum handshake settings changed",
		"initiate", cfg.initiate, "oldInitiate", old.initiate,
		"accept", cfg.accept, "oldAccept", old.accept,
		"require", cfg.require, "oldRequire", old.require,
		"sticky", cfg.sticky, "oldSticky", old.sticky,
	)
}

// pqAttempt is the initiator's post-quantum attempt for a pending handshake. It
// lives alongside the classical attempt in HandshakeHostInfo and has its own
// local index, so whichever answer arrives first wins.
type pqAttempt struct {
	machine        *handshake.Machine
	subtype        header.MessageSubType
	index          uint32
	sender         *fragment.Sender
	msg2           msg2Slots // msg2 fragments being reassembled, per responder
	cookieResendAt time.Time // last resend prompted by a cookie reply
	heard          bool      // a msg2 fragment or cookie reply arrived, so the peer speaks PQ
}

// packets returns the packets of one attempt at msg1, a fresh set of fragments: now immediately and later after the
// repair delay.
func (pq *pqAttempt) packets() (now, later [][]byte, err error) {
	return pq.sender.Attempt(fragment.DefaultRepair(pq.sender.Layout().K))
}

// usePQ decides whether this outbound attempt is post-quantum. A peer that does
// not speak PQ silently drops it, so timer retries alternate between PQ and
// classical, starting with PQ. An attempt triggered early by a lighthouse reply
// is sending to addresses nothing has been sent to yet, and a new path gets the
// PQ attempt first. With require, or for a peer that completed a PQ handshake
// when sticky is on, every attempt is PQ. Once anything has come back for the PQ
// attempt the peer evidently speaks PQ, and a classical attempt would only race
// it, so classical stops getting turns.
func (hm *HandshakeManager) usePQ(hh *HandshakeHostInfo, vpnIp netip.Addr, triggered bool) bool {
	cfg := hm.pqConfig()
	if _, ok := hm.f.pki.getCertState().hybridSubtype(); !ok {
		return false
	}
	switch {
	case hm.pqRequired():
		return true
	case !cfg.initiate, hh.noPQ:
		return false
	case hh.pq != nil && hh.pq.heard:
		return true
	case cfg.sticky:
		if _, ok := hm.pqPeers.Load(vpnIp); ok {
			return true
		}
	}
	return hh.counter <= 1 || triggered || !hh.lastPQ
}

// relayEstablished pushes the pending handshake with target through a relay that
// just came up, rather than leaving it for the next retry. Nothing has gone over
// the relay yet, so like any new path it gets the PQ attempt first, which then
// counts as the PQ turn: the next retry is classical, as if it had been sent on
// schedule. Without this, relays coming up while the first attempt is in flight
// handed every relayed handshake to the classical retry.
func (hm *HandshakeManager) relayEstablished(target netip.Addr, relayHI *HostInfo, relay *Relay) {
	hh := hm.queryVpnIp(target)
	if hh == nil {
		return
	}
	hh.Lock()
	defer hh.Unlock()
	if hm.queryVpnIp(target) != hh {
		return
	}

	var now, later [][]byte
	var err error
	switch {
	case hh.pq != nil:
		now, later, err = hh.pq.packets()
		hh.lastPQ = true
	case hh.ready:
		now, later, err = hh.stage0Packets()
	default:
		return
	}
	if err != nil {
		return
	}

	f := hm.f
	hh.hostinfo.logger(hm.l).Info("Send handshake via new relay", "relay", relayHI.vpnAddrs[0])
	_ = hm.sendFragmented(now, later, func(p []byte) error {
		f.sendHandshakeVia(relayHI, relay, p)
		return nil
	})
}

// buildPQAttempt creates the initiator's PQ Machine and msg1 sender, for the
// hybrid handshake of its v3 certificate's suite.
func (hm *HandshakeManager) buildPQAttempt(hh *HandshakeHostInfo) bool {
	cs := hm.f.pki.getCertState()
	subtype, ok := cs.hybridSubtype()
	if !ok {
		return false
	}
	v := cert.Version3
	if cs.GetCredential(v) == nil {
		hm.f.l.Error("Unable to handshake with host because no certificate is available",
			"vpnAddrs", hh.hostinfo.vpnAddrs, "certVersion", v)
		return false
	}

	pq := &pqAttempt{subtype: subtype}
	machine, err := handshake.NewMachine(
		v, cs.GetCredential,
		hm.certVerifier(), func() (uint32, error) { return hm.allocatePQIndex(hh, pq) },
		true, subtype,
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

	sender, err := fragment.NewSender(msg, pq.index)
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

// abandonPQ drops a failed PQ attempt, leaving classical attempts only. The
// caller must hold hh.Lock.
func (hm *HandshakeManager) abandonPQ(hh *HandshakeHostInfo) {
	hm.releasePQIndex(hh, hh.pq)
	hh.pq = nil
	hh.noPQ = true
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

// acceptHybrid reports whether a hybrid msg1 is one this node answers: it accepts post-quantum handshakes and holds a
// v3 certificate whose suite uses the msg1's KEM.
func (hm *HandshakeManager) acceptHybrid(via ViaSender, h *header.H) bool {
	if !hm.pqConfig().accept && !hm.pqRequired() {
		hm.l.Debug("dropping post-quantum handshake, not accepting them", "from", via)
		return false
	}
	mine, hasV3 := hm.f.pki.getCertState().hybridSubtype()
	switch {
	case !hasV3:
		hm.l.Debug("dropping hybrid handshake, no v3 certificate to answer it with", "from", via)
		return false
	case handshakePattern(h.Subtype) != mine:
		// The peer's suite uses another KEM. Like a peer without PQ, it
		// falls back to classical unless either side requires PQ.
		hm.l.Debug("dropping hybrid handshake, our v3 certificate's suite uses another KEM", "from", via,
			"style", header.SubTypeName(header.Handshake, h.Subtype), "ours", header.SubTypeName(header.Handshake, mine))
		return false
	}
	return true
}

// continuePQ collects msg2 fragments for the initiator's PQ attempt, one slot
// per responder FragID, and processes the first msg2 to complete.
func (hm *HandshakeManager) continuePQ(via ViaSender, hh *HandshakeHostInfo, h *header.H, fh fragment.Header, sym []byte) {
	hh.Lock()
	defer hh.Unlock()

	pq := hh.pq
	if pq == nil || pq.index != h.RemoteIndex || !hm.stillPending(hh, pq.index) {
		return
	}
	pq.heard = true

	a := pq.msg2.slotFor(fh)
	if a == nil {
		return
	}
	ready, err := a.Add(fh, sym)
	if err != nil || !ready {
		return
	}

	pkt, err := a.Decode(make([]byte, header.Len))
	pq.msg2.drop(a)
	if err != nil {
		hm.l.Debug("failed to decode handshake fragments", "from", via, "error", err)
		return
	}
	hm.processResponse(via, hh, pq.machine, reassembled(h, pkt))
}

// notePQPeer remembers peers that completed a PQ handshake, for sticky mode.
func (hm *HandshakeManager) notePQPeer(subtype header.MessageSubType, vpnAddrs []netip.Addr) {
	if !hm.pqConfig().sticky || !handshake.IsHybrid(subtype) {
		return
	}
	for _, a := range vpnAddrs {
		hm.pqPeers.Store(a, struct{}{})
	}
	if hm.l.Enabled(context.Background(), slog.LevelDebug) {
		hm.l.Debug("Remembering post-quantum peer", "vpnAddrs", vpnAddrs)
	}
}

// handlePQCookie attaches a responder's cookie to the PQ attempt it names and
// resends right away, at most once per retry interval, rather than waiting for
// the next attempt.
func (hm *HandshakeManager) handlePQCookie(via ViaSender, hh *HandshakeHostInfo, packet []byte, h *header.H) {
	hh.Lock()
	defer hh.Unlock()

	pq := hh.pq
	if pq == nil || pq.index != h.RemoteIndex || !hm.stillPending(hh, pq.index) {
		return
	}
	var c fragment.Cookie
	copy(c[:], packet[header.Len:])
	pq.sender.SetCookie(c)
	pq.heard = true

	// As in handleCookie: a reply from an address the attempt was not sent to only sets the cookie, an immediate
	// resend to it would aim the whole msg1 at whatever address a forged reply claims.
	if !via.IsRelayed && !slices.Contains(hh.lastRemotes, via.UdpAddr) {
		return
	}
	now := time.Now()
	if now.Sub(pq.cookieResendAt) < hm.config.tryInterval {
		return
	}
	pq.cookieResendAt = now
	pkts, later, err := pq.packets()
	if err != nil {
		return
	}
	send, err := hm.sendTo(via)
	if err != nil {
		hm.l.Debug("Failed to resend handshake with cookie", "to", via, "error", err)
		return
	}
	// A hybrid handshake only travels as fragments.
	fragmented, _ := header.FragmentedSubtype(pq.subtype)
	hm.messageMetrics.Tx(header.Handshake, fragmented, int64(len(pkts)+len(later)))
	if err := hm.sendFragmented(pkts, later, send); err != nil {
		hm.l.Debug("Failed to resend handshake with cookie", "to", via, "error", err)
	}
}
