package nebula

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/handshake"
	"github.com/slackhq/nebula/handshake/fragment"
	"github.com/slackhq/nebula/header"
)

// Hybrid handshakes (ix_hybrid_mlkem1024) take three messages, so unlike IX the
// responder has to wait for one more message and the initiator finishes by
// sending rather than receiving:
//
//   - The responder answers msg1 with msg2 and keeps the handshake pending under
//     its local index until msg3 arrives. Data for that index is dropped quietly
//     meanwhile, it must not draw a RecvError. Once msg3 verifies the tunnel
//     goes live and an empty TestReply tells the initiator so.
//   - The initiator has the keys as soon as it writes msg3, so the tunnel goes
//     live then, readable only by the real responder. msg3 is resent with fresh
//     symbols until something from the responder decrypts, and if nothing does
//     within the handshake timeout the tunnel is closed.

const (
	hybridSubtype = header.HandshakeIXHybridMLKEM1024

	// hybridMsg3MaxLen bounds the msg3 a pending responder reassembles. msg3 is
	// a ciphertext and two tags, about 1.6KB.
	hybridMsg3MaxLen = 4096
)

// hybridResponder is the responder half of a pending hybrid handshake, waiting
// for msg3.
type hybridResponder struct {
	msg3    *fragment.Assembly
	expires time.Time
}

// hybridConfirm is an initiator's completed hybrid handshake that has not yet
// heard from the responder.
type hybridConfirm struct {
	hostinfo     *HostInfo
	sender       *fragment.Sender
	send         func([]byte) error
	handshakeLen uint64 // messages the handshake took, which the replay window was seeded with
	deadline     time.Time
	next         time.Time
	attempts     int
}

// hybridState holds the hybrid handshakes waiting on their last step.
type hybridState struct {
	// responders maps local indexes to pending responders. Guarded by the
	// HandshakeManager lock; the entries are also in its indexes.
	responders map[uint32]*HandshakeHostInfo

	confirmsMu sync.Mutex
	confirms   map[*HostInfo]*hybridConfirm
}

func newHybridState() hybridState {
	return hybridState{
		responders: map[uint32]*HandshakeHostInfo{},
		confirms:   map[*HostInfo]*hybridConfirm{},
	}
}

// awaitMsg3 keeps a responder's hybrid handshake pending after msg1, and sends
// msg2. hh is already in the indexes under the local index the Machine
// allocated.
func (hm *HandshakeManager) awaitMsg3(via ViaSender, hh *HandshakeHostInfo, machine *handshake.Machine, packet, response []byte, received int) {
	f := hm.f
	hostinfo := hh.hostinfo

	remoteCert := machine.PeerCert()
	if remoteCert == nil {
		f.l.Error("Handshake did not produce a peer certificate", "from", via)
		hm.DeleteHostInfo(hostinfo)
		return
	}
	vpnAddrs, anyVpnAddrsInCommon, ok := hm.validatePeerCert(via, remoteCert)
	if !ok {
		hm.DeleteHostInfo(hostinfo)
		return
	}
	var rh header.H
	if err := rh.Parse(response); err != nil {
		hm.DeleteHostInfo(hostinfo)
		return
	}

	now := time.Now()
	hostinfo.vpnAddrs = vpnAddrs
	hostinfo.remoteIndexId = rh.RemoteIndex
	// packet aliases the listener's incoming buffer, so this copy must stay.
	hostinfo.HandshakePacket[handshakePacketStage0] = append([]byte(nil), packet[header.Len:]...)
	hostinfo.HandshakePacket[handshakePacketStage2] = response
	hostinfo.remotes = f.lightHouse.QueryCache(vpnAddrs)
	if !via.IsRelayed {
		hostinfo.SetRemote(via.UdpAddr)
	}
	hh.machine = machine
	hh.responder.expires = now.Add(hsTimeout(hm.config.retries, hm.config.tryInterval))

	hm.Lock()
	hm.hybrid.responders[hostinfo.localIndexId] = hh
	hm.Unlock()

	msg := "Handshake message received"
	if !anyVpnAddrsInCommon {
		msg = "Handshake message received, but no vpnNetworks in common."
	}
	f.l.Info(msg,
		"vpnAddrs", vpnAddrs,
		"from", via,
		"certName", remoteCert.Certificate.Name(),
		"certVersion", remoteCert.Certificate.Version(),
		"fingerprint", remoteCert.Fingerprint,
		"issuer", remoteCert.Certificate.Issuer(),
		"initiatorIndex", hostinfo.remoteIndexId,
		"responderIndex", hostinfo.localIndexId,
		"handshake", m{"stage": uint64(machine.MessageIndex()), "style": header.SubTypeName(header.Handshake, machine.Subtype())},
	)

	hm.sendHandshakeResponse(via, response, hostinfo, false, received)
	hm.pqAnswered.add(packet[header.Len:], hostinfo, now)
}

// continueHybridResponder collects msg3 fragments for a pending responder and
// completes the tunnel once they decode and verify.
func (hm *HandshakeManager) continueHybridResponder(via ViaSender, h *header.H, fh fragment.Header, sym []byte) {
	hh := hm.queryIndex(h.RemoteIndex)
	if hh == nil || hh.responder == nil {
		hm.reconfirmHybrid(h.RemoteIndex)
		return
	}
	if fh.MsgLen > hybridMsg3MaxLen {
		return
	}

	hh.Lock()
	defer hh.Unlock()
	if !hm.stillPending(hh, h.RemoteIndex) || fh.FragID != hh.hostinfo.remoteIndexId {
		return
	}

	r := hh.responder
	if r.msg3 == nil {
		a, err := fragment.NewAssembly(fh)
		if err != nil {
			return
		}
		r.msg3 = a
	}
	ready, err := r.msg3.Add(fh, sym)
	if errors.Is(err, fragment.ErrMismatch) {
		r.msg3 = nil
		return
	}
	if err != nil || !ready {
		return
	}
	msg, err := r.msg3.Decode()
	r.msg3 = nil
	if err != nil {
		hm.l.Debug("failed to decode handshake fragments", "from", via, "error", err)
		return
	}

	_, result, err := hh.machine.ProcessPacket(nil, reassembled(h, msg))
	if err != nil {
		if hh.machine.Failed() {
			hm.l.Warn("Failed to process handshake packet, abandoning",
				"vpnAddrs", hh.hostinfo.vpnAddrs, "from", via, "error", err)
			hm.forgetHybridResponder(hh)
		} else {
			hm.l.Debug("Failed to process handshake packet",
				"vpnAddrs", hh.hostinfo.vpnAddrs, "from", via, "error", err)
		}
		return
	}
	if result == nil {
		return
	}
	hm.completeHybridResponder(via, hh, result)
}

// completeHybridResponder brings up the tunnel of a responder whose msg3 verified.
// The caller must hold hh.Lock.
func (hm *HandshakeManager) completeHybridResponder(via ViaSender, hh *HandshakeHostInfo, result *handshake.Result) {
	f := hm.f
	hostinfo := hh.hostinfo
	machine := hh.machine
	defer hm.forgetHybridResponder(hh)

	cs, err := newConnectionStateFromResult(result)
	if err != nil {
		f.l.Error("Discarding handshake with an invalid message index", "error", err, "vpnAddrs", hostinfo.vpnAddrs)
		return
	}
	hostinfo.ConnectionState = cs
	hostinfo.remoteIndexId = result.RemoteIndex
	hostinfo.lastHandshakeTime = result.HandshakeTime
	if !via.IsRelayed {
		hostinfo.SetRemote(via.UdpAddr)
	} else {
		hostinfo.relayState.InsertRelayTo(via.relayHI.vpnAddrs[0])
	}
	remoteCert := result.RemoteCert
	hostinfo.buildNetworks(f.myVpnNetworksTable, remoteCert.Certificate)

	// The initiator only sends msg3 once it settled on this handshake, so this
	// tunnel wins even over a newer one: a classical attempt that crossed it, say,
	// which the initiator has already given up on.
	existing, err := hm.checkAndComplete(hostinfo, handshakePacketStage0, f, true)
	if err != nil {
		hm.handleCheckAndCompleteError(err, existing, hostinfo, via, machine.Subtype(), 0)
		return
	}

	f.l.Info("Handshake completed",
		"vpnAddrs", hostinfo.vpnAddrs,
		"from", via,
		"certName", remoteCert.Certificate.Name(),
		"certVersion", remoteCert.Certificate.Version(),
		"fingerprint", remoteCert.Fingerprint,
		"issuer", remoteCert.Certificate.Issuer(),
		"initiatorIndex", result.RemoteIndex,
		"responderIndex", result.LocalIndex,
		"handshake", m{"stage": uint64(machine.MessageIndex()), "style": header.SubTypeName(header.Handshake, machine.Subtype())},
		"durationNs", time.Since(hh.startTime).Nanoseconds(),
	)

	// Let the initiator know, even if there is no traffic to do it.
	hostinfo.handshakeResendAt.Store(time.Now().UnixNano())
	hm.sendHybridConfirmation(hostinfo)

	hm.notePQPeer(machine.Subtype(), hostinfo.vpnAddrs)
	hostinfo.remotes.RefreshFromHandshake(hostinfo.vpnAddrs)
	if f.lightHouse.IsAnyLighthouseAddr(hostinfo.vpnAddrs) {
		f.lightHouse.TriggerUpdate()
	}
}

func (hm *HandshakeManager) sendHybridConfirmation(hostinfo *HostInfo) {
	hm.f.send(header.Test, header.TestReply, hostinfo.ConnectionState, hostinfo, []byte{}, make([]byte, 12, 12), make([]byte, mtu))
}

// reconfirmHybrid answers a msg3 for a hybrid tunnel this responder already
// completed: the initiator is still resending it, so the confirmation was lost.
// Replies are rate limited to one per retry interval and go to the tunnel's
// remote, never to wherever the fragment claims to come from.
func (hm *HandshakeManager) reconfirmHybrid(index uint32) {
	hostinfo := hm.mainHostMap.QueryIndex(index)
	if hostinfo == nil || hostinfo.ConnectionState == nil || hostinfo.ConnectionState.initiator {
		return
	}
	if pc := hostinfo.ConnectionState.peerCert; pc == nil || pc.Certificate.Version() != cert.Version3 {
		return
	}
	now := time.Now().UnixNano()
	last := hostinfo.handshakeResendAt.Load()
	if now-last < int64(hm.config.tryInterval) || !hostinfo.handshakeResendAt.CompareAndSwap(last, now) {
		return
	}
	hm.sendHybridConfirmation(hostinfo)
}

// forgetHybridResponder releases a pending responder's index.
func (hm *HandshakeManager) forgetHybridResponder(hh *HandshakeHostInfo) {
	hm.Lock()
	defer hm.Unlock()
	idx := hh.hostinfo.localIndexId
	if hm.indexes[idx] == hh {
		delete(hm.indexes, idx)
	}
	if hm.hybrid.responders[idx] == hh {
		delete(hm.hybrid.responders, idx)
	}
}

// isHybridResponder reports whether index belongs to a responder still waiting
// for msg3, whose initiator may already be sending data.
func (hm *HandshakeManager) isHybridResponder(index uint32) bool {
	hm.RLock()
	defer hm.RUnlock()
	_, ok := hm.hybrid.responders[index]
	return ok
}

// expireHybridResponders drops responders that never got their msg3.
func (hm *HandshakeManager) expireHybridResponders(now time.Time) {
	hm.Lock()
	defer hm.Unlock()
	for idx, hh := range hm.hybrid.responders {
		if now.After(hh.responder.expires) {
			if hm.indexes[idx] == hh {
				delete(hm.indexes, idx)
			}
			delete(hm.hybrid.responders, idx)
		}
	}
}

// startHybridConfirm sends an initiator's msg3 and keeps resending it until the
// responder is heard from on the new tunnel.
func (hm *HandshakeManager) startHybridConfirm(via ViaSender, hostinfo *HostInfo, msg3 []byte, handshakeLen uint64) {
	var h header.H
	if err := h.Parse(msg3); err != nil {
		return
	}
	s, err := fragment.NewSender(msg3[header.Len:], h.Subtype, h.RemoteIndex, h.MessageCounter, hostinfo.localIndexId)
	if err != nil {
		hostinfo.logger(hm.l).Error("Failed to fragment handshake", "error", err)
		return
	}

	now := time.Now()
	c := &hybridConfirm{
		hostinfo:     hostinfo,
		sender:       s,
		send:         hm.sendTo(via),
		handshakeLen: handshakeLen,
		deadline:     now.Add(hsTimeout(hm.config.retries, hm.config.tryInterval)),
		next:         now.Add(hm.config.tryInterval),
		attempts:     1,
	}
	hm.hybrid.confirmsMu.Lock()
	hm.hybrid.confirms[hostinfo] = c
	hm.hybrid.confirmsMu.Unlock()
	hm.sendHybridMsg3(c)
}

func (hm *HandshakeManager) sendHybridMsg3(c *hybridConfirm) {
	pkts, later, err := c.sender.Attempt(fragment.DefaultRepair(c.sender.Layout().K))
	if err != nil {
		return
	}
	hm.messageMetrics.Tx(header.Handshake, hybridSubtype, int64(len(pkts)+len(later)))
	// No repair delay: the packets cached during the handshake go out right
	// behind msg3, and the responder drops whatever arrives before msg3
	// completes. With the repair trailing, losing either data fragment would
	// cost them. msg3 is four packets, too short for the tail drop the delay
	// guards against.
	if err := hm.sendFragmentedAfter(pkts, later, c.send, 0); err != nil {
		c.hostinfo.logger(hm.l).Debug("Failed to send handshake message", "error", err)
	}
}

// tickHybridConfirms resends msg3 to responders not heard from yet, and closes
// tunnels whose responder never was.
func (hm *HandshakeManager) tickHybridConfirms(now time.Time) {
	var resend, closing []*hybridConfirm
	hm.hybrid.confirmsMu.Lock()
	for hostinfo, c := range hm.hybrid.confirms {
		switch {
		case hm.mainHostMap.QueryIndex(hostinfo.localIndexId) != hostinfo:
			delete(hm.hybrid.confirms, hostinfo)
		case hostinfo.ConnectionState.heardFromPeer(c.handshakeLen):
			delete(hm.hybrid.confirms, hostinfo)
		case now.After(c.deadline):
			delete(hm.hybrid.confirms, hostinfo)
			closing = append(closing, c)
		case !now.Before(c.next):
			c.attempts++
			c.next = now.Add(hm.config.tryInterval * time.Duration(c.attempts))
			resend = append(resend, c)
		}
	}
	hm.hybrid.confirmsMu.Unlock()

	for _, c := range resend {
		if hm.l.Enabled(context.Background(), slog.LevelDebug) {
			c.hostinfo.logger(hm.l).Debug("Resending handshake message, responder not heard from yet", "attempts", c.attempts)
		}
		hm.sendHybridMsg3(c)
	}
	for _, c := range closing {
		c.hostinfo.logger(hm.l).Info("Responder never confirmed the handshake, closing tunnel",
			"localIndex", c.hostinfo.localIndexId, "remoteIndex", c.hostinfo.remoteIndexId)
		hm.f.closeTunnel(c.hostinfo)
	}
}
