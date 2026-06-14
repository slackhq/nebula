package nebula

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/rcrowley/go-metrics"
	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/handshake"
	"github.com/slackhq/nebula/header"
	"github.com/slackhq/nebula/pq"
	"github.com/slackhq/nebula/udp"
)

const (
	DefaultHandshakeTryInterval   = time.Millisecond * 100
	DefaultHandshakeRetries       = 10
	DefaultHandshakeTriggerBuffer = 64

	// maxCachedPackets is how many unsent packets we'll buffer per pending
	// handshake before dropping further ones.
	maxCachedPackets = 100

	// HandshakePacket map keys mirror the IX protocol stage convention:
	//   stage 0 = the initiator's first message (and what the responder
	//             receives, stripped of header)
	//   stage 2 = the responder's reply
	// Other handshake patterns will need new keys when added.
	handshakePacketStage0 uint8 = 0
	handshakePacketStage2 uint8 = 2
)

var (
	defaultHandshakeConfig = HandshakeConfig{
		tryInterval:   DefaultHandshakeTryInterval,
		retries:       DefaultHandshakeRetries,
		triggerBuffer: DefaultHandshakeTriggerBuffer,
	}
)

type HandshakeConfig struct {
	tryInterval   time.Duration
	retries       int64
	triggerBuffer int

	messageMetrics *MessageMetrics
}

type HandshakeManager struct {
	// Mutex for interacting with the vpnIps and indexes maps
	sync.RWMutex

	vpnIps  map[netip.Addr]*HandshakeHostInfo
	indexes map[uint32]*HandshakeHostInfo

	mainHostMap            *HostMap
	lightHouse             *LightHouse
	outside                udp.Conn
	config                 HandshakeConfig
	OutboundHandshakeTimer *LockingTimerWheel[netip.Addr]
	messageMetrics         *MessageMetrics
	metricInitiated        metrics.Counter
	metricTimedOut         metrics.Counter
	metricPQTimedOut       metrics.Counter
	f                      *Interface
	l                      *slog.Logger

	// pqPeerStats tracks per-peer IXPSK2 failure counts for the
	// pq-status ssh command. Bounded; eviction is arbitrary via map
	// iteration, acceptable for a diagnostic surface.
	pqStatsLock sync.Mutex
	pqPeerStats map[netip.Addr]*pqPeerStat

	// pqAltEpoch is the responder-side hint cache for epoch-skew
	// healing. When the initiator sends a rapid re-msg1 shortly after
	// we answered with a current-epoch msg2, the strong inference is
	// that the initiator rejected our PSK — so we try our previous
	// epoch once (mirroring the initiator's SwapPSK retry).
	pqAltEpoch *pq.AltEpochHint

	// can be used to trigger outbound handshake for the given vpnIp
	trigger chan netip.Addr
}

type HandshakeHostInfo struct {
	sync.Mutex

	startTime                 time.Time        // Time that we first started trying with this handshake
	ready                     bool             // Is the handshake ready
	initiatingVersionOverride cert.Version     // Should we use a non-default cert version for this handshake?
	counter                   int64            // How many attempts have we made so far
	lastRemotes               []netip.AddrPort // Remotes that we sent to during the previous attempt
	lastRelays                []netip.Addr     // Relays we attempted to use during the previous attempt
	packetStore               []*cachedPacket  // A set of packets to be transmitted once the handshake completes
	triedPrevPSK              bool             // initiator: previous-epoch swap already attempted for this handshake

	hostinfo *HostInfo
	machine  *handshake.Machine // The handshake state machine, set during stage 0 (initiator) or beginHandshake (responder multi-message)
}

func (hh *HandshakeHostInfo) cachePacket(l *slog.Logger, t header.MessageType, st header.MessageSubType, packet []byte, f packetCallback, m *cachedPacketMetrics) {
	if len(hh.packetStore) < maxCachedPackets {
		tempPacket := make([]byte, len(packet))
		copy(tempPacket, packet)

		hh.packetStore = append(hh.packetStore, &cachedPacket{t, st, f, tempPacket})
		if l.Enabled(context.Background(), slog.LevelDebug) {
			hh.hostinfo.logger(l).Debug("Packet store",
				"length", len(hh.packetStore),
				"stored", true,
			)
		}

	} else {
		m.dropped.Inc(1)

		if l.Enabled(context.Background(), slog.LevelDebug) {
			hh.hostinfo.logger(l).Debug("Packet store",
				"length", len(hh.packetStore),
				"stored", false,
			)
		}
	}
}

// isAddressFamilyMismatch reports whether err is the well-known
// "tried to send a v6 packet on a v4-only UDP socket" (or vice-
// versa) error from the kernel. We see this on handshake send paths
// whenever a peer's HostInfo carries both v4 and v6 remotes but the
// local listener is single-family. The handshake still completes
// over the matching-family address(es) in the same remotes set, so
// this is operationally noise rather than a failure. Demoting the
// per-attempt log line keeps prod logs clean without losing real
// errors.
//
// Detection is string-based because the underlying errors come from
// net.UDPConn.WriteToUDPAddrPort and are not wrapped in a typed
// sentinel. Both "non-IPv4 address" and "non-IPv6 address" patterns
// occur, depending on which way the mismatch goes.
func isAddressFamilyMismatch(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "non-IPv4 address") || strings.Contains(s, "non-IPv6 address")
}

func NewHandshakeManager(l *slog.Logger, mainHostMap *HostMap, lightHouse *LightHouse, outside udp.Conn, config HandshakeConfig) *HandshakeManager {
	return &HandshakeManager{
		vpnIps:                 map[netip.Addr]*HandshakeHostInfo{},
		indexes:                map[uint32]*HandshakeHostInfo{},
		mainHostMap:            mainHostMap,
		lightHouse:             lightHouse,
		outside:                outside,
		config:                 config,
		trigger:                make(chan netip.Addr, config.triggerBuffer),
		OutboundHandshakeTimer: NewLockingTimerWheel[netip.Addr](config.tryInterval, hsTimeout(config.retries, config.tryInterval)),
		messageMetrics:         config.messageMetrics,
		metricInitiated:        metrics.GetOrRegisterCounter("handshake_manager.initiated", nil),
		metricTimedOut:         metrics.GetOrRegisterCounter("handshake_manager.timed_out", nil),
		metricPQTimedOut:       metrics.GetOrRegisterCounter("pq.handshake_ixpsk2_timed_out", nil),
		pqPeerStats:            make(map[netip.Addr]*pqPeerStat),
		pqAltEpoch:             pq.NewAltEpochHint(),
		l:                      l,
	}
}

func (hm *HandshakeManager) Run(ctx context.Context) {
	clockSource := time.NewTicker(hm.config.tryInterval)
	defer clockSource.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case vpnIP := <-hm.trigger:
			hm.handleOutbound(vpnIP, true)
		case now := <-clockSource.C:
			hm.NextOutboundHandshakeTimerTick(now)
		}
	}
}

func (hm *HandshakeManager) HandleIncoming(via ViaSender, packet []byte, h *header.H) {
	// Gate on known handshake subtypes. Unknown subtypes (or future ones we
	// don't yet support) are dropped here rather than silently routed through
	// the IX path. Add a case when introducing a new pattern.
	switch h.Subtype {
	case header.HandshakeIXPSK0, header.HandshakeIXPSK2:
		// supported
	default:
		hm.l.Debug("dropping handshake with unsupported subtype",
			"from", via, "subtype", h.Subtype)
		return
	}

	// First remote allow list check before we know the vpnIp
	if !via.IsRelayed {
		if !hm.lightHouse.GetRemoteAllowList().AllowUnknownVpnAddr(via.UdpAddr.Addr()) {
			hm.l.Debug("lighthouse.remote_allow_list denied incoming handshake", "from", via)
			return
		}
	}

	// First message of a new handshake. The wire format requires RemoteIndex
	// to be zero here (the initiator has no responder index to fill in yet),
	// and generateIndex never allocates 0, so any non-zero RemoteIndex on a
	// stage-1 packet is malformed or someone probing for an index collision.
	// Drop without paying the cost of running noise on a pending Machine.
	if h.MessageCounter == 1 {
		if h.RemoteIndex != 0 {
			hm.l.Debug("dropping stage-1 handshake with non-zero RemoteIndex",
				"from", via, "remoteIndex", h.RemoteIndex)
			return
		}
		hm.beginHandshake(via, packet, h)
		return
	}

	// Continuation message must match a pending handshake by index.
	// Anything else is an orphaned packet (e.g., late retransmit after
	// timeout) and is dropped.
	if hh := hm.queryIndex(h.RemoteIndex); hh != nil {
		hm.continueHandshake(via, hh, packet)
		return
	}
}

func (hm *HandshakeManager) NextOutboundHandshakeTimerTick(now time.Time) {
	hm.OutboundHandshakeTimer.Advance(now)
	for {
		vpnIp, has := hm.OutboundHandshakeTimer.Purge()
		if !has {
			break
		}
		hm.handleOutbound(vpnIp, false)
	}
}

func (hm *HandshakeManager) handleOutbound(vpnIp netip.Addr, lighthouseTriggered bool) {
	hh := hm.queryVpnIp(vpnIp)
	if hh == nil {
		return
	}
	hh.Lock()
	defer hh.Unlock()

	hostinfo := hh.hostinfo
	// If we are out of time, clean up
	if hh.counter >= hm.config.retries {
		fields := []any{
			"udpAddrs", hh.hostinfo.remotes.CopyAddrs(hm.mainHostMap.GetPreferredRanges()),
			"initiatorIndex", hh.hostinfo.localIndexId,
			"durationNs", time.Since(hh.startTime).Nanoseconds(),
		}
		// hh.machine can be nil here if buildStage0Packet never succeeded
		// (e.g., no certificate available). In that case there's no useful
		// handshake metadata to log.
		if hh.machine != nil {
			fields = append(fields, "handshake", m{
				"stage": uint64(hh.machine.MessageIndex()),
				"style": header.SubTypeName(header.Handshake, hh.machine.Subtype()),
			})
			// An IXPSK2 timeout has one cause a plain timeout doesn't:
			// both sides hold a PSK for each other but the bytes differ
			// (rosenpass epoch mismatch, broken pairing), which makes the
			// responder's msg2 undecryptable here and looks identical to
			// a dead peer. Count it separately and hint, so an operator
			// staring at a reachable-but-unconnectable pair has a thread
			// to pull instead of just "timed out".
			if hh.machine.Subtype() == header.HandshakeIXPSK2 {
				hm.metricPQTimedOut.Inc(1)
				// NB: a plain timeout does NOT arm the IXPSK0 degrade.
				// Timeouts are ambiguous (dead peer, packet loss, or an
				// attacker dropping handshake packets) — degrading on
				// them lets a packet-dropper cheaply strip PQ to
				// classical. The degrade is armed only on repeated msg2
				// AEAD rejects (proven PSK desync) in continueHandshake.
				hm.bumpPQStat(vpnIp, func(s *pqPeerStat) { s.Timeouts++ })
				fields = append(fields, "pqHint",
					"IXPSK2 timeout: if the peer is otherwise reachable, compare both sides' PQ PSK material (possible epoch mismatch / broken rosenpass pairing); see pq.handshake_ixpsk2_msg2_reject")
			}
		}
		hh.hostinfo.logger(hm.l).Info("Handshake timed out", fields...)
		hm.metricTimedOut.Inc(1)
		hm.DeleteHostInfo(hostinfo)
		return
	}

	// Increment the counter to increase our delay, linear backoff
	hh.counter++

	// Check if we have a handshake packet to transmit yet
	if !hh.ready {
		if !hm.buildStage0Packet(hh) {
			hm.OutboundHandshakeTimer.Add(vpnIp, hm.config.tryInterval*time.Duration(hh.counter))
			return
		}
	}

	// TODO: this hardcodes "always retransmit stage 0", which is correct for
	// IX (the initiator only ever sends one packet, msg1) but wrong the
	// moment a 3+ message pattern lands. The retry loop should resend the
	// most recent outgoing message, not always stage 0. That implies
	// HandshakeHostInfo tracking a single "currentOutbound" packet (bytes +
	// header metadata) that gets replaced as the handshake progresses,
	// instead of indexing into HandshakePacket.
	stage0 := hostinfo.HandshakePacket[handshakePacketStage0]
	hsFields := m{
		"stage": uint64(hh.machine.MessageIndex()),
		"style": header.SubTypeName(header.Handshake, hh.machine.Subtype()),
	}

	// Get a remotes object if we don't already have one.
	// This is mainly to protect us as this should never be the case
	// NB ^ This comment doesn't jive. It's how the thing gets initialized.
	// It's the common path. Should it update every time, in case a future LH query/queries give us more info?
	if hostinfo.remotes == nil {
		hostinfo.remotes = hm.lightHouse.QueryCache([]netip.Addr{vpnIp})
	}

	remotes := hostinfo.remotes.CopyAddrs(hm.mainHostMap.GetPreferredRanges())
	remotesHaveChanged := !slices.Equal(remotes, hh.lastRemotes)

	// We only care about a lighthouse trigger if we have new remotes to send to.
	// This is a very specific optimization for a fast lighthouse reply.
	if lighthouseTriggered && !remotesHaveChanged {
		// If we didn't return here a lighthouse could cause us to aggressively send handshakes
		return
	}

	hh.lastRemotes = remotes

	// This will generate a load of queries for hosts with only 1 ip
	// (such as ones registered to the lighthouse with only a private IP)
	// So we only do it one time after attempting 5 handshakes already.
	if len(remotes) <= 1 && hh.counter == 5 {
		// If we only have 1 remote it is highly likely our query raced with the other host registered within the lighthouse
		// Our vpnIp here has a tunnel with a lighthouse but has yet to send a host update packet there so we only know about
		// the learned public ip for them. Query again to short circuit the promotion counter
		hm.lightHouse.QueryServer(vpnIp)
	}

	// Send the handshake to all known ips, stage 2 takes care of assigning the hostinfo.remote based on the first to reply
	var sentTo []netip.AddrPort
	hostinfo.remotes.ForEach(hm.mainHostMap.GetPreferredRanges(), func(addr netip.AddrPort, _ bool) {
		hm.messageMetrics.Tx(header.Handshake, hh.machine.Subtype(), 1)
		err := hm.outside.WriteTo(stage0, addr)
		if err != nil {
			// Listener-family / dest-family mismatch (e.g. v4-only
			// listener but a v6 remote in our cert-asserted list) is
			// an EXPECTED non-error — handshake completes via the
			// other-family fallback addresses in the same remotes
			// slice. Demoting to Debug avoids polluting prod logs
			// with one ERROR per send attempt per mismatched address.
			if isAddressFamilyMismatch(err) {
				hostinfo.logger(hm.l).Debug("skipping handshake address (listener family mismatch)",
					"udpAddr", addr, "err", err)
			} else {
				hostinfo.logger(hm.l).Error("Failed to send handshake message",
					"udpAddr", addr,
					"initiatorIndex", hostinfo.localIndexId,
					"handshake", hsFields,
					"error", err,
				)
			}
		} else {
			sentTo = append(sentTo, addr)
		}
	})

	// Don't be too noisy or confusing if we fail to send a handshake - if we don't get through we'll eventually log a timeout,
	// so only log when the list of remotes has changed
	if remotesHaveChanged {
		hostinfo.logger(hm.l).Info("Handshake message sent",
			"udpAddrs", sentTo,
			"initiatorIndex", hostinfo.localIndexId,
			"handshake", hsFields,
		)
	} else if hm.l.Enabled(context.Background(), slog.LevelDebug) {
		hostinfo.logger(hm.l).Debug("Handshake message sent",
			"udpAddrs", sentTo,
			"initiatorIndex", hostinfo.localIndexId,
			"handshake", hsFields,
		)
	}

	hm.f.relayManager.StartRelays(hm.f, vpnIp, hh, stage0)

	// If a lighthouse triggered this attempt then we are still in the timer wheel and do not need to re-add
	if !lighthouseTriggered {
		hm.OutboundHandshakeTimer.Add(vpnIp, hm.config.tryInterval*time.Duration(hh.counter))
	}
}

// GetOrHandshake will try to find a hostinfo with a fully formed tunnel or start a new handshake if one is not present
// The 2nd argument will be true if the hostinfo is ready to transmit traffic
func (hm *HandshakeManager) GetOrHandshake(vpnIp netip.Addr, cacheCb func(*HandshakeHostInfo)) (*HostInfo, bool) {
	hm.mainHostMap.RLock()
	h, ok := hm.mainHostMap.Hosts[vpnIp]
	hm.mainHostMap.RUnlock()

	if ok {
		// Do not attempt promotion if you are a lighthouse
		if !hm.lightHouse.amLighthouse {
			h.TryPromoteBest(hm.mainHostMap.GetPreferredRanges(), hm.f)
		}
		return h, true
	}

	return hm.StartHandshake(vpnIp, cacheCb), false
}

// StartHandshake will ensure a handshake is currently being attempted for the provided vpn ip
func (hm *HandshakeManager) StartHandshake(vpnAddr netip.Addr, cacheCb func(*HandshakeHostInfo)) *HostInfo {
	hm.Lock()

	if hh, ok := hm.vpnIps[vpnAddr]; ok {
		// We are already trying to handshake with this vpn ip
		if cacheCb != nil {
			cacheCb(hh)
		}
		hm.Unlock()
		return hh.hostinfo
	}

	hostinfo := &HostInfo{
		vpnAddrs:        []netip.Addr{vpnAddr},
		HandshakePacket: make(map[uint8][]byte, 0),
		relayState: RelayState{
			relays:         nil,
			relayForByAddr: map[netip.Addr]*Relay{},
			relayForByIdx:  map[uint32]*Relay{},
		},
	}

	hh := &HandshakeHostInfo{
		hostinfo:  hostinfo,
		startTime: time.Now(),
	}
	hm.vpnIps[vpnAddr] = hh
	hm.metricInitiated.Inc(1)
	hm.OutboundHandshakeTimer.Add(vpnAddr, hm.config.tryInterval)

	if cacheCb != nil {
		cacheCb(hh)
	}

	// If this is a static host, we don't need to wait for the HostQueryReply
	// We can trigger the handshake right now
	_, doTrigger := hm.lightHouse.GetStaticHostList()[vpnAddr]
	if !doTrigger {
		// Add any calculated remotes, and trigger early handshake if one found
		doTrigger = hm.lightHouse.addCalculatedRemotes(vpnAddr)
	}

	if doTrigger {
		select {
		case hm.trigger <- vpnAddr:
		default:
		}
	}

	hm.Unlock()
	hm.lightHouse.QueryServer(vpnAddr)
	return hostinfo
}

var (
	ErrExistingHostInfo    = errors.New("existing hostinfo")
	ErrAlreadySeen         = errors.New("already seen")
	ErrLocalIndexCollision = errors.New("local index collision")
)

// CheckAndComplete checks for any conflicts in the main and pending hostmap
// before adding hostinfo to main. If err is nil, it was added. Otherwise err will be:
//
// ErrAlreadySeen if we already have an entry in the hostmap that has seen the
// exact same handshake packet
//
// ErrExistingHostInfo if we already have an entry in the hostmap for this
// VpnIp and the new handshake was older than the one we currently have
//
// ErrLocalIndexCollision if we already have an entry in the main or pending
// hostmap for the hostinfo.localIndexId.
func (hm *HandshakeManager) CheckAndComplete(hostinfo *HostInfo, handshakePacket uint8, f *Interface) (*HostInfo, error) {
	hm.mainHostMap.Lock()
	defer hm.mainHostMap.Unlock()
	hm.Lock()
	defer hm.Unlock()

	// Check if we already have a tunnel with this vpn ip
	existingHostInfo, found := hm.mainHostMap.Hosts[hostinfo.vpnAddrs[0]]
	if found && existingHostInfo != nil {
		testHostInfo := existingHostInfo
		for testHostInfo != nil {
			// Is it just a delayed handshake packet?
			if bytes.Equal(hostinfo.HandshakePacket[handshakePacket], testHostInfo.HandshakePacket[handshakePacket]) {
				return testHostInfo, ErrAlreadySeen
			}

			testHostInfo = testHostInfo.next
		}

		// Is this a newer handshake?
		if existingHostInfo.lastHandshakeTime >= hostinfo.lastHandshakeTime && !existingHostInfo.ConnectionState.initiator {
			return existingHostInfo, ErrExistingHostInfo
		}

		existingHostInfo.logger(hm.l).Info("Taking new handshake")
	}

	existingIndex, found := hm.mainHostMap.Indexes[hostinfo.localIndexId]
	if found {
		// We have a collision, but for a different hostinfo
		return existingIndex, ErrLocalIndexCollision
	}

	existingPendingIndex, found := hm.indexes[hostinfo.localIndexId]
	if found && existingPendingIndex.hostinfo != hostinfo {
		// We have a collision, but for a different hostinfo
		return existingPendingIndex.hostinfo, ErrLocalIndexCollision
	}

	existingRemoteIndex, found := hm.mainHostMap.RemoteIndexes[hostinfo.remoteIndexId]
	if found && existingRemoteIndex != nil && existingRemoteIndex.vpnAddrs[0] != hostinfo.vpnAddrs[0] {
		// We have a collision, but this can happen since we can't control
		// the remote ID. Just log about the situation as a note.
		hostinfo.logger(hm.l).Info("New host shadows existing host remoteIndex",
			"collision", existingRemoteIndex.vpnAddrs,
		)
	}

	hm.mainHostMap.unlockedAddHostInfo(hostinfo, f)
	return existingHostInfo, nil
}

// Complete is a simpler version of CheckAndComplete when we already know we
// won't have a localIndexId collision because we already have an entry in the
// pendingHostMap. An existing hostinfo is returned if there was one.
func (hm *HandshakeManager) Complete(hostinfo *HostInfo, f *Interface) {
	hm.mainHostMap.Lock()
	defer hm.mainHostMap.Unlock()
	hm.Lock()
	defer hm.Unlock()

	existingRemoteIndex, found := hm.mainHostMap.RemoteIndexes[hostinfo.remoteIndexId]
	if found && existingRemoteIndex != nil {
		// We have a collision, but this can happen since we can't control
		// the remote ID. Just log about the situation as a note.
		hostinfo.logger(hm.l).Info("New host shadows existing host remoteIndex",
			"collision", existingRemoteIndex.vpnAddrs,
		)
	}

	// We need to remove from the pending hostmap first to avoid undoing work when after to the main hostmap.
	hm.unlockedDeleteHostInfo(hostinfo)
	hm.mainHostMap.unlockedAddHostInfo(hostinfo, f)
}

// allocateIndex generates a unique localIndexId for this HostInfo
// and adds it to the pendingHostMap. Will error if we are unable to generate
// a unique localIndexId
func (hm *HandshakeManager) allocateIndex(hh *HandshakeHostInfo) (uint32, error) {
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
			hh.hostinfo.localIndexId = index
			hm.indexes[index] = hh
			return index, nil
		}
	}

	return 0, errors.New("failed to generate unique localIndexId")
}

func (hm *HandshakeManager) DeleteHostInfo(hostinfo *HostInfo) {
	hm.Lock()
	defer hm.Unlock()
	hm.unlockedDeleteHostInfo(hostinfo)
}

func (hm *HandshakeManager) unlockedDeleteHostInfo(hostinfo *HostInfo) {
	for _, addr := range hostinfo.vpnAddrs {
		delete(hm.vpnIps, addr)
	}

	if len(hm.vpnIps) == 0 {
		hm.vpnIps = map[netip.Addr]*HandshakeHostInfo{}
	}

	delete(hm.indexes, hostinfo.localIndexId)
	if len(hm.indexes) == 0 {
		hm.indexes = map[uint32]*HandshakeHostInfo{}
	}

	if hm.l.Enabled(context.Background(), slog.LevelDebug) {
		hm.l.Debug("Pending hostmap hostInfo deleted",
			"hostMap", m{"mapTotalSize": len(hm.vpnIps),
				"vpnAddrs": hostinfo.vpnAddrs, "indexNumber": hostinfo.localIndexId, "remoteIndexNumber": hostinfo.remoteIndexId},
		)
	}
}

func (hm *HandshakeManager) QueryVpnAddr(vpnIp netip.Addr) *HostInfo {
	hh := hm.queryVpnIp(vpnIp)
	if hh != nil {
		return hh.hostinfo
	}
	return nil

}

func (hm *HandshakeManager) queryVpnIp(vpnIp netip.Addr) *HandshakeHostInfo {
	hm.RLock()
	defer hm.RUnlock()
	return hm.vpnIps[vpnIp]
}

func (hm *HandshakeManager) QueryIndex(index uint32) *HostInfo {
	hh := hm.queryIndex(index)
	if hh != nil {
		return hh.hostinfo
	}
	return nil
}

func (hm *HandshakeManager) queryIndex(index uint32) *HandshakeHostInfo {
	hm.RLock()
	defer hm.RUnlock()
	return hm.indexes[index]
}

func (hm *HandshakeManager) GetPreferredRanges() []netip.Prefix {
	return hm.mainHostMap.GetPreferredRanges()
}

func (hm *HandshakeManager) ForEachVpnAddr(f controlEach) {
	hm.RLock()
	defer hm.RUnlock()

	for _, v := range hm.vpnIps {
		f(v.hostinfo)
	}
}

func (hm *HandshakeManager) ForEachIndex(f controlEach) {
	hm.RLock()
	defer hm.RUnlock()

	for _, v := range hm.indexes {
		f(v.hostinfo)
	}
}

func (hm *HandshakeManager) EmitStats() {
	hm.RLock()
	hostLen := len(hm.vpnIps)
	indexLen := len(hm.indexes)
	hm.RUnlock()

	metrics.GetOrRegisterGauge("hostmap.pending.hosts", nil).Update(int64(hostLen))
	metrics.GetOrRegisterGauge("hostmap.pending.indexes", nil).Update(int64(indexLen))
	hm.mainHostMap.EmitStats()
}

// Utility functions below

func generateIndex(l *slog.Logger) (uint32, error) {
	b := make([]byte, 4)

	// Let zero mean we don't know the ID, so don't generate zero
	var index uint32
	for index == 0 {
		_, err := rand.Read(b)
		if err != nil {
			l.Error("Failed to generate index", "error", err)
			return 0, err
		}

		index = binary.BigEndian.Uint32(b)
	}

	if l.Enabled(context.Background(), slog.LevelDebug) {
		l.Debug("Generated index", "index", index)
	}
	return index, nil
}

func hsTimeout(tries int64, interval time.Duration) time.Duration {
	return time.Duration(tries / 2 * ((2 * int64(interval)) + (tries-1)*int64(interval)))
}

// notifyPQProvider is defined twice in the provider layer: an embedded
// build behind a build tag, and a default-build stub. Both declare the
// same function signature; the stub version is a no-op so handshake
// completion paths can call into it unconditionally without dragging
// the embedded provider package into the default build.

// vpnAddrsToStrings is a small helper for the pq.Store API, which
// keys its secondary index by VPN address string form.
func vpnAddrsToStrings(addrs []netip.Addr) []string {
	if len(addrs) == 0 {
		return nil
	}
	out := make([]string, len(addrs))
	for i, a := range addrs {
		out[i] = a.String()
	}
	return out
}

type pqPeerStat struct {
	Msg2Rejects uint64
	Timeouts    uint64
	// degradeUntilNanos: while now < this, the initiator bootstraps with
	// IXPSK0 instead of IXPSK2 for this peer. Set after repeated IXPSK2
	// timeouts. Breaks the deadlock where two peers each hold a PSK for
	// the other but the bytes differ (rosenpass epoch desync): IXPSK2
	// can't complete, so the rosenpass KEX that would re-sync the PSK
	// can't travel over the (never-formed) tunnel. Falling back to
	// IXPSK0 forms the classical tunnel, rosenpass re-keys over it, and
	// the next post-cooldown attempt upgrades to IXPSK2 cleanly.
	degradeUntilNanos int64
	// DegradeEpisodes is the cumulative count of degrade windows armed
	// for this peer — one per cooldown window, NOT re-counted on a
	// mid-cooldown re-arm. Forensic: it SURVIVES a successful IXPSK2
	// (unlike the transient counters above, which reset) so an operator
	// querying pq-status after a downgrade incident still sees it
	// happened. A non-zero value is the durable record that this link was
	// stripped to classical at least once.
	DegradeEpisodes uint64
	// consecutiveDegrades counts degrade windows since the last clean
	// IXPSK2 completion (which resets it to 0). A run of these means the
	// degrade is NOT self-healing — rosenpass never re-synced over the
	// classical fallback — i.e. a dead/misconfigured sidecar or an active
	// attacker sustaining the strip. Crossing pqDegradeWarnConsecutive
	// emits a WARN.
	consecutiveDegrades uint64
}

const pqPeerStatsCap = 1024

const (
	// pqIXPSK2DegradeThreshold is how many IXPSK2 msg2 AEAD rejects to a
	// peer (after the previous-epoch SwapPSK heal also failed, i.e. a
	// genuine multi-epoch-unrecoverable PSK desync) before the initiator
	// degrades to IXPSK0. Rejects accrue across handshake cycles, so this
	// requires a persistent desync, not a one-off blip.
	pqIXPSK2DegradeThreshold = 2
	// pqIXPSK2DegradeCooldown is how long to stay on IXPSK0 after
	// degrading — long enough for rosenpass to complete a fresh KEX over
	// the now-classical tunnel (rekey is ~tens of seconds) before we
	// retry IXPSK2. A successful IXPSK2 completion clears it early.
	pqIXPSK2DegradeCooldown = 60 * time.Second
	// pqDegradeWarnConsecutive is how many consecutive degrade windows
	// (no clean IXPSK2 in between) trigger a WARN. A self-healing desync
	// resolves in one window (rosenpass re-keys, IXPSK2 succeeds, the run
	// resets), so a run this long means the heal is NOT working: dead
	// sidecar, or an attacker sustaining a downgrade strip.
	pqDegradeWarnConsecutive = 3
)

// pqInDegradeCooldown reports whether the initiator should currently
// bootstrap this peer with IXPSK0 because recent IXPSK2 attempts kept
// timing out (see degradeUntilNanos).
func (hm *HandshakeManager) pqInDegradeCooldown(addr netip.Addr) bool {
	hm.pqStatsLock.Lock()
	defer hm.pqStatsLock.Unlock()
	s, ok := hm.pqPeerStats[addr]
	if !ok || s.degradeUntilNanos == 0 {
		return false
	}
	return time.Now().UnixNano() < s.degradeUntilNanos
}

// PQPeerStats returns a copy of the per-peer IXPSK2 failure counters
// for the pq-status command.
func (hm *HandshakeManager) PQPeerStats() map[netip.Addr]pqPeerStat {
	hm.pqStatsLock.Lock()
	defer hm.pqStatsLock.Unlock()
	out := make(map[netip.Addr]pqPeerStat, len(hm.pqPeerStats))
	for k, v := range hm.pqPeerStats {
		out[k] = *v
	}
	return out
}

func (hm *HandshakeManager) bumpPQStat(addr netip.Addr, f func(*pqPeerStat)) {
	hm.pqStatsLock.Lock()
	defer hm.pqStatsLock.Unlock()
	s, ok := hm.pqPeerStats[addr]
	if !ok {
		if len(hm.pqPeerStats) >= pqPeerStatsCap {
			for k := range hm.pqPeerStats {
				delete(hm.pqPeerStats, k)
				break
			}
		}
		s = &pqPeerStat{}
		hm.pqPeerStats[addr] = s
	}
	f(s)
}

// lookupPrevPSKFor resolves the previous-epoch PSK for the peer of a
// pending initiator handshake, reusing the same identity-resolution
// order as buildStage0Packet (live cert, then main hostmap cert).
// Returns nil when no previous epoch is retained or no identity is
// resolvable — callers treat nil as "healing unavailable".
func (hm *HandshakeManager) lookupPrevPSKFor(hh *HandshakeHostInfo) []byte {
	cs := hm.f.pki.getCertState()
	var cachedCert *cert.CachedCertificate
	if c := hh.hostinfo.GetCert(); c != nil {
		cachedCert = c
	} else if len(hh.hostinfo.vpnAddrs) > 0 {
		hm.mainHostMap.RLock()
		if primary, ok := hm.mainHostMap.Hosts[hh.hostinfo.vpnAddrs[0]]; ok && primary != nil {
			cachedCert = primary.GetCert()
		}
		hm.mainHostMap.RUnlock()
	}
	if cachedCert == nil {
		return nil
	}
	return cs.LookupPQPSKPrev(cachedCert.Certificate.PublicKey(), cachedCert.Certificate)
}

// buildStage0Packet creates the initial handshake packet for the initiator.
func (hm *HandshakeManager) buildStage0Packet(hh *HandshakeHostInfo) bool {
	cs := hm.f.pki.getCertState()
	v := cs.DefaultVersion()
	if hh.initiatingVersionOverride != cert.VersionPre1 {
		v = hh.initiatingVersionOverride
	} else if v < cert.Version2 {
		for _, a := range hh.hostinfo.vpnAddrs {
			if a.Is6() {
				v = cert.Version2
				break
			}
		}
	}

	cred := cs.GetCredential(v)
	if cred == nil {
		hm.f.l.Error("Unable to handshake with host because no certificate is available",
			"vpnAddrs", hh.hostinfo.vpnAddrs, "certVersion", v)
		return false
	}

	// Resolve handshake subtype via the PQ policy. The policy answers
	// based on Provider availability + per-peer history; this code
	// path no longer makes its own decisions.
	//
	// Identity resolution priority for the initiator:
	//   1. ConnectionState on the freshly-allocated hh.hostinfo (rare;
	//      only set after a previous completed handshake on this slot).
	//   2. Cert cached on the primary HostInfo in the main hostmap (a
	//      live tunnel exists; this is the rekey-upgrade case).
	//   3. pq.Policy's persistent identity cache, looked up by VPN
	//      addr. Powers the cold-boot story for per-group overrides:
	//      after a process restart, in-memory state is empty but the
	//      on-disk Store still knows who lives at this VPN addr and
	//      which CA-signed groups they assert, so the boot initiator
	//      can apply DefaultPolicy.Overrides without first waiting
	//      for a fresh handshake to deliver the cert.
	pqPolicy := hm.f.pki.PQPolicy()
	var cachedCert *cert.CachedCertificate
	if c := hh.hostinfo.GetCert(); c != nil {
		cachedCert = c
	} else if len(hh.hostinfo.vpnAddrs) > 0 {
		hm.mainHostMap.RLock()
		if primary, ok := hm.mainHostMap.Hosts[hh.hostinfo.vpnAddrs[0]]; ok && primary != nil {
			cachedCert = primary.GetCert()
		}
		hm.mainHostMap.RUnlock()
	}

	pi := pq.PeerInfo{}
	if cachedCert != nil {
		pi.StaticPubKey = cachedCert.Certificate.PublicKey()
		pi.Fingerprint = cachedCert.Fingerprint
		pi.Groups = cachedCert.Certificate.Groups()
	} else if len(hh.hostinfo.vpnAddrs) > 0 {
		// Boot path: ask the policy's identity cache. If the policy
		// implementation doesn't expose a boot lookup, this is a
		// no-op and we fall through with empty PeerInfo, which the
		// policy translates into an IXPSK0 bootstrap.
		if booter, ok := pqPolicy.(interface {
			LookupBootIdentity(string) (pq.PeerInfo, bool)
		}); ok {
			if booted, hit := booter.LookupBootIdentity(hh.hostinfo.vpnAddrs[0].String()); hit {
				pi = booted
				hm.f.l.Debug("PQ identity resolved from on-disk cache",
					"vpnAddr", hh.hostinfo.vpnAddrs[0], "fingerprint", booted.Fingerprint)
			}
		}
	}
	pqSub, err := pqPolicy.InitiatorSubtype(pi)
	if err != nil {
		// Policy refuses to handshake with this peer at all.
		hm.f.l.Info("Refusing to initiate handshake (PQ policy)",
			"vpnAddrs", hh.hostinfo.vpnAddrs, "error", err)
		return false
	}
	// Opportunistic degrade: if IXPSK2 to this peer has been timing out
	// (PSK epoch desync that IXPSK2 itself can't recover from), bootstrap
	// IXPSK0 for a cooldown so the classical tunnel forms and rosenpass
	// can re-key over it. The post-cooldown attempt upgrades to IXPSK2.
	// Never applies under required mode (InitiatorSubtype errors above if
	// the PSK is mandatory and absent).
	if pqSub == pq.SubtypePerPeer && len(hh.hostinfo.vpnAddrs) > 0 &&
		hm.pqInDegradeCooldown(hh.hostinfo.vpnAddrs[0]) {
		// Never degrade under required mode — that mode demands PQ and
		// the responder would reject IXPSK0 anyway.
		opportunistic := true
		if mp, ok := pqPolicy.(interface {
			ResolvedMode(pq.PeerInfo) pq.Mode
		}); ok {
			opportunistic = mp.ResolvedMode(pi) == pq.ModeOpportunistic
		}
		if opportunistic {
			hm.f.l.Warn("Degrading initiator to IXPSK0 (repeated IXPSK2 timeouts; letting classical bootstrap so rosenpass can re-key)",
				"vpnAddrs", hh.hostinfo.vpnAddrs)
			pqSub = pq.SubtypeNoPSK
		}
	}
	subtype := header.HandshakeIXPSK0
	var peerStatic []byte
	var peerCert cert.Certificate
	if pqSub == pq.SubtypePerPeer {
		subtype = header.HandshakeIXPSK2
		peerStatic = pi.StaticPubKey
		// Hand the cached cert to NewMachine so the PSK lookup can
		// run the PQ-PSK binding check before the
		// PSK is preset into the noise state. cachedCert may be nil
		// on a fresh boot when the only identity hint came from the
		// pq.Store; in that case the lookup wrapper treats nil as
		// "no claim to verify" and falls through to use-PSK.
		if cachedCert != nil {
			peerCert = cachedCert.Certificate
		}
	}

	machine, err := handshake.NewMachine(
		v, cs.GetCredential,
		hm.certVerifier(), func() (uint32, error) { return hm.allocateIndex(hh) },
		true, subtype, peerStatic, peerCert,
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
		return false
	}

	// hostinfo.ConnectionState stays nil until the handshake completes in
	// continueHandshake. Pre-completion control surfaces guard with nil
	// checks; the data plane never observes a pending hostinfo.
	hh.hostinfo.HandshakePacket[handshakePacketStage0] = msg
	hh.machine = machine
	hh.ready = true
	return true
}

// beginHandshake handles an incoming handshake packet that doesn't match any
// existing pending handshake. It creates a new responder Machine and processes
// the first message.
func (hm *HandshakeManager) beginHandshake(via ViaSender, packet []byte, h *header.H) {
	f := hm.f
	cs := f.pki.getCertState()

	v := cs.DefaultVersion()
	if cs.GetCredential(v) == nil {
		f.l.Error("Unable to handshake with host because no certificate is available",
			"from", via, "certVersion", v)
		return
	}

	machine, err := handshake.NewMachine(
		v, cs.GetCredential,
		hm.certVerifier(), func() (uint32, error) { return generateIndex(f.l) },
		false, h.Subtype, nil, nil,
	)
	if err != nil {
		f.l.Error("Failed to create handshake machine", "from", via, "error", err)
		return
	}

	if h.Subtype == header.HandshakeIXPSK2 {
		machine.SetResponderPSKChooser(func(peerStatic []byte) bool {
			return hm.pqAltEpoch.ChoosePrev(string(peerStatic), time.Now())
		})
	}

	response, result, err := machine.ProcessPacket(nil, packet)
	if err != nil {
		// Cold-start race: the PSK provider hasn't been populated yet
		// (sidecar provider mid-first-KEX, or embedded service still
		// warming up). The initiator will retry on its next interval
		// and succeed once the provider has the peer's PSK, so this is
		// expected noise on fresh boot — log at Debug. Once the
		// provider holds at least one PSK, a missing peer is a real
		// misconfig and stays at Error.
		if errors.Is(err, handshake.ErrResponderPSKMissing) && !pq.HasPSK(f.pki.PQProvider()) {
			// Counted so a provider that never populates (broken sidecar,
			// dead keyer) is visible to monitoring even though each
			// individual deferral only logs at Debug.
			metrics.GetOrRegisterCounter("pq.responder_psk_deferred", nil).Inc(1)
			f.l.Debug("Deferring handshake: PSK provider not yet populated", "from", via, "error", err)
			return
		}
		f.l.Error("Failed to process handshake packet", "from", via, "error", err)
		return
	}

	if result == nil {
		// Multi-message pattern: the responder Machine would need to be
		// registered in hm.indexes so a future inbound packet finds it via
		// continueHandshake. The current manager doesn't do that yet, so
		// fail loudly rather than silently dropping the in-flight handshake.
		// TODO: support multi-message responder flows (XX, pqIX, etc.).
		// See also the IX-shaped cipher key assignment in handshake.Machine.
		f.l.Error("multi-message handshake responder is not supported",
			"from", via, "error", handshake.ErrMultiMessageUnsupported)
		return
	}

	remoteCert := result.RemoteCert
	if remoteCert == nil {
		f.l.Error("Handshake did not produce a peer certificate", "from", via)
		return
	}

	// PQ policy gate: now that we know the peer, decide whether the
	// subtype the initiator chose is acceptable. Refusing here drops
	// the in-flight handshake without sending msg2 contents downstream.
	//
	// Ordering note: ProcessPacket has already advanced the noise state
	// and derived session keys by the time this gate runs — the peer
	// identity the policy needs only exists after msg1 is processed (IX
	// carries the cert in msg1, and producing msg2 is part of the same
	// machine step). On rejection those keys are simply discarded with
	// `result`; nothing derived ever touches the wire or a hostinfo.
	// The cost is one wasted WriteMessage per rejected attempt, not a
	// security exposure.
	pqPolicy := f.pki.PQPolicy()
	pqPeer := pq.PeerInfo{
		StaticPubKey: remoteCert.Certificate.PublicKey(),
		Fingerprint:  remoteCert.Fingerprint,
		Groups:       remoteCert.Certificate.Groups(),
	}
	pqIncoming := pq.SubtypeNoPSK
	if h.Subtype == header.HandshakeIXPSK2 {
		pqIncoming = pq.SubtypePerPeer
	}
	if err := pqPolicy.AcceptResponderSubtype(pqPeer, pqIncoming); err != nil {
		f.l.Info("Rejecting handshake (PQ policy)",
			"from", via, "certName", remoteCert.Certificate.Name(),
			"fingerprint", remoteCert.Fingerprint, "subtype", header.SubTypeName(header.Handshake, h.Subtype),
			"error", err)
		pqPolicy.OnHandshakeFailed(pqPeer, pqIncoming, err)
		return
	}

	// Validate peer identity
	vpnAddrs, anyVpnAddrsInCommon, ok := hm.validatePeerCert(via, remoteCert)
	if !ok {
		return
	}

	hostinfo := &HostInfo{
		ConnectionState:   newConnectionStateFromResult(result),
		localIndexId:      result.LocalIndex,
		remoteIndexId:     result.RemoteIndex,
		vpnAddrs:          vpnAddrs,
		HandshakePacket:   make(map[uint8][]byte, 0),
		lastHandshakeTime: result.HandshakeTime,
		relayState: RelayState{
			relays:         nil,
			relayForByAddr: map[netip.Addr]*Relay{},
			relayForByIdx:  map[uint32]*Relay{},
		},
	}

	// Record successful handshake outcome with the policy. For
	// IXPSK2 this captures the peer's identity (cert + pubkey + vpn
	// addrs + groups) in the boot-path identity cache so a future
	// cold boot can resolve this peer's per-group overrides without
	// needing a fresh handshake first.
	if certBytes, err := remoteCert.Certificate.Marshal(); err == nil {
		pqPeer.CertBytes = certBytes
	}
	pqPeer.VpnAddrs = vpnAddrsToStrings(vpnAddrs)
	pqPolicy.OnHandshakeComplete(pqPeer, pqIncoming)
	notifyPQProvider(f, remoteCert, vpnAddrs)

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
		"initiatorIndex", result.RemoteIndex,
		"responderIndex", result.LocalIndex,
		"handshake", m{"stage": uint64(machine.MessageIndex()), "style": header.SubTypeName(header.Handshake, machine.Subtype())},
	)

	if machine.Subtype() == header.HandshakeIXPSK2 {
		peerKey := string(remoteCert.Certificate.PublicKey())
		hm.pqAltEpoch.NoteMsg2(peerKey, time.Now(), machine.UsedPreviousPSK())
		if machine.UsedPreviousPSK() {
			pq.IncCounter(pq.MetricPrevEpochRecovered)
			f.l.Info("IXPSK2 msg2 sent under previous PSK epoch (rotation skew healing)",
				"vpnAddrs", vpnAddrs, "from", via)
		}
	}

	// packet aliases the listener's incoming buffer, so this copy must stay.
	hostinfo.HandshakePacket[handshakePacketStage0] = make([]byte, len(packet[header.Len:]))
	copy(hostinfo.HandshakePacket[handshakePacketStage0], packet[header.Len:])

	// response was freshly allocated by ProcessPacket; safe to retain directly.
	if response != nil {
		hostinfo.HandshakePacket[handshakePacketStage2] = response
	}

	hostinfo.remotes = f.lightHouse.QueryCache(vpnAddrs)
	if !via.IsRelayed {
		hostinfo.SetRemote(via.UdpAddr)
	}
	hostinfo.buildNetworks(f.myVpnNetworksTable, remoteCert.Certificate)

	existing, err := hm.CheckAndComplete(hostinfo, handshakePacketStage0, f)
	if err != nil {
		hm.handleCheckAndCompleteError(err, existing, hostinfo, via)
		return
	}

	hm.sendHandshakeResponse(via, response, hostinfo, false)
	hostinfo.remotes.RefreshFromHandshake(vpnAddrs)

	// Don't wait for UpdateWorker
	if f.lightHouse.IsAnyLighthouseAddr(vpnAddrs) {
		f.lightHouse.TriggerUpdate()
	}
}

// continueHandshake feeds an incoming packet to an existing pending handshake Machine.
func (hm *HandshakeManager) continueHandshake(via ViaSender, hh *HandshakeHostInfo, packet []byte) {
	f := hm.f

	hh.Lock()
	defer hh.Unlock()

	// Re-verify hh is still tracked. Between queryIndex returning and us taking
	// hh.Lock, handleOutbound may have timed out and deleted it. Once we hold
	// hh.Lock no other deleter can race our index: handleOutbound also takes
	// hh.Lock first, and handleRecvError targets a main-hostmap entry with a
	// different localIndexId.
	hm.RLock()
	cur, ok := hm.indexes[hh.hostinfo.localIndexId]
	hm.RUnlock()
	if !ok || cur != hh {
		return
	}

	hostinfo := hh.hostinfo
	if !via.IsRelayed {
		if !f.lightHouse.GetRemoteAllowList().AllowAll(hostinfo.vpnAddrs, via.UdpAddr.Addr()) {
			f.l.Debug("lighthouse.remote_allow_list denied incoming handshake",
				"vpnAddrs", hostinfo.vpnAddrs, "from", via)
			return
		}
	}

	machine := hh.machine
	if machine == nil {
		f.l.Error("No handshake machine available for continuation",
			"vpnAddrs", hostinfo.vpnAddrs, "from", via)
		hm.DeleteHostInfo(hostinfo)
		return
	}

	response, result, err := machine.ProcessPacket(nil, packet)
	if err != nil {
		// IXPSK2 epoch-skew healing: a non-fatal ReadMessage failure on
		// an initiator waiting for msg2 means the peer is alive but the
		// PSK bytes differ (AEAD reject) — the epoch-mismatch signature.
		// noise rolled back, so swap in the previous-epoch PSK (if the
		// provider retained one) and re-process the SAME packet: a
		// zero-round-trip retry. One attempt per handshake.
		if !machine.Failed() &&
			machine.Subtype() == header.HandshakeIXPSK2 &&
			machine.MessageIndex() == 1 &&
			!hh.triedPrevPSK {
			pq.IncCounter(pq.MetricHandshakeMsg2Reject)
			if len(hostinfo.vpnAddrs) > 0 {
				hm.bumpPQStat(hostinfo.vpnAddrs[0], func(s *pqPeerStat) { s.Msg2Rejects++ })
			}
			hh.triedPrevPSK = true
			if prev := hm.lookupPrevPSKFor(hh); prev != nil {
				if swapErr := machine.SwapPSK(prev); swapErr == nil {
					response, result, err = machine.ProcessPacket(nil, packet)
					if err == nil {
						pq.IncCounter(pq.MetricPrevEpochRecovered)
						f.l.Info("IXPSK2 msg2 accepted under previous PSK epoch (rotation skew healed)",
							"vpnAddrs", hostinfo.vpnAddrs, "from", via)
					}
				}
				pq.Wipe(prev)
			}
			// Genuine, multi-epoch-unrecoverable PSK desync: the responder
			// replied but neither the current nor previous epoch PSK
			// decrypts its msg2 (err still set). This is the deadlock
			// signature — IXPSK2 can't complete, so the rosenpass KEX that
			// would re-sync the PSK can't travel over the never-formed
			// tunnel. After pqIXPSK2DegradeThreshold such rejects (across
			// handshake cycles), drop to IXPSK0 for a cooldown so the
			// classical tunnel forms and rosenpass re-keys over it; the
			// post-cooldown attempt then upgrades to IXPSK2.
			//
			// Armed ONLY here (proven AEAD reject), never on a plain
			// timeout — a packet-dropping attacker produces timeouts, not
			// rejects, so they cannot use this to strip PQ to classical.
			if err != nil && len(hostinfo.vpnAddrs) > 0 {
				var armedEpisode bool
				var consec, episodes uint64
				hm.bumpPQStat(hostinfo.vpnAddrs[0], func(s *pqPeerStat) {
					if s.Msg2Rejects >= pqIXPSK2DegradeThreshold {
						nowNanos := time.Now().UnixNano()
						// Count a fresh episode only on the transition into
						// a degrade window — a re-arm while a cooldown is
						// still active just extends it, it is not a new
						// downgrade event.
						wasActive := s.degradeUntilNanos > nowNanos
						s.degradeUntilNanos = nowNanos + int64(pqIXPSK2DegradeCooldown)
						if !wasActive {
							s.DegradeEpisodes++
							s.consecutiveDegrades++
							armedEpisode = true
							consec = s.consecutiveDegrades
							episodes = s.DegradeEpisodes
						}
					}
				})
				if armedEpisode {
					// Loud, observable record of a PQ->classical strip.
					// Passive HNDL is unaffected (it can't force this);
					// a climbing count is a persistent desync or an active
					// downgrade attacker — investigate, and consider
					// pq.mode=required on the link if it is the latter.
					pq.IncCounter(pq.MetricForcedDegrade)
					if consec >= pqDegradeWarnConsecutive {
						f.l.Warn("IXPSK2 repeatedly degraded to IXPSK0 for peer — heal is not working (dead rosenpass sidecar or active downgrade attacker)",
							"vpnAddrs", hostinfo.vpnAddrs, "from", via,
							"consecutiveDegrades", consec, "totalDegradeEpisodes", episodes)
					}
				}
			}
		}
		if err != nil {
			if machine.Failed() {
				f.l.Warn("Failed to process handshake packet, abandoning",
					"vpnAddrs", hostinfo.vpnAddrs, "from", via, "error", err)
				hm.DeleteHostInfo(hostinfo)
			} else {
				f.l.Debug("Failed to process handshake packet",
					"vpnAddrs", hostinfo.vpnAddrs, "from", via, "error", err)
			}
			return
		}
	}

	if response != nil {
		hm.sendHandshakeResponse(via, response, hostinfo, false)
	}

	if result == nil {
		return
	}

	// Handshake complete; build the ConnectionState now that we have keys and a verified peer cert.
	hostinfo.ConnectionState = newConnectionStateFromResult(result)

	remoteCert := result.RemoteCert
	if remoteCert == nil {
		f.l.Error("Handshake completed without peer certificate",
			"vpnAddrs", hostinfo.vpnAddrs, "from", via)
		hm.DeleteHostInfo(hostinfo)
		return
	}

	pqResultSubtype := pq.SubtypeNoPSK
	if result.Subtype == header.HandshakeIXPSK2 {
		pqResultSubtype = pq.SubtypePerPeer
	}

	if result.Subtype == header.HandshakeIXPSK2 && len(hostinfo.vpnAddrs) > 0 {
		hm.pqStatsLock.Lock()
		addr := hostinfo.vpnAddrs[0]
		if s, ok := hm.pqPeerStats[addr]; ok {
			if s.DegradeEpisodes > 0 {
				// This link was stripped before. Clear the transient
				// failure state and the consecutive run (a clean IXPSK2
				// means the heal worked / the strip ended), but PRESERVE
				// the cumulative DegradeEpisodes so the incident remains
				// visible in pq-status after recovery.
				s.Msg2Rejects = 0
				s.Timeouts = 0
				s.degradeUntilNanos = 0
				s.consecutiveDegrades = 0
			} else {
				// Never degraded — nothing worth retaining; drop the
				// entry so the stats map stays small.
				delete(hm.pqPeerStats, addr)
			}
		}
		hm.pqStatsLock.Unlock()
	}

	vpnNetworks := remoteCert.Certificate.Networks()
	hostinfo.remoteIndexId = result.RemoteIndex
	hostinfo.lastHandshakeTime = result.HandshakeTime

	if !via.IsRelayed {
		hostinfo.SetRemote(via.UdpAddr)
	} else {
		hostinfo.relayState.InsertRelayTo(via.relayHI.vpnAddrs[0])
	}

	// Verify correct host responded (initiator check)
	vpnAddrs := make([]netip.Addr, len(vpnNetworks))
	correctHostResponded := false
	anyVpnAddrsInCommon := false
	for i, network := range vpnNetworks {
		// inside.go drops self-routed packets at the firewall stage, but we'd
		// rather not let a self-handshake complete in the first place: it
		// wastes a hostmap slot, suppresses no log, and obscures routing
		// misconfig. Explicit refusal here mirrors the responder-side check
		// in validatePeerCert.
		if f.myVpnAddrsTable.Contains(network.Addr()) {
			f.l.Error("Refusing to handshake with myself",
				"vpnNetworks", vpnNetworks,
				"from", via,
				"certName", remoteCert.Certificate.Name(),
				"certVersion", remoteCert.Certificate.Version(),
				"fingerprint", remoteCert.Fingerprint,
				"issuer", remoteCert.Certificate.Issuer(),
				"handshake", m{"stage": uint64(machine.MessageIndex()), "style": header.SubTypeName(header.Handshake, machine.Subtype())},
			)
			hm.DeleteHostInfo(hostinfo)
			return
		}
		vpnAddrs[i] = network.Addr()
		if hostinfo.vpnAddrs[0] == network.Addr() {
			correctHostResponded = true
		}
		if f.myVpnNetworksTable.Contains(network.Addr()) {
			anyVpnAddrsInCommon = true
		}
	}

	// Record initiator-side handshake outcome with the policy. The
	// responder records its own outcome from beginHandshake; doing it
	// on both sides keeps the per-peer state symmetric. We pass the
	// full cert + vpn addrs so the Store can persist the identity for
	// future cold-boot lookups (boot-path per-group overrides).
	{
		pqPeer := pq.PeerInfo{
			StaticPubKey: remoteCert.Certificate.PublicKey(),
			Fingerprint:  remoteCert.Fingerprint,
			VpnAddrs:     vpnAddrsToStrings(vpnAddrs),
			Groups:       remoteCert.Certificate.Groups(),
		}
		if certBytes, err := remoteCert.Certificate.Marshal(); err == nil {
			pqPeer.CertBytes = certBytes
		}
		f.pki.PQPolicy().OnHandshakeComplete(pqPeer, pqResultSubtype)
		notifyPQProvider(f, remoteCert, vpnAddrs)
	}

	if !correctHostResponded {
		f.l.Info("Incorrect host responded to handshake",
			"intendedVpnAddrs", hostinfo.vpnAddrs,
			"haveVpnNetworks", vpnNetworks,
			"from", via,
			"certName", remoteCert.Certificate.Name(),
			"certVersion", remoteCert.Certificate.Version(),
			"fingerprint", remoteCert.Fingerprint,
			"issuer", remoteCert.Certificate.Issuer(),
			"handshake", m{"stage": uint64(machine.MessageIndex()), "style": header.SubTypeName(header.Handshake, machine.Subtype())},
		)

		hm.DeleteHostInfo(hostinfo)
		hm.StartHandshake(hostinfo.vpnAddrs[0], func(newHH *HandshakeHostInfo) {
			newHH.hostinfo.remotes = hostinfo.remotes
			newHH.hostinfo.remotes.BlockRemote(via)
			newHH.packetStore = hh.packetStore
			hh.packetStore = []*cachedPacket{}
			hostinfo.vpnAddrs = vpnAddrs
			f.sendCloseTunnel(hostinfo)
		})
		return
	}

	duration := time.Since(hh.startTime).Nanoseconds()
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
		"initiatorIndex", result.LocalIndex,
		"responderIndex", result.RemoteIndex,
		"handshake", m{"stage": uint64(machine.MessageIndex()), "style": header.SubTypeName(header.Handshake, machine.Subtype())},
		"durationNs", duration,
		"sentCachedPackets", len(hh.packetStore),
	)

	hostinfo.vpnAddrs = vpnAddrs
	hostinfo.buildNetworks(f.myVpnNetworksTable, remoteCert.Certificate)

	hm.Complete(hostinfo, f)

	if len(hh.packetStore) > 0 {
		if f.l.Enabled(context.Background(), slog.LevelDebug) {
			hostinfo.logger(f.l).Debug("Sending stored packets", "count", len(hh.packetStore))
		}
		nb := make([]byte, 12, 12)
		out := make([]byte, mtu)
		for _, cp := range hh.packetStore {
			cp.callback(cp.messageType, cp.messageSubType, hostinfo, cp.packet, nb, out)
		}
		f.cachedPacketMetrics.sent.Inc(int64(len(hh.packetStore)))
	}

	hostinfo.remotes.RefreshFromHandshake(vpnAddrs)
	f.metricHandshakes.Update(duration)

	// Don't wait for UpdateWorker
	if f.lightHouse.IsAnyLighthouseAddr(vpnAddrs) {
		f.lightHouse.TriggerUpdate()
	}
}

// validatePeerCert checks the peer certificate for self-connection and remote allow list.
// Returns the VPN addrs, whether any of them fall within one of our own VPN
// networks, and true if valid; false if rejected.
func (hm *HandshakeManager) validatePeerCert(via ViaSender, remoteCert *cert.CachedCertificate) ([]netip.Addr, bool, bool) {
	f := hm.f
	vpnNetworks := remoteCert.Certificate.Networks()

	// The cert package rejects host certs with no networks at parse time, so
	// reaching this state would mean an invariant was bypassed elsewhere.
	// Refuse explicitly so downstream code (which indexes vpnAddrs[0]) can't
	// panic if that invariant ever changes.
	if len(vpnNetworks) == 0 {
		f.l.Info("No networks in certificate",
			"from", via, "cert", remoteCert)
		return nil, false, false
	}

	vpnAddrs := make([]netip.Addr, len(vpnNetworks))
	anyVpnAddrsInCommon := false

	for i, network := range vpnNetworks {
		if f.myVpnAddrsTable.Contains(network.Addr()) {
			f.l.Error("Refusing to handshake with myself",
				"vpnNetworks", vpnNetworks,
				"from", via,
				"certName", remoteCert.Certificate.Name(),
				"certVersion", remoteCert.Certificate.Version(),
				"fingerprint", remoteCert.Fingerprint,
				"issuer", remoteCert.Certificate.Issuer(),
			)
			return nil, false, false
		}
		vpnAddrs[i] = network.Addr()
		if f.myVpnNetworksTable.Contains(network.Addr()) {
			anyVpnAddrsInCommon = true
		}
	}

	if !via.IsRelayed {
		if !f.lightHouse.GetRemoteAllowList().AllowAll(vpnAddrs, via.UdpAddr.Addr()) {
			f.l.Debug("lighthouse.remote_allow_list denied incoming handshake",
				"vpnAddrs", vpnAddrs, "from", via)
			return nil, false, false
		}
	}

	return vpnAddrs, anyVpnAddrsInCommon, true
}

// sendHandshakeResponse sends a handshake response via the appropriate transport.
// cached is true when msg is a stored response being retransmitted because
// the peer's stage-1 retransmit landed (the ErrAlreadySeen path); false on a
// fresh response.
func (hm *HandshakeManager) sendHandshakeResponse(via ViaSender, msg []byte, hostinfo *HostInfo, cached bool) {
	if msg == nil {
		return
	}

	f := hm.f
	f.messageMetrics.Tx(header.Handshake, header.MessageSubType(msg[1]), 1)

	// Common log fields. peerCert may be nil during intermediate
	// multi-message flows (handshake hasn't completed yet); skip the cert
	// block if so.
	logFields := []any{
		"vpnAddrs", hostinfo.vpnAddrs,
		"handshake", m{"stage": uint64(2), "style": header.SubTypeName(header.Handshake, header.MessageSubType(msg[1]))},
		"cached", cached,
		"initiatorIndex", hostinfo.remoteIndexId,
		"responderIndex", hostinfo.localIndexId,
	}
	if peerCert := hostinfo.ConnectionState.peerCert; peerCert != nil {
		logFields = append(logFields,
			"certName", peerCert.Certificate.Name(),
			"certVersion", peerCert.Certificate.Version(),
			"fingerprint", peerCert.Fingerprint,
			"issuer", peerCert.Certificate.Issuer(),
		)
	}

	if !via.IsRelayed {
		fields := append(logFields, "from", via)
		err := f.outside.WriteTo(msg, via.UdpAddr)
		if err != nil {
			f.l.Error("Failed to send handshake message", append(fields, "error", err)...)
		} else {
			f.l.Info("Handshake message sent", fields...)
		}
	} else {
		if via.relay == nil {
			f.l.Error("Handshake send failed: both addr and via.relay are nil.")
			return
		}
		hostinfo.relayState.InsertRelayTo(via.relayHI.vpnAddrs[0])
		// We received a valid handshake on this relay, so make sure the relay
		// state reflects that, in case it had been marked Disestablished.
		via.relayHI.relayState.UpdateRelayForByIdxState(via.remoteIdx, Established)
		f.SendVia(via.relayHI, via.relay, msg, make([]byte, 12), make([]byte, mtu), false)
		f.l.Info("Handshake message sent", append(logFields, "relay", via.relayHI.vpnAddrs[0])...)
	}
}

// handleCheckAndCompleteError handles errors from CheckAndComplete.
// This only fires from the responder-side beginHandshake path, after the
// peer cert has been validated and ConnectionState populated, so peerCert
// is always non-nil for the cases that log it.
func (hm *HandshakeManager) handleCheckAndCompleteError(err error, existing, hostinfo *HostInfo, via ViaSender) {
	f := hm.f
	peerCert := hostinfo.ConnectionState.peerCert
	hsFields := m{"stage": uint64(1), "style": header.SubTypeName(header.Handshake, hostinfo.ConnectionState.subtype)}

	switch err {
	case ErrAlreadySeen:
		if existing.SetRemoteIfPreferred(f.hostMap, via) {
			f.SendMessageToVpnAddr(header.Test, header.TestRequest, hostinfo.vpnAddrs[0], []byte(""), make([]byte, 12, 12), make([]byte, mtu))
		}
		// Resend the original response. The peer is committed to that response's
		// ephemeral keys; a freshly-built one would have different keys and break
		// the tunnel even though both sides "completed" the handshake.
		if msg := existing.HandshakePacket[handshakePacketStage2]; msg != nil {
			hm.sendHandshakeResponse(via, msg, existing, true)
		}

	case ErrExistingHostInfo:
		f.l.Info("Handshake too old",
			"vpnAddrs", hostinfo.vpnAddrs,
			"from", via,
			"certName", peerCert.Certificate.Name(),
			"certVersion", peerCert.Certificate.Version(),
			"fingerprint", peerCert.Fingerprint,
			"issuer", peerCert.Certificate.Issuer(),
			"oldHandshakeTime", existing.lastHandshakeTime,
			"newHandshakeTime", hostinfo.lastHandshakeTime,
			"initiatorIndex", hostinfo.remoteIndexId,
			"responderIndex", hostinfo.localIndexId,
			"handshake", hsFields,
		)
		f.SendMessageToVpnAddr(header.Test, header.TestRequest, hostinfo.vpnAddrs[0], []byte(""), make([]byte, 12, 12), make([]byte, mtu))

	case ErrLocalIndexCollision:
		f.l.Error("Failed to add HostInfo due to localIndex collision",
			"vpnAddrs", hostinfo.vpnAddrs,
			"from", via,
			"certName", peerCert.Certificate.Name(),
			"certVersion", peerCert.Certificate.Version(),
			"fingerprint", peerCert.Fingerprint,
			"issuer", peerCert.Certificate.Issuer(),
			"localIndex", hostinfo.localIndexId,
			"initiatorIndex", hostinfo.remoteIndexId,
			"responderIndex", hostinfo.localIndexId,
			"handshake", hsFields,
		)

	default:
		f.l.Error("Failed to add HostInfo to HostMap",
			"vpnAddrs", hostinfo.vpnAddrs,
			"from", via,
			"error", err,
			"certName", peerCert.Certificate.Name(),
			"certVersion", peerCert.Certificate.Version(),
			"fingerprint", peerCert.Fingerprint,
			"issuer", peerCert.Certificate.Issuer(),
			"initiatorIndex", hostinfo.remoteIndexId,
			"responderIndex", hostinfo.localIndexId,
			"handshake", hsFields,
		)
	}
}

// certVerifier returns a CertVerifier that validates certs against the current CA pool.
func (hm *HandshakeManager) certVerifier() handshake.CertVerifier {
	return func(c cert.Certificate) (*cert.CachedCertificate, error) {
		return hm.f.pki.GetCAPool().VerifyCertificate(time.Now(), c)
	}
}
