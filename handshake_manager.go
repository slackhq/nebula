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
	"sync"
	"time"

	"github.com/rcrowley/go-metrics"
	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/handshake"
	"github.com/slackhq/nebula/header"
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
	f                      *Interface
	l                      *slog.Logger

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
	packetStore               []*cachedPacket  // A set of packets to be transmitted once the handshake completes

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
	case header.HandshakeIXPSK0:
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
			"remoteIndex", hh.hostinfo.remoteIndexId,
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
			hostinfo.logger(hm.l).Error("Failed to send handshake message",
				"udpAddr", addr,
				"initiatorIndex", hostinfo.localIndexId,
				"handshake", hsFields,
				"error", err,
			)

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

	hm.f.relayManager.StartRelays(hm.f, vpnIp, hostinfo, stage0)

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
			"remoteIndex", hostinfo.remoteIndexId,
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
			"remoteIndex", hostinfo.remoteIndexId,
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

	machine, err := handshake.NewMachine(
		v, cs.GetCredential,
		hm.certVerifier(), func() (uint32, error) { return hm.allocateIndex(hh) },
		true, header.HandshakeIXPSK0,
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
		false, header.HandshakeIXPSK0,
	)
	if err != nil {
		f.l.Error("Failed to create handshake machine", "from", via, "error", err)
		return
	}

	response, result, err := machine.ProcessPacket(nil, packet)
	if err != nil {
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
	f.connectionManager.AddTrafficWatch(hostinfo)
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
		// Recoverable errors are routine noise, log at Debug. Fatal errors get a Warn.
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
	f.connectionManager.AddTrafficWatch(hostinfo)

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
		"handshake", m{"stage": uint64(2), "style": header.SubTypeName(header.Handshake, header.HandshakeIXPSK0)},
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
	hsFields := m{"stage": uint64(1), "style": header.SubTypeName(header.Handshake, header.HandshakeIXPSK0)}

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
