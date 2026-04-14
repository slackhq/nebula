package nebula

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/flynn/noise"
	"github.com/rcrowley/go-metrics"
	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/handshake"
	"github.com/slackhq/nebula/header"
	"github.com/slackhq/nebula/udp"
)

const (
	DefaultHandshakeTryInterval   = time.Millisecond * 100
	DefaultHandshakeRetries       = 10
	DefaultHandshakeTriggerBuffer = 64
	DefaultUseRelays              = true
)

var (
	defaultHandshakeConfig = HandshakeConfig{
		tryInterval:   DefaultHandshakeTryInterval,
		retries:       DefaultHandshakeRetries,
		triggerBuffer: DefaultHandshakeTriggerBuffer,
		useRelays:     DefaultUseRelays,
	}
)

type HandshakeConfig struct {
	tryInterval   time.Duration
	retries       int64
	triggerBuffer int
	useRelays     bool

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
	l                      *logrus.Logger

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
	machine  *handshake.Machine[*cert.CachedCertificate] // The handshake state machine, set during stage 0 (initiator) or beginHandshake (responder multi-message)
}

func (hh *HandshakeHostInfo) cachePacket(l *logrus.Logger, t header.MessageType, st header.MessageSubType, packet []byte, f packetCallback, m *cachedPacketMetrics) {
	if len(hh.packetStore) < 100 {
		tempPacket := make([]byte, len(packet))
		copy(tempPacket, packet)

		hh.packetStore = append(hh.packetStore, &cachedPacket{t, st, f, tempPacket})
		if l.Level >= logrus.DebugLevel {
			hh.hostinfo.logger(l).
				WithField("length", len(hh.packetStore)).
				WithField("stored", true).
				Debugf("Packet store")
		}

	} else {
		m.dropped.Inc(1)

		if l.Level >= logrus.DebugLevel {
			hh.hostinfo.logger(l).
				WithField("length", len(hh.packetStore)).
				WithField("stored", false).
				Debugf("Packet store")
		}
	}
}

func NewHandshakeManager(l *logrus.Logger, mainHostMap *HostMap, lightHouse *LightHouse, outside udp.Conn, config HandshakeConfig) *HandshakeManager {
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
	// First remote allow list check before we know the vpnIp
	if !via.IsRelayed {
		if !hm.lightHouse.GetRemoteAllowList().AllowUnknownVpnAddr(via.UdpAddr.Addr()) {
			hm.l.WithField("from", via).Debug("lighthouse.remote_allow_list denied incoming handshake")
			return
		}
	}

	// Case 1: Existing pending handshake, feed packet to the stored Machine
	if hh := hm.queryIndex(h.RemoteIndex); hh != nil {
		hm.continueHandshake(via, hh, packet, h)
		return
	}

	// Case 2: First message of a new handshake, start as responder.
	// Any other message counter without a matching pending index is an
	// orphaned packet (e.g., late retransmit after timeout) and is dropped.
	if h.MessageCounter == 1 {
		hm.beginHandshake(via, packet, h)
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
		hh.hostinfo.logger(hm.l).WithField("udpAddrs", hh.hostinfo.remotes.CopyAddrs(hm.mainHostMap.GetPreferredRanges())).
			WithField("initiatorIndex", hh.hostinfo.localIndexId).
			WithField("remoteIndex", hh.hostinfo.remoteIndexId).
			WithField("handshake", m{"stage": 1, "style": "ix_psk0"}).
			WithField("durationNs", time.Since(hh.startTime).Nanoseconds()).
			Info("Handshake timed out")
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
		hm.messageMetrics.Tx(header.Handshake, header.MessageSubType(hostinfo.HandshakePacket[0][1]), 1)
		err := hm.outside.WriteTo(hostinfo.HandshakePacket[0], addr)
		if err != nil {
			hostinfo.logger(hm.l).WithField("udpAddr", addr).
				WithField("initiatorIndex", hostinfo.localIndexId).
				WithField("handshake", m{"stage": 1, "style": "ix_psk0"}).
				WithError(err).Error("Failed to send handshake message")

		} else {
			sentTo = append(sentTo, addr)
		}
	})

	// Don't be too noisy or confusing if we fail to send a handshake - if we don't get through we'll eventually log a timeout,
	// so only log when the list of remotes has changed
	if remotesHaveChanged {
		hostinfo.logger(hm.l).WithField("udpAddrs", sentTo).
			WithField("initiatorIndex", hostinfo.localIndexId).
			WithField("handshake", m{"stage": 1, "style": "ix_psk0"}).
			Info("Handshake message sent")
	} else if hm.l.Level >= logrus.DebugLevel {
		hostinfo.logger(hm.l).WithField("udpAddrs", sentTo).
			WithField("initiatorIndex", hostinfo.localIndexId).
			WithField("handshake", m{"stage": 1, "style": "ix_psk0"}).
			Debug("Handshake message sent")
	}

	if hm.config.useRelays && len(hostinfo.remotes.relays) > 0 {
		hostinfo.logger(hm.l).WithField("relays", hostinfo.remotes.relays).Info("Attempt to relay through hosts")
		// Send a RelayRequest to all known Relay IP's
		for _, relay := range hostinfo.remotes.relays {
			// Don't relay through the host I'm trying to connect to
			if relay == vpnIp {
				continue
			}

			// Don't relay to myself
			if hm.f.myVpnAddrsTable.Contains(relay) {
				continue
			}

			relayHostInfo := hm.mainHostMap.QueryVpnAddr(relay)
			if relayHostInfo == nil || !relayHostInfo.remote.IsValid() {
				hostinfo.logger(hm.l).WithField("relay", relay.String()).Info("Establish tunnel to relay target")
				hm.f.Handshake(relay)
				continue
			}
			// Check the relay HostInfo to see if we already established a relay through
			existingRelay, ok := relayHostInfo.relayState.QueryRelayForByIp(vpnIp)
			if !ok {
				// No relays exist or requested yet.
				if relayHostInfo.remote.IsValid() {
					idx, err := AddRelay(hm.l, relayHostInfo, hm.mainHostMap, vpnIp, nil, TerminalType, Requested)
					if err != nil {
						hostinfo.logger(hm.l).WithField("relay", relay.String()).WithError(err).Info("Failed to add relay to hostmap")
					}

					m := NebulaControl{
						Type:                NebulaControl_CreateRelayRequest,
						InitiatorRelayIndex: idx,
					}

					switch relayHostInfo.GetCert().Certificate.Version() {
					case cert.Version1:
						if !hm.f.myVpnAddrs[0].Is4() {
							hostinfo.logger(hm.l).Error("can not establish v1 relay with a v6 network because the relay is not running a current nebula version")
							continue
						}

						if !vpnIp.Is4() {
							hostinfo.logger(hm.l).Error("can not establish v1 relay with a v6 remote network because the relay is not running a current nebula version")
							continue
						}

						b := hm.f.myVpnAddrs[0].As4()
						m.OldRelayFromAddr = binary.BigEndian.Uint32(b[:])
						b = vpnIp.As4()
						m.OldRelayToAddr = binary.BigEndian.Uint32(b[:])
					case cert.Version2:
						m.RelayFromAddr = netAddrToProtoAddr(hm.f.myVpnAddrs[0])
						m.RelayToAddr = netAddrToProtoAddr(vpnIp)
					default:
						hostinfo.logger(hm.l).Error("Unknown certificate version found while creating relay")
						continue
					}

					msg, err := m.Marshal()
					if err != nil {
						hostinfo.logger(hm.l).
							WithError(err).
							Error("Failed to marshal Control message to create relay")
					} else {
						hm.f.SendMessageToHostInfo(header.Control, 0, relayHostInfo, msg, make([]byte, 12), make([]byte, mtu))
						hm.l.WithFields(logrus.Fields{
							"relayFrom":           hm.f.myVpnAddrs[0],
							"relayTo":             vpnIp,
							"initiatorRelayIndex": idx,
							"relay":               relay}).
							Info("send CreateRelayRequest")
					}
				}
				continue
			}

			switch existingRelay.State {
			case Established:
				hostinfo.logger(hm.l).WithField("relay", relay.String()).Info("Send handshake via relay")
				hm.f.SendVia(relayHostInfo, existingRelay, hostinfo.HandshakePacket[0], make([]byte, 12), make([]byte, mtu), false)
			case Disestablished:
				// Mark this relay as 'requested'
				relayHostInfo.relayState.UpdateRelayForByIpState(vpnIp, Requested)
				fallthrough
			case Requested:
				hostinfo.logger(hm.l).WithField("relay", relay.String()).Info("Re-send CreateRelay request")
				// Re-send the CreateRelay request, in case the previous one was lost.
				m := NebulaControl{
					Type:                NebulaControl_CreateRelayRequest,
					InitiatorRelayIndex: existingRelay.LocalIndex,
				}

				switch relayHostInfo.GetCert().Certificate.Version() {
				case cert.Version1:
					if !hm.f.myVpnAddrs[0].Is4() {
						hostinfo.logger(hm.l).Error("can not establish v1 relay with a v6 network because the relay is not running a current nebula version")
						continue
					}

					if !vpnIp.Is4() {
						hostinfo.logger(hm.l).Error("can not establish v1 relay with a v6 remote network because the relay is not running a current nebula version")
						continue
					}

					b := hm.f.myVpnAddrs[0].As4()
					m.OldRelayFromAddr = binary.BigEndian.Uint32(b[:])
					b = vpnIp.As4()
					m.OldRelayToAddr = binary.BigEndian.Uint32(b[:])
				case cert.Version2:
					m.RelayFromAddr = netAddrToProtoAddr(hm.f.myVpnAddrs[0])
					m.RelayToAddr = netAddrToProtoAddr(vpnIp)
				default:
					hostinfo.logger(hm.l).Error("Unknown certificate version found while creating relay")
					continue
				}
				msg, err := m.Marshal()
				if err != nil {
					hostinfo.logger(hm.l).
						WithError(err).
						Error("Failed to marshal Control message to create relay")
				} else {
					// This must send over the hostinfo, not over hm.Hosts[ip]
					hm.f.SendMessageToHostInfo(header.Control, 0, relayHostInfo, msg, make([]byte, 12), make([]byte, mtu))
					hm.l.WithFields(logrus.Fields{
						"relayFrom":           hm.f.myVpnAddrs[0],
						"relayTo":             vpnIp,
						"initiatorRelayIndex": existingRelay.LocalIndex,
						"relay":               relay}).
						Info("send CreateRelayRequest")
				}
			case PeerRequested:
				// PeerRequested only occurs in Forwarding relays, not Terminal relays, and this is a Terminal relay case.
				fallthrough
			default:
				hostinfo.logger(hm.l).
					WithField("vpnIp", vpnIp).
					WithField("state", existingRelay.State).
					WithField("relay", relay).
					Errorf("Relay unexpected state")

			}
		}
	}

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
		hostinfo.logger(hm.l).
			WithField("remoteIndex", hostinfo.remoteIndexId).WithField("collision", existingRemoteIndex.vpnAddrs).
			Info("New host shadows existing host remoteIndex")
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
		hostinfo.logger(hm.l).
			WithField("remoteIndex", hostinfo.remoteIndexId).WithField("collision", existingRemoteIndex.vpnAddrs).
			Info("New host shadows existing host remoteIndex")
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

	if hm.l.Level >= logrus.DebugLevel {
		hm.l.WithField("hostMap", m{"mapTotalSize": len(hm.vpnIps),
			"vpnAddrs": hostinfo.vpnAddrs, "indexNumber": hostinfo.localIndexId, "remoteIndexNumber": hostinfo.remoteIndexId}).
			Debug("Pending hostmap hostInfo deleted")
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

func generateIndex(l *logrus.Logger) (uint32, error) {
	b := make([]byte, 4)

	// Let zero mean we don't know the ID, so don't generate zero
	var index uint32
	for index == 0 {
		_, err := rand.Read(b)
		if err != nil {
			l.Errorln(err)
			return 0, err
		}

		index = binary.BigEndian.Uint32(b)
	}

	if l.Level >= logrus.DebugLevel {
		l.WithField("index", index).
			Debug("Generated index")
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

	cred := cs.GetHandshakeCredential(v)
	if cred == nil {
		hm.f.l.WithField("vpnAddrs", hh.hostinfo.vpnAddrs).WithField("certVersion", v).
			Error("Unable to handshake with host because no certificate is available")
		return false
	}

	hs, err := cred.NewHandshakeState(true, noise.HandshakeIX)
	if err != nil {
		hm.f.l.WithError(err).WithField("vpnAddrs", hh.hostinfo.vpnAddrs).
			Error("Failed to create noise handshake state")
		return false
	}

	machine, err := handshake.NewMachine(
		hs, v, cs.GetHandshakeCredential,
		hm.certVerifier(), func() (uint32, error) { return hm.allocateIndex(hh) },
		true, header.HandshakeIXPSK0,
	)
	if err != nil {
		hm.f.l.WithError(err).WithField("vpnAddrs", hh.hostinfo.vpnAddrs).
			Error("Failed to create handshake machine")
		return false
	}

	msg, err := machine.Initiate(nil)
	if err != nil {
		hm.f.l.WithError(err).WithField("vpnAddrs", hh.hostinfo.vpnAddrs).
			Error("Failed to initiate handshake")
		return false
	}

	ci := &ConnectionState{
		myCert:    cred.Cert,
		initiator: true,
		window:    NewBits(ReplayWindow),
	}

	hh.hostinfo.ConnectionState = ci
	hh.hostinfo.HandshakePacket[0] = msg
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
	cred := cs.GetHandshakeCredential(v)
	if cred == nil {
		f.l.WithField("from", via).WithField("certVersion", v).
			Error("Unable to handshake with host because no certificate is available")
		return
	}

	hs, err := cred.NewHandshakeState(false, noise.HandshakeIX)
	if err != nil {
		f.l.WithError(err).WithField("from", via).Error("Failed to create noise handshake state")
		return
	}

	machine, err := handshake.NewMachine(
		hs, v, cs.GetHandshakeCredential,
		hm.certVerifier(), func() (uint32, error) { return generateIndex(f.l) },
		false, header.HandshakeIXPSK0,
	)
	if err != nil {
		f.l.WithError(err).WithField("from", via).Error("Failed to create handshake machine")
		return
	}

	response, result, err := machine.ProcessPacket(nil, packet)
	if err != nil {
		f.l.WithError(err).WithField("from", via).Error("Failed to process handshake packet")
		return
	}

	if result == nil {
		// Multi-message pattern: not yet complete.
		//TODO: register in hm.indexes so continueHandshake can find us
		hm.sendHandshakeResponse(via, response, nil)
		return
	}

	remoteCert := result.RemoteCert
	if remoteCert == nil {
		f.l.WithField("from", via).Error("Handshake did not produce a peer certificate")
		return
	}

	// Validate peer identity
	vpnAddrs, ok := hm.validatePeerCert(via, remoteCert)
	if !ok {
		return
	}

	hostinfo := &HostInfo{
		ConnectionState:   buildConnectionState(result, nonceEndiannessForCipher(cs.cipher)),
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

	f.l.WithField("vpnAddrs", vpnAddrs).WithField("from", via).
		WithField("certName", remoteCert.Certificate.Name()).
		WithField("initiatorIndex", result.RemoteIndex).
		WithField("responderIndex", result.LocalIndex).
		Info("Handshake message received")

	hostinfo.HandshakePacket[0] = make([]byte, len(packet[header.Len:]))
	copy(hostinfo.HandshakePacket[0], packet[header.Len:])

	if response != nil {
		hostinfo.HandshakePacket[2] = make([]byte, len(response))
		copy(hostinfo.HandshakePacket[2], response)
	}

	hostinfo.remotes = f.lightHouse.QueryCache(vpnAddrs)
	if !via.IsRelayed {
		hostinfo.SetRemote(via.UdpAddr)
	}
	hostinfo.buildNetworks(f.myVpnNetworksTable, remoteCert.Certificate)

	existing, err := hm.CheckAndComplete(hostinfo, 0, f)
	if err != nil {
		hm.handleCheckAndCompleteError(err, existing, hostinfo, via, response, h)
		return
	}

	hm.sendHandshakeResponse(via, response, hostinfo)
	f.connectionManager.AddTrafficWatch(hostinfo)
	hostinfo.remotes.RefreshFromHandshake(vpnAddrs)

	// Don't wait for UpdateWorker
	if f.lightHouse.IsAnyLighthouseAddr(vpnAddrs) {
		f.lightHouse.TriggerUpdate()
	}
}

// continueHandshake feeds an incoming packet to an existing pending handshake Machine.
func (hm *HandshakeManager) continueHandshake(via ViaSender, hh *HandshakeHostInfo, packet []byte, h *header.H) {
	f := hm.f

	hh.Lock()
	defer hh.Unlock()

	hostinfo := hh.hostinfo
	if !via.IsRelayed {
		if !f.lightHouse.GetRemoteAllowList().AllowAll(hostinfo.vpnAddrs, via.UdpAddr.Addr()) {
			f.l.WithField("vpnAddrs", hostinfo.vpnAddrs).WithField("from", via).
				Debug("lighthouse.remote_allow_list denied incoming handshake")
			return
		}
	}

	machine := hh.machine
	if machine == nil {
		f.l.WithField("vpnAddrs", hostinfo.vpnAddrs).WithField("from", via).
			Error("No handshake machine available for continuation")
		hm.DeleteHostInfo(hostinfo)
		return
	}

	response, result, err := machine.ProcessPacket(nil, packet)
	if err != nil {
		f.l.WithError(err).WithField("vpnAddrs", hostinfo.vpnAddrs).WithField("from", via).
			Error("Failed to process handshake packet")
		if machine.Failed() {
			hm.DeleteHostInfo(hostinfo)
		}
		return
	}

	if response != nil {
		hm.sendHandshakeResponse(via, response, hostinfo)
	}

	if result == nil {
		return
	}

	// Handshake complete, set keys on the ConnectionState
	ci := hostinfo.ConnectionState
	ci.peerCert = result.RemoteCert
	ne := nonceEndiannessForCipher(f.pki.getCertState().cipher)
	ci.eKey = NewNebulaCipherState(result.EKey, ne)
	ci.dKey = NewNebulaCipherState(result.DKey, ne)
	ci.messageCounter.Add(result.MessageIndex)
	for i := uint64(1); i <= result.MessageIndex; i++ {
		ci.window.Update(nil, i)
	}
	// Note: ci.myCert is not updated here. It was set when the ConnectionState
	// was created (buildStage0Packet) and reflects the cert version we actually
	// used in the handshake. The Machine's version negotiation may have noted
	// a better version for next time, but this handshake already used the original.

	remoteCert := result.RemoteCert
	if remoteCert == nil {
		f.l.WithField("vpnAddrs", hostinfo.vpnAddrs).WithField("from", via).
			Error("Handshake completed without peer certificate")
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
	for i, network := range vpnNetworks {
		vpnAddrs[i] = network.Addr()
		if hostinfo.vpnAddrs[0] == network.Addr() {
			correctHostResponded = true
		}
	}

	if !correctHostResponded {
		f.l.WithField("intendedVpnAddrs", hostinfo.vpnAddrs).WithField("haveVpnNetworks", vpnNetworks).
			WithField("from", via).Info("Incorrect host responded to handshake")

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
	f.l.WithField("vpnAddrs", vpnAddrs).WithField("from", via).
		WithField("certName", remoteCert.Certificate.Name()).
		WithField("durationNs", duration).
		WithField("sentCachedPackets", len(hh.packetStore)).
		Info("Handshake message received")

	hostinfo.vpnAddrs = vpnAddrs
	hostinfo.buildNetworks(f.myVpnNetworksTable, remoteCert.Certificate)

	hm.Complete(hostinfo, f)
	f.connectionManager.AddTrafficWatch(hostinfo)

	if len(hh.packetStore) > 0 {
		if f.l.Level >= logrus.DebugLevel {
			hostinfo.logger(f.l).Debugf("Sending %d stored packets", len(hh.packetStore))
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
// Returns the VPN addrs and true if valid, false if rejected.
func (hm *HandshakeManager) validatePeerCert(via ViaSender, remoteCert *cert.CachedCertificate) ([]netip.Addr, bool) {
	f := hm.f
	vpnNetworks := remoteCert.Certificate.Networks()
	vpnAddrs := make([]netip.Addr, len(vpnNetworks))

	for i, network := range vpnNetworks {
		if f.myVpnAddrsTable.Contains(network.Addr()) {
			f.l.WithField("vpnNetworks", vpnNetworks).WithField("from", via).
				Error("Refusing to handshake with myself")
			return nil, false
		}
		vpnAddrs[i] = network.Addr()
	}

	if !via.IsRelayed {
		if !f.lightHouse.GetRemoteAllowList().AllowAll(vpnAddrs, via.UdpAddr.Addr()) {
			f.l.WithField("vpnAddrs", vpnAddrs).WithField("from", via).
				Debug("lighthouse.remote_allow_list denied incoming handshake")
			return nil, false
		}
	}

	return vpnAddrs, true
}

// sendHandshakeResponse sends a handshake response via the appropriate transport.
func (hm *HandshakeManager) sendHandshakeResponse(via ViaSender, msg []byte, hostinfo *HostInfo) {
	if msg == nil {
		return
	}

	f := hm.f
	f.messageMetrics.Tx(header.Handshake, header.MessageSubType(msg[1]), 1)

	if !via.IsRelayed {
		err := f.outside.WriteTo(msg, via.UdpAddr)
		if err != nil {
			f.l.WithField("vpnAddrs", hostinfo.vpnAddrs).WithField("from", via).
				WithError(err).Error("Failed to send handshake message")
		} else {
			f.l.WithField("vpnAddrs", hostinfo.vpnAddrs).WithField("from", via).
				Info("Handshake message sent")
		}
	} else {
		if via.relay == nil {
			f.l.Error("Handshake send failed: both addr and via.relay are nil.")
			return
		}
		hostinfo.relayState.InsertRelayTo(via.relayHI.vpnAddrs[0])
		via.relayHI.relayState.UpdateRelayForByIdxState(via.remoteIdx, Established)
		f.SendVia(via.relayHI, via.relay, msg, make([]byte, 12), make([]byte, mtu), false)
		f.l.WithField("vpnAddrs", hostinfo.vpnAddrs).WithField("relay", via.relayHI.vpnAddrs[0]).
			Info("Handshake message sent")
	}
}

// handleCheckAndCompleteError handles errors from CheckAndComplete.
func (hm *HandshakeManager) handleCheckAndCompleteError(err error, existing, hostinfo *HostInfo, via ViaSender, cachedResponse []byte, h *header.H) {
	f := hm.f

	switch err {
	case ErrAlreadySeen:
		if existing.SetRemoteIfPreferred(f.hostMap, via) {
			f.SendMessageToVpnAddr(header.Test, header.TestRequest, hostinfo.vpnAddrs[0], []byte(""), make([]byte, 12, 12), make([]byte, mtu))
		}
		// Resend cached response
		if msg := existing.HandshakePacket[2]; msg != nil {
			hm.sendHandshakeResponse(via, msg, existing)
		}

	case ErrExistingHostInfo:
		f.l.WithField("vpnAddrs", hostinfo.vpnAddrs).WithField("from", via).
			WithField("oldHandshakeTime", existing.lastHandshakeTime).
			WithField("newHandshakeTime", hostinfo.lastHandshakeTime).
			Info("Handshake too old")
		f.SendMessageToVpnAddr(header.Test, header.TestRequest, hostinfo.vpnAddrs[0], []byte(""), make([]byte, 12, 12), make([]byte, mtu))

	case ErrLocalIndexCollision:
		f.l.WithField("vpnAddrs", hostinfo.vpnAddrs).WithField("from", via).
			WithField("localIndex", hostinfo.localIndexId).
			Error("Failed to add HostInfo due to localIndex collision")

	default:
		f.l.WithError(err).WithField("vpnAddrs", hostinfo.vpnAddrs).WithField("from", via).
			Error("Failed to add HostInfo to HostMap")
	}
}

// buildConnectionState constructs a ConnectionState from a completed handshake.
func buildConnectionState(r *handshake.CompletedHandshake[*cert.CachedCertificate], nonceEndianness endianness) *ConnectionState {
	ci := &ConnectionState{
		myCert:    r.MyCert,
		peerCert:  r.RemoteCert,
		eKey:      NewNebulaCipherState(r.EKey, nonceEndianness),
		dKey:      NewNebulaCipherState(r.DKey, nonceEndianness),
		initiator: r.Initiator,
		window:    NewBits(ReplayWindow),
	}
	ci.messageCounter.Add(r.MessageIndex)

	// Mark handshake message counters as seen so they don't count as lost
	for i := uint64(1); i <= r.MessageIndex; i++ {
		ci.window.Update(nil, i)
	}

	return ci
}

// certVerifier returns a CertVerifier that validates certs against the current CA pool.
func (hm *HandshakeManager) certVerifier() handshake.CertVerifier[*cert.CachedCertificate] {
	return func(c cert.Certificate) (*cert.CachedCertificate, error) {
		return hm.f.pki.GetCAPool().VerifyCertificate(time.Now(), c)
	}
}
