package nebula

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/rcrowley/go-metrics"
	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/header"
	"github.com/slackhq/nebula/iputil"
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
	retries       int
	triggerBuffer int
	useRelays     bool

	messageMetrics *MessageMetrics
}

type HandshakeManager struct {
	// Mutex for interacting with the vpnIps and indexes maps
	sync.RWMutex

	vpnIps  map[iputil.VpnIp]*HostInfo
	indexes map[uint32]*HostInfo

	mainHostMap            *HostMap
	lightHouse             *LightHouse
	outside                udp.Conn
	config                 HandshakeConfig
	OutboundHandshakeTimer *LockingTimerWheel[iputil.VpnIp]
	messageMetrics         *MessageMetrics
	metricInitiated        metrics.Counter
	metricTimedOut         metrics.Counter
	f                      *Interface
	l                      *logrus.Logger

	// can be used to trigger outbound handshake for the given vpnIp
	trigger chan iputil.VpnIp
}

func NewHandshakeManager(l *logrus.Logger, mainHostMap *HostMap, lightHouse *LightHouse, outside udp.Conn, config HandshakeConfig) *HandshakeManager {
	return &HandshakeManager{
		vpnIps:                 map[iputil.VpnIp]*HostInfo{},
		indexes:                map[uint32]*HostInfo{},
		mainHostMap:            mainHostMap,
		lightHouse:             lightHouse,
		outside:                outside,
		config:                 config,
		trigger:                make(chan iputil.VpnIp, config.triggerBuffer),
		OutboundHandshakeTimer: NewLockingTimerWheel[iputil.VpnIp](config.tryInterval, hsTimeout(config.retries, config.tryInterval)),
		messageMetrics:         config.messageMetrics,
		metricInitiated:        metrics.GetOrRegisterCounter("handshake_manager.initiated", nil),
		metricTimedOut:         metrics.GetOrRegisterCounter("handshake_manager.timed_out", nil),
		l:                      l,
	}
}

func (c *HandshakeManager) Run(ctx context.Context) {
	clockSource := time.NewTicker(c.config.tryInterval)
	defer clockSource.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case vpnIP := <-c.trigger:
			c.handleOutbound(vpnIP, true)
		case now := <-clockSource.C:
			c.NextOutboundHandshakeTimerTick(now)
		}
	}
}

func (c *HandshakeManager) NextOutboundHandshakeTimerTick(now time.Time) {
	c.OutboundHandshakeTimer.Advance(now)
	for {
		vpnIp, has := c.OutboundHandshakeTimer.Purge()
		if !has {
			break
		}
		c.handleOutbound(vpnIp, false)
	}
}

func (c *HandshakeManager) handleOutbound(vpnIp iputil.VpnIp, lighthouseTriggered bool) {
	hostinfo := c.QueryVpnIp(vpnIp)
	if hostinfo == nil {
		return
	}
	hostinfo.Lock()
	defer hostinfo.Unlock()

	// We may have raced to completion but now that we have a lock we should ensure we have not yet completed.
	if hostinfo.HandshakeComplete {
		// Ensure we don't exist in the pending hostmap anymore since we have completed
		c.DeleteHostInfo(hostinfo)
		return
	}

	// If we are out of time, clean up
	if hostinfo.HandshakeCounter >= c.config.retries {
		hostinfo.logger(c.l).WithField("udpAddrs", hostinfo.remotes.CopyAddrs(c.mainHostMap.preferredRanges)).
			WithField("initiatorIndex", hostinfo.localIndexId).
			WithField("remoteIndex", hostinfo.remoteIndexId).
			WithField("handshake", m{"stage": 1, "style": "ix_psk0"}).
			WithField("durationNs", time.Since(hostinfo.handshakeStart).Nanoseconds()).
			Info("Handshake timed out")
		c.metricTimedOut.Inc(1)
		c.DeleteHostInfo(hostinfo)
		return
	}

	// Increment the counter to increase our delay, linear backoff
	hostinfo.HandshakeCounter++

	// Check if we have a handshake packet to transmit yet
	if !hostinfo.HandshakeReady {
		if !ixHandshakeStage0(c.f, hostinfo) {
			c.OutboundHandshakeTimer.Add(vpnIp, c.config.tryInterval*time.Duration(hostinfo.HandshakeCounter))
			return
		}
	}

	// Get a remotes object if we don't already have one.
	// This is mainly to protect us as this should never be the case
	// NB ^ This comment doesn't jive. It's how the thing gets initialized.
	// It's the common path. Should it update every time, in case a future LH query/queries give us more info?
	if hostinfo.remotes == nil {
		hostinfo.remotes = c.lightHouse.QueryCache(vpnIp)
	}

	remotes := hostinfo.remotes.CopyAddrs(c.mainHostMap.preferredRanges)
	remotesHaveChanged := !udp.AddrSlice(remotes).Equal(hostinfo.HandshakeLastRemotes)

	// We only care about a lighthouse trigger if we have new remotes to send to.
	// This is a very specific optimization for a fast lighthouse reply.
	if lighthouseTriggered && !remotesHaveChanged {
		// If we didn't return here a lighthouse could cause us to aggressively send handshakes
		return
	}

	hostinfo.HandshakeLastRemotes = remotes

	// TODO: this will generate a load of queries for hosts with only 1 ip
	// (such as ones registered to the lighthouse with only a private IP)
	// So we only do it one time after attempting 5 handshakes already.
	if len(remotes) <= 1 && hostinfo.HandshakeCounter == 5 {
		// If we only have 1 remote it is highly likely our query raced with the other host registered within the lighthouse
		// Our vpnIp here has a tunnel with a lighthouse but has yet to send a host update packet there so we only know about
		// the learned public ip for them. Query again to short circuit the promotion counter
		c.lightHouse.QueryServer(vpnIp, c.f)
	}

	// Send the handshake to all known ips, stage 2 takes care of assigning the hostinfo.remote based on the first to reply
	var sentTo []*udp.Addr
	hostinfo.remotes.ForEach(c.mainHostMap.preferredRanges, func(addr *udp.Addr, _ bool) {
		c.messageMetrics.Tx(header.Handshake, header.MessageSubType(hostinfo.HandshakePacket[0][1]), 1)
		err := c.outside.WriteTo(hostinfo.HandshakePacket[0], addr)
		if err != nil {
			hostinfo.logger(c.l).WithField("udpAddr", addr).
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
		hostinfo.logger(c.l).WithField("udpAddrs", sentTo).
			WithField("initiatorIndex", hostinfo.localIndexId).
			WithField("handshake", m{"stage": 1, "style": "ix_psk0"}).
			Info("Handshake message sent")
	} else if c.l.IsLevelEnabled(logrus.DebugLevel) {
		hostinfo.logger(c.l).WithField("udpAddrs", sentTo).
			WithField("initiatorIndex", hostinfo.localIndexId).
			WithField("handshake", m{"stage": 1, "style": "ix_psk0"}).
			Debug("Handshake message sent")
	}

	if c.config.useRelays && len(hostinfo.remotes.relays) > 0 {
		hostinfo.logger(c.l).WithField("relays", hostinfo.remotes.relays).Info("Attempt to relay through hosts")
		// Send a RelayRequest to all known Relay IP's
		for _, relay := range hostinfo.remotes.relays {
			// Don't relay to myself, and don't relay through the host I'm trying to connect to
			if *relay == vpnIp || *relay == c.lightHouse.myVpnIp {
				continue
			}
			relayHostInfo := c.mainHostMap.QueryVpnIp(*relay)
			if relayHostInfo == nil || relayHostInfo.remote == nil {
				hostinfo.logger(c.l).WithField("relay", relay.String()).Info("Establish tunnel to relay target")
				c.f.Handshake(*relay)
				continue
			}
			// Check the relay HostInfo to see if we already established a relay through it
			if existingRelay, ok := relayHostInfo.relayState.QueryRelayForByIp(vpnIp); ok {
				switch existingRelay.State {
				case Established:
					hostinfo.logger(c.l).WithField("relay", relay.String()).Info("Send handshake via relay")
					c.f.SendVia(relayHostInfo, existingRelay, hostinfo.HandshakePacket[0], make([]byte, 12), make([]byte, mtu), false)
				case Requested:
					hostinfo.logger(c.l).WithField("relay", relay.String()).Info("Re-send CreateRelay request")
					// Re-send the CreateRelay request, in case the previous one was lost.
					m := NebulaControl{
						Type:                NebulaControl_CreateRelayRequest,
						InitiatorRelayIndex: existingRelay.LocalIndex,
						RelayFromIp:         uint32(c.lightHouse.myVpnIp),
						RelayToIp:           uint32(vpnIp),
					}
					msg, err := m.Marshal()
					if err != nil {
						hostinfo.logger(c.l).
							WithError(err).
							Error("Failed to marshal Control message to create relay")
					} else {
						// This must send over the hostinfo, not over hm.Hosts[ip]
						c.f.SendMessageToHostInfo(header.Control, 0, relayHostInfo, msg, make([]byte, 12), make([]byte, mtu))
						c.l.WithFields(logrus.Fields{
							"relayFrom":           c.lightHouse.myVpnIp,
							"relayTo":             vpnIp,
							"initiatorRelayIndex": existingRelay.LocalIndex,
							"relay":               *relay}).
							Info("send CreateRelayRequest")
					}
				default:
					hostinfo.logger(c.l).
						WithField("vpnIp", vpnIp).
						WithField("state", existingRelay.State).
						WithField("relay", relayHostInfo.vpnIp).
						Errorf("Relay unexpected state")
				}
			} else {
				// No relays exist or requested yet.
				if relayHostInfo.remote != nil {
					idx, err := AddRelay(c.l, relayHostInfo, c.mainHostMap, vpnIp, nil, TerminalType, Requested)
					if err != nil {
						hostinfo.logger(c.l).WithField("relay", relay.String()).WithError(err).Info("Failed to add relay to hostmap")
					}

					m := NebulaControl{
						Type:                NebulaControl_CreateRelayRequest,
						InitiatorRelayIndex: idx,
						RelayFromIp:         uint32(c.lightHouse.myVpnIp),
						RelayToIp:           uint32(vpnIp),
					}
					msg, err := m.Marshal()
					if err != nil {
						hostinfo.logger(c.l).
							WithError(err).
							Error("Failed to marshal Control message to create relay")
					} else {
						c.f.SendMessageToHostInfo(header.Control, 0, relayHostInfo, msg, make([]byte, 12), make([]byte, mtu))
						c.l.WithFields(logrus.Fields{
							"relayFrom":           c.lightHouse.myVpnIp,
							"relayTo":             vpnIp,
							"initiatorRelayIndex": idx,
							"relay":               *relay}).
							Info("send CreateRelayRequest")
					}
				}
			}
		}
	}

	// If a lighthouse triggered this attempt then we are still in the timer wheel and do not need to re-add
	if !lighthouseTriggered {
		c.OutboundHandshakeTimer.Add(vpnIp, c.config.tryInterval*time.Duration(hostinfo.HandshakeCounter))
	}
}

// GetOrHandshake will try to find a hostinfo with a fully formed tunnel or start a new handshake if one is not present
// The 2nd argument will be true if the hostinfo is ready to transmit traffic
func (hm *HandshakeManager) GetOrHandshake(vpnIp iputil.VpnIp, cacheCb func(*HostInfo)) (*HostInfo, bool) {
	// Check the main hostmap and maintain a read lock if our host is not there
	hm.mainHostMap.RLock()
	if h, ok := hm.mainHostMap.Hosts[vpnIp]; ok {
		hm.mainHostMap.RUnlock()
		// Do not attempt promotion if you are a lighthouse
		if !hm.lightHouse.amLighthouse {
			h.TryPromoteBest(hm.mainHostMap.preferredRanges, hm.f)
		}
		return h, true
	}

	defer hm.mainHostMap.RUnlock()
	return hm.StartHandshake(vpnIp, cacheCb), false
}

// StartHandshake will ensure a handshake is currently being attempted for the provided vpn ip
func (hm *HandshakeManager) StartHandshake(vpnIp iputil.VpnIp, cacheCb func(*HostInfo)) *HostInfo {
	hm.Lock()
	defer hm.Unlock()

	if hostinfo, ok := hm.vpnIps[vpnIp]; ok {
		// We are already trying to handshake with this vpn ip
		if cacheCb != nil {
			cacheCb(hostinfo)
		}
		return hostinfo
	}

	hostinfo := &HostInfo{
		vpnIp:           vpnIp,
		HandshakePacket: make(map[uint8][]byte, 0),
		relayState: RelayState{
			relays:        map[iputil.VpnIp]struct{}{},
			relayForByIp:  map[iputil.VpnIp]*Relay{},
			relayForByIdx: map[uint32]*Relay{},
		},
	}

	hm.vpnIps[vpnIp] = hostinfo
	hm.metricInitiated.Inc(1)
	hm.OutboundHandshakeTimer.Add(vpnIp, hm.config.tryInterval)

	if cacheCb != nil {
		cacheCb(hostinfo)
	}

	// If this is a static host, we don't need to wait for the HostQueryReply
	// We can trigger the handshake right now
	_, doTrigger := hm.lightHouse.GetStaticHostList()[vpnIp]
	if !doTrigger {
		// Add any calculated remotes, and trigger early handshake if one found
		doTrigger = hm.lightHouse.addCalculatedRemotes(vpnIp)
	}

	if doTrigger {
		select {
		case hm.trigger <- vpnIp:
		default:
		}
	}

	hm.lightHouse.QueryServer(vpnIp, hm.f)
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
func (c *HandshakeManager) CheckAndComplete(hostinfo *HostInfo, handshakePacket uint8, f *Interface) (*HostInfo, error) {
	c.mainHostMap.Lock()
	defer c.mainHostMap.Unlock()
	c.Lock()
	defer c.Unlock()

	// Check if we already have a tunnel with this vpn ip
	existingHostInfo, found := c.mainHostMap.Hosts[hostinfo.vpnIp]
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

		existingHostInfo.logger(c.l).Info("Taking new handshake")
	}

	existingIndex, found := c.mainHostMap.Indexes[hostinfo.localIndexId]
	if found {
		// We have a collision, but for a different hostinfo
		return existingIndex, ErrLocalIndexCollision
	}

	existingIndex, found = c.indexes[hostinfo.localIndexId]
	if found && existingIndex != hostinfo {
		// We have a collision, but for a different hostinfo
		return existingIndex, ErrLocalIndexCollision
	}

	existingRemoteIndex, found := c.mainHostMap.RemoteIndexes[hostinfo.remoteIndexId]
	if found && existingRemoteIndex != nil && existingRemoteIndex.vpnIp != hostinfo.vpnIp {
		// We have a collision, but this can happen since we can't control
		// the remote ID. Just log about the situation as a note.
		hostinfo.logger(c.l).
			WithField("remoteIndex", hostinfo.remoteIndexId).WithField("collision", existingRemoteIndex.vpnIp).
			Info("New host shadows existing host remoteIndex")
	}

	c.mainHostMap.unlockedAddHostInfo(hostinfo, f)
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
			WithField("remoteIndex", hostinfo.remoteIndexId).WithField("collision", existingRemoteIndex.vpnIp).
			Info("New host shadows existing host remoteIndex")
	}

	// We need to remove from the pending hostmap first to avoid undoing work when after to the main hostmap.
	hm.unlockedDeleteHostInfo(hostinfo)
	hm.mainHostMap.unlockedAddHostInfo(hostinfo, f)
}

// allocateIndex generates a unique localIndexId for this HostInfo
// and adds it to the pendingHostMap. Will error if we are unable to generate
// a unique localIndexId
func (hm *HandshakeManager) allocateIndex(h *HostInfo) error {
	hm.mainHostMap.RLock()
	defer hm.mainHostMap.RUnlock()
	hm.Lock()
	defer hm.Unlock()

	for i := 0; i < 32; i++ {
		index, err := generateIndex(hm.l)
		if err != nil {
			return err
		}

		_, inPending := hm.indexes[index]
		_, inMain := hm.mainHostMap.Indexes[index]

		if !inMain && !inPending {
			h.localIndexId = index
			hm.indexes[index] = h
			return nil
		}
	}

	return errors.New("failed to generate unique localIndexId")
}

func (c *HandshakeManager) DeleteHostInfo(hostinfo *HostInfo) {
	c.Lock()
	defer c.Unlock()
	c.unlockedDeleteHostInfo(hostinfo)
}

func (c *HandshakeManager) unlockedDeleteHostInfo(hostinfo *HostInfo) {
	delete(c.vpnIps, hostinfo.vpnIp)
	if len(c.vpnIps) == 0 {
		c.vpnIps = map[iputil.VpnIp]*HostInfo{}
	}

	delete(c.indexes, hostinfo.localIndexId)
	if len(c.vpnIps) == 0 {
		c.indexes = map[uint32]*HostInfo{}
	}

	if c.l.Level >= logrus.DebugLevel {
		c.l.WithField("hostMap", m{"mapTotalSize": len(c.vpnIps),
			"vpnIp": hostinfo.vpnIp, "indexNumber": hostinfo.localIndexId, "remoteIndexNumber": hostinfo.remoteIndexId}).
			Debug("Pending hostmap hostInfo deleted")
	}
}

func (c *HandshakeManager) QueryVpnIp(vpnIp iputil.VpnIp) *HostInfo {
	c.RLock()
	defer c.RUnlock()
	return c.vpnIps[vpnIp]
}

func (c *HandshakeManager) QueryIndex(index uint32) *HostInfo {
	c.RLock()
	defer c.RUnlock()
	return c.indexes[index]
}

func (c *HandshakeManager) GetPreferredRanges() []*net.IPNet {
	return c.mainHostMap.preferredRanges
}

func (c *HandshakeManager) ForEachVpnIp(f controlEach) {
	c.RLock()
	defer c.RUnlock()

	for _, v := range c.vpnIps {
		f(v)
	}
}

func (c *HandshakeManager) ForEachIndex(f controlEach) {
	c.RLock()
	defer c.RUnlock()

	for _, v := range c.indexes {
		f(v)
	}
}

func (c *HandshakeManager) EmitStats() {
	c.RLock()
	hostLen := len(c.vpnIps)
	indexLen := len(c.indexes)
	c.RUnlock()

	metrics.GetOrRegisterGauge("hostmap.pending.hosts", nil).Update(int64(hostLen))
	metrics.GetOrRegisterGauge("hostmap.pending.indexes", nil).Update(int64(indexLen))
	c.mainHostMap.EmitStats()
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

func hsTimeout(tries int, interval time.Duration) time.Duration {
	return time.Duration(tries / 2 * ((2 * int(interval)) + (tries-1)*int(interval)))
}
