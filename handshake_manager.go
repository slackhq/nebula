package nebula

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
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
	pendingHostMap         *HostMap
	mainHostMap            *HostMap
	lightHouse             *LightHouse
	outside                *udp.Conn
	config                 HandshakeConfig
	OutboundHandshakeTimer *LockingTimerWheel[iputil.VpnIp]
	messageMetrics         *MessageMetrics
	metricInitiated        metrics.Counter
	metricTimedOut         metrics.Counter
	l                      *logrus.Logger

	// vpnIps is another map similar to the pending hostmap but tracks entries in the wheel instead
	// this is to avoid situations where the same vpn ip enters the wheel and causes rapid fire handshaking
	vpnIps map[iputil.VpnIp]struct{}

	// can be used to trigger outbound handshake for the given vpnIp
	trigger chan iputil.VpnIp
}

func NewHandshakeManager(l *logrus.Logger, tunCidr *net.IPNet, preferredRanges []*net.IPNet, mainHostMap *HostMap, lightHouse *LightHouse, outside *udp.Conn, config HandshakeConfig) *HandshakeManager {
	return &HandshakeManager{
		pendingHostMap:         NewHostMap(l, "pending", tunCidr, preferredRanges),
		mainHostMap:            mainHostMap,
		lightHouse:             lightHouse,
		outside:                outside,
		config:                 config,
		trigger:                make(chan iputil.VpnIp, config.triggerBuffer),
		OutboundHandshakeTimer: NewLockingTimerWheel[iputil.VpnIp](config.tryInterval, hsTimeout(config.retries, config.tryInterval)),
		vpnIps:                 map[iputil.VpnIp]struct{}{},
		messageMetrics:         config.messageMetrics,
		metricInitiated:        metrics.GetOrRegisterCounter("handshake_manager.initiated", nil),
		metricTimedOut:         metrics.GetOrRegisterCounter("handshake_manager.timed_out", nil),
		l:                      l,
	}
}

func (c *HandshakeManager) Run(ctx context.Context, f udp.EncWriter) {
	clockSource := time.NewTicker(c.config.tryInterval)
	defer clockSource.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case vpnIP := <-c.trigger:
			c.handleOutbound(vpnIP, f, true)
		case now := <-clockSource.C:
			c.NextOutboundHandshakeTimerTick(now, f)
		}
	}
}

func (c *HandshakeManager) NextOutboundHandshakeTimerTick(now time.Time, f udp.EncWriter) {
	c.OutboundHandshakeTimer.Advance(now)
	for {
		vpnIp, has := c.OutboundHandshakeTimer.Purge()
		if !has {
			break
		}
		c.handleOutbound(vpnIp, f, false)
	}
}

func (c *HandshakeManager) handleOutbound(vpnIp iputil.VpnIp, f udp.EncWriter, lighthouseTriggered bool) {
	hostinfo, err := c.pendingHostMap.QueryVpnIp(vpnIp)
	if err != nil {
		delete(c.vpnIps, vpnIp)
		return
	}
	hostinfo.Lock()
	defer hostinfo.Unlock()

	// We may have raced to completion but now that we have a lock we should ensure we have not yet completed.
	if hostinfo.HandshakeComplete {
		// Ensure we don't exist in the pending hostmap anymore since we have completed
		c.pendingHostMap.DeleteHostInfo(hostinfo)
		return
	}

	// Check if we have a handshake packet to transmit yet
	if !hostinfo.HandshakeReady {
		// There is currently a slight race in getOrHandshake due to ConnectionState not being part of the HostInfo directly
		// Our hostinfo here was added to the pending map and the wheel may have ticked to us before we created ConnectionState
		c.OutboundHandshakeTimer.Add(vpnIp, c.config.tryInterval*time.Duration(hostinfo.HandshakeCounter))
		return
	}

	// If we are out of time, clean up
	if hostinfo.HandshakeCounter >= c.config.retries {
		hostinfo.logger(c.l).WithField("udpAddrs", hostinfo.remotes.CopyAddrs(c.pendingHostMap.preferredRanges)).
			WithField("initiatorIndex", hostinfo.localIndexId).
			WithField("remoteIndex", hostinfo.remoteIndexId).
			WithField("handshake", m{"stage": 1, "style": "ix_psk0"}).
			WithField("durationNs", time.Since(hostinfo.handshakeStart).Nanoseconds()).
			Info("Handshake timed out")
		c.metricTimedOut.Inc(1)
		c.pendingHostMap.DeleteHostInfo(hostinfo)
		return
	}

	// Get a remotes object if we don't already have one.
	// This is mainly to protect us as this should never be the case
	// NB ^ This comment doesn't jive. It's how the thing gets initialized.
	// It's the common path. Should it update every time, in case a future LH query/queries give us more info?
	if hostinfo.remotes == nil {
		hostinfo.remotes = c.lightHouse.QueryCache(vpnIp)
	}

	remotes := hostinfo.remotes.CopyAddrs(c.pendingHostMap.preferredRanges)
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
		c.lightHouse.QueryServer(vpnIp, f)
	}

	// Send the handshake to all known ips, stage 2 takes care of assigning the hostinfo.remote based on the first to reply
	var sentTo []*udp.Addr
	hostinfo.remotes.ForEach(c.pendingHostMap.preferredRanges, func(addr *udp.Addr, _ bool) {
		c.messageMetrics.Tx(header.Handshake, header.MessageSubType(hostinfo.HandshakePacket[0][1]), 1)
		err = c.outside.WriteTo(hostinfo.HandshakePacket[0], addr)
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
		hostinfo.logger(c.l).WithField("relayIps", hostinfo.remotes.relays).Info("Attempt to relay through hosts")
		// Send a RelayRequest to all known Relay IP's
		for _, relay := range hostinfo.remotes.relays {
			// Don't relay to myself, and don't relay through the host I'm trying to connect to
			if *relay == vpnIp || *relay == c.lightHouse.myVpnIp {
				continue
			}
			relayHostInfo, err := c.mainHostMap.QueryVpnIp(*relay)
			if err != nil || relayHostInfo.remote == nil {
				hostinfo.logger(c.l).WithError(err).WithField("relay", relay.String()).Info("Establish tunnel to relay target.")
				f.Handshake(*relay)
				continue
			}
			// Check the relay HostInfo to see if we already established a relay through it
			if existingRelay, ok := relayHostInfo.relayState.QueryRelayForByIp(vpnIp); ok {
				switch existingRelay.State {
				case Established:
					hostinfo.logger(c.l).WithField("relay", relay.String()).Info("Send handshake via relay")
					f.SendVia(relayHostInfo, existingRelay, hostinfo.HandshakePacket[0], make([]byte, 12), make([]byte, mtu), false)
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
						f.SendMessageToVpnIp(header.Control, 0, *relay, msg, make([]byte, 12), make([]byte, mtu))
						c.l.WithFields(logrus.Fields{
							"relayFrom":    iputil.VpnIp(c.lightHouse.myVpnIp),
							"relayTarget":  iputil.VpnIp(vpnIp),
							"initiatorIdx": existingRelay.LocalIndex,
							"vpnIp":        *relay}).
							Info("send CreateRelayRequest")
					}
				default:
					hostinfo.logger(c.l).
						WithField("vpnIp", vpnIp).
						WithField("state", existingRelay.State).
						WithField("relayVpnIp", relayHostInfo.vpnIp).
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
						f.SendMessageToVpnIp(header.Control, 0, *relay, msg, make([]byte, 12), make([]byte, mtu))
						c.l.WithFields(logrus.Fields{
							"relayFrom":    iputil.VpnIp(c.lightHouse.myVpnIp),
							"relayTarget":  iputil.VpnIp(vpnIp),
							"initiatorIdx": idx,
							"vpnIp":        *relay}).
							Info("send CreateRelayRequest")
					}
				}
			}
		}
	}

	// Increment the counter to increase our delay, linear backoff
	hostinfo.HandshakeCounter++

	// If a lighthouse triggered this attempt then we are still in the timer wheel and do not need to re-add
	if !lighthouseTriggered {
		c.OutboundHandshakeTimer.Add(vpnIp, c.config.tryInterval*time.Duration(hostinfo.HandshakeCounter))
	}
}

func (c *HandshakeManager) AddVpnIp(vpnIp iputil.VpnIp, init func(*HostInfo)) *HostInfo {
	hostinfo, created := c.pendingHostMap.AddVpnIp(vpnIp, init)

	if created {
		if _, ok := c.vpnIps[vpnIp]; !ok {
			c.OutboundHandshakeTimer.Add(vpnIp, c.config.tryInterval)
		}
		c.vpnIps[vpnIp] = struct{}{}
		c.metricInitiated.Inc(1)
	}

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
	c.pendingHostMap.Lock()
	defer c.pendingHostMap.Unlock()
	c.mainHostMap.Lock()
	defer c.mainHostMap.Unlock()

	// Check if we already have a tunnel with this vpn ip
	existingHostInfo, found := c.mainHostMap.Hosts[hostinfo.vpnIp]
	if found && existingHostInfo != nil {
		testHostInfo := existingHostInfo
		for testHostInfo != nil {
			// Is it just a delayed handshake packet?
			if bytes.Equal(hostinfo.HandshakePacket[handshakePacket], existingHostInfo.HandshakePacket[handshakePacket]) {
				return existingHostInfo, ErrAlreadySeen
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

	existingIndex, found = c.pendingHostMap.Indexes[hostinfo.localIndexId]
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
func (c *HandshakeManager) Complete(hostinfo *HostInfo, f *Interface) *HostInfo {
	c.pendingHostMap.Lock()
	defer c.pendingHostMap.Unlock()
	c.mainHostMap.Lock()
	defer c.mainHostMap.Unlock()

	existingRemoteIndex, found := c.mainHostMap.RemoteIndexes[hostinfo.remoteIndexId]
	if found && existingRemoteIndex != nil {
		// We have a collision, but this can happen since we can't control
		// the remote ID. Just log about the situation as a note.
		hostinfo.logger(c.l).
			WithField("remoteIndex", hostinfo.remoteIndexId).WithField("collision", existingRemoteIndex.vpnIp).
			Info("New host shadows existing host remoteIndex")
	}

	existingHostInfo := c.mainHostMap.Hosts[hostinfo.vpnIp]
	// We need to remove from the pending hostmap first to avoid undoing work when after to the main hostmap.
	c.pendingHostMap.unlockedDeleteHostInfo(hostinfo)
	c.mainHostMap.unlockedAddHostInfo(hostinfo, f)
	return existingHostInfo
}

// AddIndexHostInfo generates a unique localIndexId for this HostInfo
// and adds it to the pendingHostMap. Will error if we are unable to generate
// a unique localIndexId
func (c *HandshakeManager) AddIndexHostInfo(h *HostInfo) error {
	c.pendingHostMap.Lock()
	defer c.pendingHostMap.Unlock()
	c.mainHostMap.RLock()
	defer c.mainHostMap.RUnlock()

	for i := 0; i < 32; i++ {
		index, err := generateIndex(c.l)
		if err != nil {
			return err
		}

		_, inPending := c.pendingHostMap.Indexes[index]
		_, inMain := c.mainHostMap.Indexes[index]

		if !inMain && !inPending {
			h.localIndexId = index
			c.pendingHostMap.Indexes[index] = h
			return nil
		}
	}

	return errors.New("failed to generate unique localIndexId")
}

func (c *HandshakeManager) addRemoteIndexHostInfo(index uint32, h *HostInfo) {
	c.pendingHostMap.addRemoteIndexHostInfo(index, h)
}

func (c *HandshakeManager) DeleteHostInfo(hostinfo *HostInfo) {
	//l.Debugln("Deleting pending hostinfo :", hostinfo)
	c.pendingHostMap.DeleteHostInfo(hostinfo)
}

func (c *HandshakeManager) QueryIndex(index uint32) (*HostInfo, error) {
	return c.pendingHostMap.QueryIndex(index)
}

func (c *HandshakeManager) EmitStats() {
	c.pendingHostMap.EmitStats("pending")
	c.mainHostMap.EmitStats("main")
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
