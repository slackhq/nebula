package nebula

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"time"

	"github.com/rcrowley/go-metrics"
	"github.com/sirupsen/logrus"
)

const (
	DefaultHandshakeTryInterval   = time.Millisecond * 100
	DefaultHandshakeRetries       = 10
	DefaultHandshakeTriggerBuffer = 64
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
	retries       int
	triggerBuffer int

	messageMetrics *MessageMetrics
}

type HandshakeManager struct {
	pendingHostMap         *HostMap
	mainHostMap            *HostMap
	lightHouse             *LightHouse
	outside                *udpConn
	config                 HandshakeConfig
	OutboundHandshakeTimer *SystemTimerWheel
	messageMetrics         *MessageMetrics
	metricInitiated        metrics.Counter
	metricTimedOut         metrics.Counter
	l                      *logrus.Logger

	// can be used to trigger outbound handshake for the given vpnIP
	trigger chan uint32
}

func NewHandshakeManager(l *logrus.Logger, tunCidr *net.IPNet, preferredRanges []*net.IPNet, mainHostMap *HostMap, lightHouse *LightHouse, outside *udpConn, config HandshakeConfig) *HandshakeManager {
	return &HandshakeManager{
		pendingHostMap:         NewHostMap(l, "pending", tunCidr, preferredRanges),
		mainHostMap:            mainHostMap,
		lightHouse:             lightHouse,
		outside:                outside,
		config:                 config,
		trigger:                make(chan uint32, config.triggerBuffer),
		OutboundHandshakeTimer: NewSystemTimerWheel(config.tryInterval, hsTimeout(config.retries, config.tryInterval)),
		messageMetrics:         config.messageMetrics,
		metricInitiated:        metrics.GetOrRegisterCounter("handshake_manager.initiated", nil),
		metricTimedOut:         metrics.GetOrRegisterCounter("handshake_manager.timed_out", nil),
		l:                      l,
	}
}

func (c *HandshakeManager) Run(f EncWriter) {
	clockSource := time.Tick(c.config.tryInterval)
	for {
		select {
		case vpnIP := <-c.trigger:
			c.l.WithField("vpnIp", IntIp(vpnIP)).Debug("HandshakeManager: triggered")
			c.handleOutbound(vpnIP, f, true)
		case now := <-clockSource:
			c.NextOutboundHandshakeTimerTick(now, f)
		}
	}
}

func (c *HandshakeManager) NextOutboundHandshakeTimerTick(now time.Time, f EncWriter) {
	c.OutboundHandshakeTimer.advance(now)
	for {
		ep := c.OutboundHandshakeTimer.Purge()
		if ep == nil {
			break
		}
		vpnIP := ep.(uint32)
		c.handleOutbound(vpnIP, f, false)
	}
}

func (c *HandshakeManager) handleOutbound(vpnIP uint32, f EncWriter, lighthouseTriggered bool) {
	hostinfo, err := c.pendingHostMap.QueryVpnIP(vpnIP)
	if err != nil {
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
		c.OutboundHandshakeTimer.Add(vpnIP, c.config.tryInterval*time.Duration(hostinfo.HandshakeCounter))
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

	// We only care about a lighthouse trigger before the first handshake transmit attempt. This is a very specific
	// optimization for a fast lighthouse reply
	//TODO: it would feel better to do this once, anytime, as our delay increases over time
	if lighthouseTriggered && hostinfo.HandshakeCounter > 0 {
		// If we didn't return here a lighthouse could cause us to aggressively send handshakes
		return
	}

	// Get a remotes object if we don't already have one.
	// This is mainly to protect us as this should never be the case
	if hostinfo.remotes == nil {
		hostinfo.remotes = c.lightHouse.QueryCache(vpnIP)
	}

	//TODO: this will generate a load of queries for hosts with only 1 ip (i'm not using a lighthouse, static mapped)
	if hostinfo.remotes.Len(c.pendingHostMap.preferredRanges) <= 1 {
		// If we only have 1 remote it is highly likely our query raced with the other host registered within the lighthouse
		// Our vpnIP here has a tunnel with a lighthouse but has yet to send a host update packet there so we only know about
		// the learned public ip for them. Query again to short circuit the promotion counter
		c.lightHouse.QueryServer(vpnIP, f)
	}

	// Send a the handshake to all known ips, stage 2 takes care of assigning the hostinfo.remote based on the first to reply
	var sentTo []*udpAddr
	hostinfo.remotes.ForEach(c.pendingHostMap.preferredRanges, func(addr *udpAddr, _ bool) {
		c.messageMetrics.Tx(handshake, NebulaMessageSubType(hostinfo.HandshakePacket[0][1]), 1)
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

	// Don't be too noisy or confusing if we fail to send a handshake - if we don't get through we'll eventually log a timeout
	if len(sentTo) > 0 {
		hostinfo.logger(c.l).WithField("udpAddrs", sentTo).
			WithField("initiatorIndex", hostinfo.localIndexId).
			WithField("handshake", m{"stage": 1, "style": "ix_psk0"}).
			Info("Handshake message sent")
	}

	// Increment the counter to increase our delay, linear backoff
	hostinfo.HandshakeCounter++

	// If a lighthouse triggered this attempt then we are still in the timer wheel and do not need to re-add
	if !lighthouseTriggered {
		//TODO: feel like we dupe handshake real fast in a tight loop, why?
		c.OutboundHandshakeTimer.Add(vpnIP, c.config.tryInterval*time.Duration(hostinfo.HandshakeCounter))
	}
}

func (c *HandshakeManager) AddVpnIP(vpnIP uint32) *HostInfo {
	hostinfo := c.pendingHostMap.AddVpnIP(vpnIP)
	// We lock here and use an array to insert items to prevent locking the
	// main receive thread for very long by waiting to add items to the pending map
	//TODO: what lock?
	c.OutboundHandshakeTimer.Add(vpnIP, c.config.tryInterval)
	c.metricInitiated.Inc(1)

	return hostinfo
}

var (
	ErrExistingHostInfo    = errors.New("existing hostinfo")
	ErrAlreadySeen         = errors.New("already seen")
	ErrLocalIndexCollision = errors.New("local index collision")
	ErrExistingHandshake   = errors.New("existing handshake")
)

// CheckAndComplete checks for any conflicts in the main and pending hostmap
// before adding hostinfo to main. If err is nil, it was added. Otherwise err will be:

// ErrAlreadySeen if we already have an entry in the hostmap that has seen the
// exact same handshake packet
//
// ErrExistingHostInfo if we already have an entry in the hostmap for this
// VpnIP and the new handshake was older than the one we currently have
//
// ErrLocalIndexCollision if we already have an entry in the main or pending
// hostmap for the hostinfo.localIndexId.
func (c *HandshakeManager) CheckAndComplete(hostinfo *HostInfo, handshakePacket uint8, overwrite bool, f *Interface) (*HostInfo, error) {
	c.pendingHostMap.Lock()
	defer c.pendingHostMap.Unlock()
	c.mainHostMap.Lock()
	defer c.mainHostMap.Unlock()

	// Check if we already have a tunnel with this vpn ip
	existingHostInfo, found := c.mainHostMap.Hosts[hostinfo.hostId]
	if found && existingHostInfo != nil {
		// Is it just a delayed handshake packet?
		if bytes.Equal(hostinfo.HandshakePacket[handshakePacket], existingHostInfo.HandshakePacket[handshakePacket]) {
			return existingHostInfo, ErrAlreadySeen
		}

		// Is this a newer handshake?
		if existingHostInfo.lastHandshakeTime >= hostinfo.lastHandshakeTime {
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
	if found && existingRemoteIndex != nil && existingRemoteIndex.hostId != hostinfo.hostId {
		// We have a collision, but this can happen since we can't control
		// the remote ID. Just log about the situation as a note.
		hostinfo.logger(c.l).
			WithField("remoteIndex", hostinfo.remoteIndexId).WithField("collision", IntIp(existingRemoteIndex.hostId)).
			Info("New host shadows existing host remoteIndex")
	}

	// Check if we are also handshaking with this vpn ip
	pendingHostInfo, found := c.pendingHostMap.Hosts[hostinfo.hostId]
	if found && pendingHostInfo != nil {
		if !overwrite {
			// We won, let our pending handshake win
			return pendingHostInfo, ErrExistingHandshake
		}

		// We lost, take this handshake and move any cached packets over so they get sent
		pendingHostInfo.ConnectionState.queueLock.Lock()
		hostinfo.packetStore = append(hostinfo.packetStore, pendingHostInfo.packetStore...)
		c.pendingHostMap.unlockedDeleteHostInfo(pendingHostInfo)
		pendingHostInfo.ConnectionState.queueLock.Unlock()
		pendingHostInfo.logger(c.l).Info("Handshake race lost, replacing pending handshake with completed tunnel")
	}

	if existingHostInfo != nil {
		// We are going to overwrite this entry, so remove the old references
		delete(c.mainHostMap.Hosts, existingHostInfo.hostId)
		delete(c.mainHostMap.Indexes, existingHostInfo.localIndexId)
		delete(c.mainHostMap.RemoteIndexes, existingHostInfo.remoteIndexId)
	}

	c.mainHostMap.addHostInfo(hostinfo, f)
	return existingHostInfo, nil
}

// Complete is a simpler version of CheckAndComplete when we already know we
// won't have a localIndexId collision because we already have an entry in the
// pendingHostMap
func (c *HandshakeManager) Complete(hostinfo *HostInfo, f *Interface) {
	c.pendingHostMap.Lock()
	defer c.pendingHostMap.Unlock()
	c.mainHostMap.Lock()
	defer c.mainHostMap.Unlock()

	existingHostInfo, found := c.mainHostMap.Hosts[hostinfo.hostId]
	if found && existingHostInfo != nil {
		// We are going to overwrite this entry, so remove the old references
		delete(c.mainHostMap.Hosts, existingHostInfo.hostId)
		delete(c.mainHostMap.Indexes, existingHostInfo.localIndexId)
		delete(c.mainHostMap.RemoteIndexes, existingHostInfo.remoteIndexId)
	}

	existingRemoteIndex, found := c.mainHostMap.RemoteIndexes[hostinfo.remoteIndexId]
	if found && existingRemoteIndex != nil {
		// We have a collision, but this can happen since we can't control
		// the remote ID. Just log about the situation as a note.
		hostinfo.logger(c.l).
			WithField("remoteIndex", hostinfo.remoteIndexId).WithField("collision", IntIp(existingRemoteIndex.hostId)).
			Info("New host shadows existing host remoteIndex")
	}

	c.mainHostMap.addHostInfo(hostinfo, f)
	c.pendingHostMap.unlockedDeleteHostInfo(hostinfo)
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
