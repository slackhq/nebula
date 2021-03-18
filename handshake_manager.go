package nebula

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/udp"
)

const (
	// Total time to try a handshake = sequence of HandshakeTryInterval * HandshakeRetries
	// With 100ms interval and 20 retries is 23.5 seconds
	DefaultHandshakeTryInterval = time.Millisecond * 100
	DefaultHandshakeRetries     = 20
	// DefaultHandshakeWaitRotation is the number of handshake attempts to do before starting to use other ips addresses
	DefaultHandshakeWaitRotation  = 5
	DefaultHandshakeTriggerBuffer = 64
)

var (
	defaultHandshakeConfig = HandshakeConfig{
		tryInterval:   DefaultHandshakeTryInterval,
		retries:       DefaultHandshakeRetries,
		waitRotation:  DefaultHandshakeWaitRotation,
		triggerBuffer: DefaultHandshakeTriggerBuffer,
	}
)

type HandshakeConfig struct {
	tryInterval   time.Duration
	retries       int
	waitRotation  int
	triggerBuffer int

	messageMetrics *MessageMetrics
}

type HandshakeManager struct {
	pendingHostMap *HostMap
	mainHostMap    *HostMap
	lightHouse     *LightHouse
	outside        udp.Conn
	config         HandshakeConfig

	// can be used to trigger outbound handshake for the given vpnIP
	trigger chan uint32

	OutboundHandshakeTimer *SystemTimerWheel
	InboundHandshakeTimer  *SystemTimerWheel

	messageMetrics *MessageMetrics
}

func NewHandshakeManager(tunCidr *net.IPNet, preferredRanges []*net.IPNet, mainHostMap *HostMap, lightHouse *LightHouse, outside udp.Conn, config HandshakeConfig) *HandshakeManager {
	return &HandshakeManager{
		pendingHostMap: NewHostMap("pending", tunCidr, preferredRanges),
		mainHostMap:    mainHostMap,
		lightHouse:     lightHouse,
		outside:        outside,

		config: config,

		trigger: make(chan uint32, config.triggerBuffer),

		OutboundHandshakeTimer: NewSystemTimerWheel(config.tryInterval, config.tryInterval*time.Duration(config.retries)),
		InboundHandshakeTimer:  NewSystemTimerWheel(config.tryInterval, config.tryInterval*time.Duration(config.retries)),

		messageMetrics: config.messageMetrics,
	}
}

func (c *HandshakeManager) Run(f udp.EncWriter) {
	clockSource := time.Tick(c.config.tryInterval)
	for {
		select {
		case vpnIP := <-c.trigger:
			l.WithField("vpnIp", IntIp(vpnIP)).Debug("HandshakeManager: triggered")
			c.handleOutbound(vpnIP, f, true)
		case now := <-clockSource:
			c.NextOutboundHandshakeTimerTick(now, f)
			c.NextInboundHandshakeTimerTick(now)
		}
	}
}

func (c *HandshakeManager) NextOutboundHandshakeTimerTick(now time.Time, f udp.EncWriter) {
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

func (c *HandshakeManager) handleOutbound(vpnIP uint32, f udp.EncWriter, lighthouseTriggered bool) {
	hostinfo, err := c.pendingHostMap.QueryVpnIP(vpnIP)
	if err != nil {
		return
	}
	hostinfo.Lock()
	defer hostinfo.Unlock()

	// If we haven't finished the handshake and we haven't hit max retries, query
	// lighthouse and then send the handshake packet again.
	if hostinfo.HandshakeCounter < c.config.retries && !hostinfo.HandshakeComplete {
		if hostinfo.remote == nil {
			// We continue to query the lighthouse because hosts may
			// come online during handshake retries. If the query
			// succeeds (no error), add the lighthouse info to hostinfo
			ips := c.lightHouse.QueryCache(vpnIP)
			// If we have no responses yet, or only one IP (the host hadn't
			// finished reporting its own IPs yet), then send another query to
			// the LH.
			if len(ips) <= 1 {
				ips, err = c.lightHouse.Query(vpnIP, f)
			}
			if err == nil {
				for _, ip := range ips {
					hostinfo.AddRemote(ip)
				}
				hostinfo.ForcePromoteBest(c.mainHostMap.preferredRanges)
			}
		} else if lighthouseTriggered {
			// We were triggered by a lighthouse HostQueryReply packet, but
			// we have already picked a remote for this host (this can happen
			// if we are configured with multiple lighthouses). So we can skip
			// this trigger and let the timerwheel handle the rest of the
			// process
			return
		}

		hostinfo.HandshakeCounter++

		// We want to use the "best" calculated ip for the first 5 attempts, after that we just blindly rotate through
		// all the others until we can stand up a connection.
		if hostinfo.HandshakeCounter > c.config.waitRotation {
			hostinfo.rotateRemote()
		}

		// Ensure the handshake is ready to avoid a race in timer tick and stage 0 handshake generation
		if hostinfo.HandshakeReady && hostinfo.remote != nil {
			c.messageMetrics.Tx(udp.Handshake, udp.NebulaMessageSubType(hostinfo.HandshakePacket[0][1]), 1)
			err := c.outside.WriteTo(hostinfo.HandshakePacket[0], hostinfo.remote)
			if err != nil {
				hostinfo.logger().WithField("udpAddr", hostinfo.remote).
					WithField("initiatorIndex", hostinfo.localIndexId).
					WithField("remoteIndex", hostinfo.remoteIndexId).
					WithField("handshake", m{"stage": 1, "style": "ix_psk0"}).
					WithError(err).Error("Failed to send handshake message")
			} else {
				//TODO: this log line is assuming a lot of stuff around the cached stage 0 handshake packet, we should
				// keep the real packet struct around for logging purposes
				hostinfo.logger().WithField("udpAddr", hostinfo.remote).
					WithField("initiatorIndex", hostinfo.localIndexId).
					WithField("remoteIndex", hostinfo.remoteIndexId).
					WithField("handshake", m{"stage": 1, "style": "ix_psk0"}).
					Info("Handshake message sent")
			}
		}

		// Readd to the timer wheel so we continue trying wait HandshakeTryInterval * counter longer for next try
		if !lighthouseTriggered {
			//l.Infoln("Interval: ", HandshakeTryInterval*time.Duration(hostinfo.HandshakeCounter))
			c.OutboundHandshakeTimer.Add(vpnIP, c.config.tryInterval*time.Duration(hostinfo.HandshakeCounter))
		}
	} else {
		c.pendingHostMap.DeleteHostInfo(hostinfo)
	}
}

func (c *HandshakeManager) NextInboundHandshakeTimerTick(now time.Time) {
	c.InboundHandshakeTimer.advance(now)
	for {
		ep := c.InboundHandshakeTimer.Purge()
		if ep == nil {
			break
		}
		index := ep.(uint32)

		c.pendingHostMap.DeleteIndex(index)
	}
}

func (c *HandshakeManager) AddVpnIP(vpnIP uint32) *HostInfo {
	hostinfo := c.pendingHostMap.AddVpnIP(vpnIP)
	// We lock here and use an array to insert items to prevent locking the
	// main receive thread for very long by waiting to add items to the pending map
	c.OutboundHandshakeTimer.Add(vpnIP, c.config.tryInterval)

	return hostinfo
}

var (
	ErrExistingHostInfo    = errors.New("existing hostinfo")
	ErrAlreadySeen         = errors.New("already seen")
	ErrLocalIndexCollision = errors.New("local index collision")
)

// CheckAndComplete checks for any conflicts in the main and pending hostmap
// before adding hostinfo to main. If err is nil, it was added. Otherwise err will be:

// ErrAlreadySeen if we already have an entry in the hostmap that has seen the
// exact same handshake packet
//
// ErrExistingHostInfo if we already have an entry in the hostmap for this
// VpnIP and overwrite was false.
//
// ErrLocalIndexCollision if we already have an entry in the main or pending
// hostmap for the hostinfo.localIndexId.
func (c *HandshakeManager) CheckAndComplete(hostinfo *HostInfo, handshakePacket uint8, overwrite bool, f *Interface) (*HostInfo, error) {
	c.pendingHostMap.RLock()
	defer c.pendingHostMap.RUnlock()
	c.mainHostMap.Lock()
	defer c.mainHostMap.Unlock()

	existingHostInfo, found := c.mainHostMap.Hosts[hostinfo.hostId]
	if found && existingHostInfo != nil {
		if bytes.Equal(hostinfo.HandshakePacket[handshakePacket], existingHostInfo.HandshakePacket[handshakePacket]) {
			return existingHostInfo, ErrAlreadySeen
		}
		if !overwrite {
			return existingHostInfo, ErrExistingHostInfo
		}
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
		hostinfo.logger().
			WithField("remoteIndex", hostinfo.remoteIndexId).WithField("collision", IntIp(existingRemoteIndex.hostId)).
			Info("New host shadows existing host remoteIndex")
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
		hostinfo.logger().
			WithField("remoteIndex", hostinfo.remoteIndexId).WithField("collision", IntIp(existingRemoteIndex.hostId)).
			Info("New host shadows existing host remoteIndex")
	}

	c.mainHostMap.addHostInfo(hostinfo, f)
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
		index, err := generateIndex()
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

func generateIndex() (uint32, error) {
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
