package nebula

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/rcrowley/go-metrics"
	"github.com/sirupsen/logrus"
)

const (
	// Total time to try a handshake = sequence of HandshakeTryInterval * HandshakeRetries
	// With 100ms interval and 20 retries is 23.5 seconds
	DefaultHandshakeTryInterval = time.Millisecond * 100
	DefaultHandshakeRetries     = 20
	// DefaultHandshakeWaitRotation is the number of handshake attempts to do before starting to use other ips addresses
	DefaultHandshakeWaitRotation = 5
)

var (
	defaultHandshakeConfig = HandshakeConfig{
		tryInterval:  DefaultHandshakeTryInterval,
		retries:      DefaultHandshakeRetries,
		waitRotation: DefaultHandshakeWaitRotation,
	}
)

type HandshakeConfig struct {
	tryInterval  time.Duration
	retries      int
	waitRotation int

	metricsEnabled bool
}

type HandshakeManager struct {
	pendingHostMap *HostMap
	mainHostMap    *HostMap
	lightHouse     *LightHouse
	outside        *udpConn
	config         HandshakeConfig

	OutboundHandshakeTimer *SystemTimerWheel
	InboundHandshakeTimer  *SystemTimerWheel

	metricHandshakeTx metrics.Counter
}

func NewHandshakeManager(tunCidr *net.IPNet, preferredRanges []*net.IPNet, mainHostMap *HostMap, lightHouse *LightHouse, outside *udpConn, config HandshakeConfig) *HandshakeManager {
	h := &HandshakeManager{
		pendingHostMap: NewHostMap("pending", tunCidr, preferredRanges),
		mainHostMap:    mainHostMap,
		lightHouse:     lightHouse,
		outside:        outside,

		config: config,

		OutboundHandshakeTimer: NewSystemTimerWheel(config.tryInterval, config.tryInterval*time.Duration(config.retries)),
		InboundHandshakeTimer:  NewSystemTimerWheel(config.tryInterval, config.tryInterval*time.Duration(config.retries)),
	}

	if config.metricsEnabled {
		h.metricHandshakeTx = metrics.GetOrRegisterCounter("messages.tx.handshake", nil)
	} else {
		h.metricHandshakeTx = metrics.NilCounter{}
	}

	return h
}

func (c *HandshakeManager) Run(f EncWriter) {
	clockSource := time.Tick(c.config.tryInterval)
	for now := range clockSource {
		c.NextOutboundHandshakeTimerTick(now, f)
		c.NextInboundHandshakeTimerTick(now)
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

		index, err := c.pendingHostMap.GetIndexByVpnIP(vpnIP)
		if err != nil {
			continue
		}

		hostinfo, err := c.pendingHostMap.QueryVpnIP(vpnIP)
		if err != nil {
			continue
		}

		// If we haven't finished the handshake and we haven't hit max retries, query
		// lighthouse and then send the handshake packet again.
		if hostinfo.HandshakeCounter < c.config.retries && !hostinfo.HandshakeComplete {
			if hostinfo.remote == nil {
				// We continue to query the lighthouse because hosts may
				// come online during handshake retries. If the query
				// succeeds (no error), add the lighthouse info to hostinfo
				ips, err := c.lightHouse.Query(vpnIP, f)
				if err == nil {
					for _, ip := range ips {
						hostinfo.AddRemote(ip)
					}
					hostinfo.ForcePromoteBest(c.mainHostMap.preferredRanges)
				}
			}

			hostinfo.HandshakeCounter++

			// We want to use the "best" calculated ip for the first 5 attempts, after that we just blindly rotate through
			// all the others until we can stand up a connection.
			if hostinfo.HandshakeCounter > c.config.waitRotation {
				hostinfo.rotateRemote()
			}

			// Ensure the handshake is ready to avoid a race in timer tick and stage 0 handshake generation
			if hostinfo.HandshakeReady && hostinfo.remote != nil {
				c.metricHandshakeTx.Inc(1)
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
			//l.Infoln("Interval: ", HandshakeTryInterval*time.Duration(hostinfo.HandshakeCounter))
			c.OutboundHandshakeTimer.Add(vpnIP, c.config.tryInterval*time.Duration(hostinfo.HandshakeCounter))
		} else {
			c.pendingHostMap.DeleteVpnIP(vpnIP)
			c.pendingHostMap.DeleteIndex(index)
		}
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

		vpnIP, err := c.pendingHostMap.GetVpnIPByIndex(index)
		if err != nil {
			continue
		}
		c.pendingHostMap.DeleteIndex(index)
		c.pendingHostMap.DeleteVpnIP(vpnIP)
	}
}

func (c *HandshakeManager) AddVpnIP(vpnIP uint32) *HostInfo {
	hostinfo := c.pendingHostMap.AddVpnIP(vpnIP)
	// We lock here and use an array to insert items to prevent locking the
	// main receive thread for very long by waiting to add items to the pending map
	c.OutboundHandshakeTimer.Add(vpnIP, c.config.tryInterval)
	return hostinfo
}

func (c *HandshakeManager) DeleteVpnIP(vpnIP uint32) {
	//l.Debugln("Deleting pending vpn ip :", IntIp(vpnIP))
	c.pendingHostMap.DeleteVpnIP(vpnIP)
}

func (c *HandshakeManager) AddIndex(index uint32, ci *ConnectionState) (*HostInfo, error) {
	hostinfo, err := c.pendingHostMap.AddIndex(index, ci)
	if err != nil {
		return nil, fmt.Errorf("Issue adding index: %d", index)
	}
	//c.mainHostMap.AddIndexHostInfo(index, hostinfo)
	c.InboundHandshakeTimer.Add(index, time.Second*10)
	return hostinfo, nil
}

func (c *HandshakeManager) AddIndexHostInfo(index uint32, h *HostInfo) {
	c.pendingHostMap.AddIndexHostInfo(index, h)
}

func (c *HandshakeManager) DeleteIndex(index uint32) {
	//l.Debugln("Deleting pending index :", index)
	c.pendingHostMap.DeleteIndex(index)
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
	_, err := rand.Read(b)
	if err != nil {
		l.Errorln(err)
		return 0, err
	}

	index := binary.BigEndian.Uint32(b)
	if l.Level >= logrus.DebugLevel {
		l.WithField("index", index).
			Debug("Generated index")
	}
	return index, nil
}
