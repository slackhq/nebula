package nebula

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"sync/atomic"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/header"
)

type relayManager struct {
	l       *logrus.Logger
	hostmap *HostMap
	amRelay atomic.Bool
}

func NewRelayManager(ctx context.Context, l *logrus.Logger, hostmap *HostMap, c *config.C) *relayManager {
	rm := &relayManager{
		l:       l,
		hostmap: hostmap,
	}
	rm.reload(c, true)
	c.RegisterReloadCallback(func(c *config.C) {
		err := rm.reload(c, false)
		if err != nil {
			l.WithError(err).Error("Failed to reload relay_manager")
		}
	})
	return rm
}

func (rm *relayManager) reload(c *config.C, initial bool) error {
	if initial || c.HasChanged("relay.am_relay") {
		rm.setAmRelay(c.GetBool("relay.am_relay", false))
	}
	return nil
}

func (rm *relayManager) GetAmRelay() bool {
	return rm.amRelay.Load()
}

func (rm *relayManager) setAmRelay(v bool) {
	rm.amRelay.Store(v)
}

// AddRelay finds an available relay index on the hostmap, and associates the relay info with it.
// relayHostInfo is the Nebula peer which can be used as a relay to access the target vpnIp.
func AddRelay(l *logrus.Logger, relayHostInfo *HostInfo, hm *HostMap, vpnIp netip.Addr, remoteIdx *uint32, relayType int, state int) (uint32, error) {
	hm.Lock()
	defer hm.Unlock()
	for i := 0; i < 32; i++ {
		index, err := generateIndex(l)
		if err != nil {
			return 0, err
		}

		_, inRelays := hm.Relays[index]
		if !inRelays {
			// Avoid standing up a relay that can't be used since only the primary hostinfo
			// will be pointed to by the relay logic
			//TODO: if there was an existing primary and it had relay state, should we merge?
			hm.unlockedMakePrimary(relayHostInfo)

			hm.Relays[index] = relayHostInfo
			newRelay := Relay{
				Type:       relayType,
				State:      state,
				LocalIndex: index,
				PeerAddr:   vpnIp,
			}

			if remoteIdx != nil {
				newRelay.RemoteIndex = *remoteIdx
			}
			relayHostInfo.relayState.InsertRelay(vpnIp, index, &newRelay)

			return index, nil
		}
	}

	return 0, errors.New("failed to generate unique localIndexId")
}

// EstablishRelay updates a Requested Relay to become an Established Relay, which can pass traffic.
func (rm *relayManager) EstablishRelay(relayHostInfo *HostInfo, m *NebulaControl) (*Relay, error) {
	relay, ok := relayHostInfo.relayState.CompleteRelayByIdx(m.InitiatorRelayIndex, m.ResponderRelayIndex)
	if !ok {
		fields := logrus.Fields{
			"relay":               relayHostInfo.vpnAddrs[0],
			"initiatorRelayIndex": m.InitiatorRelayIndex,
		}

		if m.RelayFromAddr == nil {
			fields["relayFrom"] = m.OldRelayFromAddr
		} else {
			fields["relayFrom"] = m.RelayFromAddr
		}

		if m.RelayToAddr == nil {
			fields["relayTo"] = m.OldRelayToAddr
		} else {
			fields["relayTo"] = m.RelayToAddr
		}

		rm.l.WithFields(fields).Info("relayManager failed to update relay")
		return nil, fmt.Errorf("unknown relay")
	}

	return relay, nil
}

func (rm *relayManager) HandleControlMsg(h *HostInfo, d []byte, f *Interface) {
	msg := &NebulaControl{}
	err := msg.Unmarshal(d)
	if err != nil {
		h.logger(f.l).WithError(err).Error("Failed to unmarshal control message")
		return
	}

	var v cert.Version
	if msg.OldRelayFromAddr > 0 || msg.OldRelayToAddr > 0 {
		v = cert.Version1

		b := [4]byte{}
		binary.BigEndian.PutUint32(b[:], msg.OldRelayFromAddr)
		msg.RelayFromAddr = netAddrToProtoAddr(netip.AddrFrom4(b))

		binary.BigEndian.PutUint32(b[:], msg.OldRelayToAddr)
		msg.RelayToAddr = netAddrToProtoAddr(netip.AddrFrom4(b))
	} else {
		v = cert.Version2
	}

	switch msg.Type {
	case NebulaControl_CreateRelayRequest:
		rm.handleCreateRelayRequest(v, h, f, msg)
	case NebulaControl_CreateRelayResponse:
		rm.handleCreateRelayResponse(v, h, f, msg)
	}
}

func (rm *relayManager) handleCreateRelayResponse(v cert.Version, h *HostInfo, f *Interface, m *NebulaControl) {
	rm.l.WithFields(logrus.Fields{
		"relayFrom":           protoAddrToNetAddr(m.RelayFromAddr),
		"relayTo":             protoAddrToNetAddr(m.RelayToAddr),
		"initiatorRelayIndex": m.InitiatorRelayIndex,
		"responderRelayIndex": m.ResponderRelayIndex,
		"vpnAddrs":            h.vpnAddrs}).
		Info("handleCreateRelayResponse")

	target := m.RelayToAddr
	targetAddr := protoAddrToNetAddr(target)

	relay, err := rm.EstablishRelay(h, m)
	if err != nil {
		rm.l.WithError(err).Error("Failed to update relay for relayTo")
		return
	}
	// Do I need to complete the relays now?
	if relay.Type == TerminalType {
		return
	}
	// I'm the middle man. Let the initiator know that the I've established the relay they requested.
	peerHostInfo := rm.hostmap.QueryVpnAddr(relay.PeerAddr)
	if peerHostInfo == nil {
		rm.l.WithField("relayTo", relay.PeerAddr).Error("Can't find a HostInfo for peer")
		return
	}
	peerRelay, ok := peerHostInfo.relayState.QueryRelayForByIp(targetAddr)
	if !ok {
		rm.l.WithField("relayTo", peerHostInfo.vpnAddrs[0]).Error("peerRelay does not have Relay state for relayTo")
		return
	}
	switch peerRelay.State {
	case Requested:
		// I initiated the request to this peer, but haven't heard back from the peer yet. I must wait for this peer
		// to respond to complete the connection.
	case PeerRequested, Disestablished, Established:
		peerHostInfo.relayState.UpdateRelayForByIpState(targetAddr, Established)
		resp := NebulaControl{
			Type:                NebulaControl_CreateRelayResponse,
			ResponderRelayIndex: peerRelay.LocalIndex,
			InitiatorRelayIndex: peerRelay.RemoteIndex,
		}

		if v == cert.Version1 {
			peer := peerHostInfo.vpnAddrs[0]
			if !peer.Is4() {
				rm.l.WithField("relayFrom", peer).
					WithField("relayTo", target).
					WithField("initiatorRelayIndex", resp.InitiatorRelayIndex).
					WithField("responderRelayIndex", resp.ResponderRelayIndex).
					WithField("vpnAddrs", peerHostInfo.vpnAddrs).
					Error("Refusing to CreateRelayResponse for a v1 relay with an ipv6 address")
				return
			}

			b := peer.As4()
			resp.OldRelayFromAddr = binary.BigEndian.Uint32(b[:])
			b = targetAddr.As4()
			resp.OldRelayToAddr = binary.BigEndian.Uint32(b[:])
		} else {
			resp.RelayFromAddr = netAddrToProtoAddr(peerHostInfo.vpnAddrs[0])
			resp.RelayToAddr = target
		}

		msg, err := resp.Marshal()
		if err != nil {
			rm.l.WithError(err).
				Error("relayManager Failed to marshal Control CreateRelayResponse message to create relay")
		} else {
			f.SendMessageToHostInfo(header.Control, 0, peerHostInfo, msg, make([]byte, 12), make([]byte, mtu))
			rm.l.WithFields(logrus.Fields{
				"relayFrom":           resp.RelayFromAddr,
				"relayTo":             resp.RelayToAddr,
				"initiatorRelayIndex": resp.InitiatorRelayIndex,
				"responderRelayIndex": resp.ResponderRelayIndex,
				"vpnAddrs":            peerHostInfo.vpnAddrs}).
				Info("send CreateRelayResponse")
		}
	}
}

func (rm *relayManager) handleCreateRelayRequest(v cert.Version, h *HostInfo, f *Interface, m *NebulaControl) {
	from := protoAddrToNetAddr(m.RelayFromAddr)
	target := protoAddrToNetAddr(m.RelayToAddr)

	logMsg := rm.l.WithFields(logrus.Fields{
		"relayFrom":           from,
		"relayTo":             target,
		"initiatorRelayIndex": m.InitiatorRelayIndex,
		"vpnAddrs":            h.vpnAddrs})

	logMsg.Info("handleCreateRelayRequest")
	// Is the source of the relay me? This should never happen, but did happen due to
	// an issue migrating relays over to newly re-handshaked host info objects.
	if f.myVpnAddrsTable.Contains(from) {
		logMsg.WithField("myIP", from).Error("Discarding relay request from myself")
		return
	}

	// Is the target of the relay me?
	if f.myVpnAddrsTable.Contains(target) {
		existingRelay, ok := h.relayState.QueryRelayForByIp(from)
		if ok {
			switch existingRelay.State {
			case Requested:
				ok = h.relayState.CompleteRelayByIP(from, m.InitiatorRelayIndex)
				if !ok {
					logMsg.Error("Relay State not found")
					return
				}
			case Established:
				if existingRelay.RemoteIndex != m.InitiatorRelayIndex {
					// We got a brand new Relay request, because its index is different than what we saw before.
					// This should never happen. The peer should never change an index, once created.
					logMsg.WithFields(logrus.Fields{
						"existingRemoteIndex": existingRelay.RemoteIndex}).Error("Existing relay mismatch with CreateRelayRequest")
					return
				}
			case Disestablished:
				if existingRelay.RemoteIndex != m.InitiatorRelayIndex {
					// We got a brand new Relay request, because its index is different than what we saw before.
					// This should never happen. The peer should never change an index, once created.
					logMsg.WithFields(logrus.Fields{
						"existingRemoteIndex": existingRelay.RemoteIndex}).Error("Existing relay mismatch with CreateRelayRequest")
					return
				}
				// Mark the relay as 'Established' because it's safe to use again
				h.relayState.UpdateRelayForByIpState(from, Established)
			case PeerRequested:
				// I should never be in this state, because I am terminal, not forwarding.
				logMsg.WithFields(logrus.Fields{
					"existingRemoteIndex": existingRelay.RemoteIndex,
					"state":               existingRelay.State}).Error("Unexpected Relay State found")
			}
		} else {
			_, err := AddRelay(rm.l, h, f.hostMap, from, &m.InitiatorRelayIndex, TerminalType, Established)
			if err != nil {
				logMsg.WithError(err).Error("Failed to add relay")
				return
			}
		}

		relay, ok := h.relayState.QueryRelayForByIp(from)
		if !ok {
			logMsg.WithField("from", from).Error("Relay State not found")
			return
		}

		resp := NebulaControl{
			Type:                NebulaControl_CreateRelayResponse,
			ResponderRelayIndex: relay.LocalIndex,
			InitiatorRelayIndex: relay.RemoteIndex,
		}

		if v == cert.Version1 {
			b := from.As4()
			resp.OldRelayFromAddr = binary.BigEndian.Uint32(b[:])
			b = target.As4()
			resp.OldRelayToAddr = binary.BigEndian.Uint32(b[:])
		} else {
			resp.RelayFromAddr = netAddrToProtoAddr(from)
			resp.RelayToAddr = netAddrToProtoAddr(target)
		}

		msg, err := resp.Marshal()
		if err != nil {
			logMsg.
				WithError(err).Error("relayManager Failed to marshal Control CreateRelayResponse message to create relay")
		} else {
			f.SendMessageToHostInfo(header.Control, 0, h, msg, make([]byte, 12), make([]byte, mtu))
			rm.l.WithFields(logrus.Fields{
				"relayFrom":           from,
				"relayTo":             target,
				"initiatorRelayIndex": resp.InitiatorRelayIndex,
				"responderRelayIndex": resp.ResponderRelayIndex,
				"vpnAddrs":            h.vpnAddrs}).
				Info("send CreateRelayResponse")
		}
		return
	} else {
		// the target is not me. Create a relay to the target, from me.
		if !rm.GetAmRelay() {
			return
		}
		peer := rm.hostmap.QueryVpnAddr(target)
		if peer == nil {
			// Try to establish a connection to this host. If we get a future relay request,
			// we'll be ready!
			f.Handshake(target)
			return
		}
		if !peer.remote.IsValid() {
			// Only create relays to peers for whom I have a direct connection
			return
		}
		var index uint32
		var err error
		targetRelay, ok := peer.relayState.QueryRelayForByIp(from)
		if ok {
			index = targetRelay.LocalIndex
		} else {
			// Allocate an index in the hostMap for this relay peer
			index, err = AddRelay(rm.l, peer, f.hostMap, from, nil, ForwardingType, Requested)
			if err != nil {
				return
			}
		}
		peer.relayState.UpdateRelayForByIpState(from, Requested)
		// Send a CreateRelayRequest to the peer.
		req := NebulaControl{
			Type:                NebulaControl_CreateRelayRequest,
			InitiatorRelayIndex: index,
		}

		if v == cert.Version1 {
			if !h.vpnAddrs[0].Is4() {
				rm.l.WithField("relayFrom", h.vpnAddrs[0]).
					WithField("relayTo", target).
					WithField("initiatorRelayIndex", req.InitiatorRelayIndex).
					WithField("responderRelayIndex", req.ResponderRelayIndex).
					WithField("vpnAddr", target).
					Error("Refusing to CreateRelayRequest for a v1 relay with an ipv6 address")
				return
			}

			b := h.vpnAddrs[0].As4()
			req.OldRelayFromAddr = binary.BigEndian.Uint32(b[:])
			b = target.As4()
			req.OldRelayToAddr = binary.BigEndian.Uint32(b[:])
		} else {
			req.RelayFromAddr = netAddrToProtoAddr(h.vpnAddrs[0])
			req.RelayToAddr = netAddrToProtoAddr(target)
		}

		msg, err := req.Marshal()
		if err != nil {
			logMsg.
				WithError(err).Error("relayManager Failed to marshal Control message to create relay")
		} else {
			f.SendMessageToHostInfo(header.Control, 0, peer, msg, make([]byte, 12), make([]byte, mtu))
			rm.l.WithFields(logrus.Fields{
				"relayFrom":           h.vpnAddrs[0],
				"relayTo":             target,
				"initiatorRelayIndex": req.InitiatorRelayIndex,
				"responderRelayIndex": req.ResponderRelayIndex,
				"vpnAddr":             target}).
				Info("send CreateRelayRequest")
		}

		// Also track the half-created Relay state just received
		_, ok = h.relayState.QueryRelayForByIp(target)
		if !ok {
			_, err := AddRelay(rm.l, h, f.hostMap, target, &m.InitiatorRelayIndex, ForwardingType, PeerRequested)
			if err != nil {
				logMsg.
					WithError(err).Error("relayManager Failed to allocate a local index for relay")
				return
			}
		}
	}
}
