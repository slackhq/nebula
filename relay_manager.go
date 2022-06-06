package nebula

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/header"
	"github.com/slackhq/nebula/iputil"
)

type relayManager struct {
	l             *logrus.Logger
	hostmap       *HostMap
	atomicAmRelay int32
}

func NewRelayManager(ctx context.Context, l *logrus.Logger, hostmap *HostMap, c *config.C) *relayManager {
	rm := &relayManager{
		l:       l,
		hostmap: hostmap,
	}
	rm.reload(c, true)
	c.RegisterReloadCallback(func(c *config.C) {
		err := rm.reload(c, false)
		l.WithError(err).Error("Failed to reload relay_manager")
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
	return atomic.LoadInt32(&rm.atomicAmRelay) == 1
}

func (rm *relayManager) setAmRelay(v bool) {
	var val int32
	switch v {
	case true:
		val = 1
	case false:
		val = 0
	}
	atomic.StoreInt32(&rm.atomicAmRelay, val)
}

// AddRelay finds an available relay index on the hostmap, and associates the relay info with it.
// relayHostInfo is the Nebula peer which can be used as a relay to access the target vpnIp.
func AddRelay(l *logrus.Logger, relayHostInfo *HostInfo, hm *HostMap, vpnIp iputil.VpnIp, remoteIdx *uint32, relayType int, state int) (uint32, error) {
	hm.Lock()
	defer hm.Unlock()
	for i := 0; i < 32; i++ {
		index, err := generateIndex(l)
		if err != nil {
			return 0, err
		}

		_, inRelays := hm.Relays[index]
		if !inRelays {
			hm.Relays[index] = relayHostInfo
			newRelay := Relay{
				Type:       relayType,
				State:      state,
				LocalIndex: index,
				PeerIp:     vpnIp,
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

func (rm *relayManager) SetRelay(relayHostInfo *HostInfo, m *NebulaControl) (*Relay, error) {
	relay, ok := relayHostInfo.relayState.QueryRelayForByIdx(m.InitiatorRelayIndex)
	if !ok {
		rm.l.Infof("BRAD: relayManager SetRelay on %v with index %v relayForByIdx not found from %v to %v", relayHostInfo.vpnIp, m.InitiatorRelayIndex, m.RelayFromIp, m.RelayToIp)
		return nil, fmt.Errorf("wat")
	}
	// relay deserves some synchronization
	relay.RemoteIndex = m.ResponderRelayIndex
	relay.State = Established

	return relay, nil
}

func (rm *relayManager) HandleControlMsg(h *HostInfo, m *NebulaControl, f *Interface) {

	switch m.Type {
	case NebulaControl_CreateRelayRequest:
		rm.handleCreateRelayRequest(h, f, m)
	case NebulaControl_CreateRelayResponse:
		rm.handleCreateRelayResponse(h, f, m)
	case NebulaControl_RemoveRelayRequest:
		rm.handleRemoveRelayRequest(h, f, m)
	}

}

func (rm *relayManager) handleCreateRelayResponse(h *HostInfo, f *Interface, m *NebulaControl) {
	target := iputil.VpnIp(m.RelayToIp)

	relay, err := rm.SetRelay(h, m)
	if err != nil {
		rm.l.WithError(err).Errorf("Failed to update relay for target %v: %v", target.String(), err)
		return
	}
	// Do I need to complete the relays now?
	if relay.Type == TerminalType {
		return
	}
	// I'm the middle man. Let the initiator know that the I've established the relay they requested.
	peerHostInfo, err := rm.hostmap.QueryVpnIp(relay.PeerIp)
	if err != nil {
		rm.l.WithError(err).Errorf("Can't find a HostInfo for peer IP %v", relay.PeerIp.String())
		return
	}
	peerRelay, ok := peerHostInfo.relayState.QueryRelayForByIp(target)
	if !ok {
		rm.l.Errorf("peerRelay %v does not have Relay state for %v", peerHostInfo.vpnIp.String(), target.String())
		return
	}
	peerRelay.State = Established
	resp := NebulaControl{
		Type:                NebulaControl_CreateRelayResponse,
		ResponderRelayIndex: peerRelay.LocalIndex,
		InitiatorRelayIndex: peerRelay.RemoteIndex,
		RelayFromIp:         uint32(peerHostInfo.vpnIp),
		RelayToIp:           uint32(target),
	}
	msg, err := resp.Marshal()
	if err != nil {
		rm.l.
			WithError(err).Error("relayManager Failed to marhsal Control CreateRelayResponse message to create relay")
	} else {
		f.SendMessageToVpnIp(header.Control, 0, peerHostInfo.vpnIp, msg, make([]byte, 12), make([]byte, mtu))
	}
}

func (rm *relayManager) handleCreateRelayRequest(h *HostInfo, f *Interface, m *NebulaControl) {
	from := iputil.VpnIp(m.RelayFromIp)
	target := iputil.VpnIp(m.RelayToIp)
	// Is the target of the relay me?
	if target == f.myVpnIp {
		existingRelay, ok := h.relayState.QueryRelayForByIp(from)
		addRelay := !ok
		if ok {
			// Clean up existing relay, if this is a new request.
			if existingRelay.RemoteIndex != m.InitiatorRelayIndex {
				// We got a brand new Relay request, because its index is different than what we saw before.
				// Clean up the existing Relay state, and get ready to record new Relay state.
				rm.hostmap.RemoveRelay(existingRelay.LocalIndex)
				addRelay = true
			}
		}
		if addRelay {
			_, err := AddRelay(rm.l, h, f.hostMap, from, &m.InitiatorRelayIndex, TerminalType, Requested)
			if err != nil {
				return
			}
		}

		relay, ok := h.relayState.QueryRelayForByIp(from)
		if ok && m.InitiatorRelayIndex != relay.RemoteIndex {
			// Do something, Something happened.
		}

		resp := NebulaControl{
			Type:                NebulaControl_CreateRelayResponse,
			ResponderRelayIndex: relay.LocalIndex,
			InitiatorRelayIndex: relay.RemoteIndex,
			RelayFromIp:         uint32(from),
			RelayToIp:           uint32(target),
		}
		msg, err := resp.Marshal()
		if err != nil {
			rm.l.
				WithError(err).Error("relayManager Failed to marshal Control CreateRelayResponse message to create relay")
		} else {
			f.SendMessageToVpnIp(header.Control, 0, h.vpnIp, msg, make([]byte, 12), make([]byte, mtu))
		}
		return
	} else {
		if rm.GetAmRelay() == false {
			return
		}
		// the target is not me. Create a relay to the target, from me.
		peer, err := rm.hostmap.QueryVpnIp(target)
		if err != nil {
			// Try to establish a connection to this host. If we get a future relay request,
			// we'll be ready!
			f.getOrHandshake(target)
			return
		}
		if peer.remote == nil {
			// Only create relays to peers for whom I have a direct connection
			return
		}
		sendCreateRequest := false
		var index uint32
		targetRelay, ok := peer.relayState.QueryRelayForByIp(from)
		if ok {
			index = targetRelay.LocalIndex
			if targetRelay.State == Requested {
				sendCreateRequest = true
			}
		} else {
			// Allocate an index in the hostMap for this relay peer
			index, err = AddRelay(rm.l, peer, f.hostMap, from, nil, RelayType, Requested)
			if err != nil {
				return
			}
			sendCreateRequest = true
		}
		if sendCreateRequest {
			// Send a CreateRelayRequest to the peer.
			req := NebulaControl{
				Type:                NebulaControl_CreateRelayRequest,
				InitiatorRelayIndex: index,
				RelayFromIp:         uint32(h.vpnIp),
				RelayToIp:           uint32(target),
			}
			msg, err := req.Marshal()
			if err != nil {
				rm.l.
					WithError(err).Error("relayManager Failed to marshal Control message to create relay")
			} else {
				f.SendMessageToVpnIp(header.Control, 0, target, msg, make([]byte, 12), make([]byte, mtu))
			}
		}
		// Also track the half-created Relay state just received
		relay, ok := h.relayState.QueryRelayForByIp(target)
		if !ok {
			// Add the relay
			state := Requested
			if targetRelay != nil && targetRelay.State == Established {

				state = Established
			}
			_, err := AddRelay(rm.l, h, f.hostMap, target, &m.InitiatorRelayIndex, RelayType, state)
			if err != nil {
				return
			}
		} else {
			if relay.RemoteIndex != m.InitiatorRelayIndex {
				// This is a stale Relay entry for the same tunnel targets.
				// Clean up the existing stuff.
				rm.RemoveRelay(relay.LocalIndex)
				// Add the new relay
				_, err := AddRelay(rm.l, h, f.hostMap, target, &m.InitiatorRelayIndex, RelayType, Requested)
				if err != nil {
					return
				}
			}
			switch relay.State {
			case Established:
				resp := NebulaControl{
					Type:                NebulaControl_CreateRelayResponse,
					ResponderRelayIndex: relay.LocalIndex,
					InitiatorRelayIndex: relay.RemoteIndex,
					RelayFromIp:         uint32(h.vpnIp),
					RelayToIp:           uint32(target),
				}
				msg, err := resp.Marshal()
				if err != nil {
					rm.l.
						WithError(err).Error("relayManager Failed to marshal Control CreateRelayResponse message to create relay")
				} else {
					f.SendMessageToVpnIp(header.Control, 0, h.vpnIp, msg, make([]byte, 12), make([]byte, mtu))
				}

			case Requested:
				// Keep waiting for the other relay to complete
			}
		}
	}
}

func (rm *relayManager) RemoveRelay(localIdx uint32) {
	rm.hostmap.RemoveRelay(localIdx)
}

func (rm *relayManager) handleRemoveRelayRequest(h *HostInfo, f *Interface, m *NebulaControl) {
	// Find the Relay object based on the remote index and host IP that sent the message
	//rm.RemoveRelay(relay, h)
}
