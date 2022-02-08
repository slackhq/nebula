package nebula

import (
	"context"
	"errors"
	"fmt"

	"github.com/golang/protobuf/proto"
	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/header"
	"github.com/slackhq/nebula/iputil"
)

type relayManager struct {
	l       *logrus.Logger
	hostmap *HostMap
}

func NewRelayManager(ctx context.Context, l *logrus.Logger, hostmap *HostMap) *relayManager {
	l.Info("BRAD: NewRelayManager")
	rm := &relayManager{
		l:       l,
		hostmap: hostmap,
	}
	return rm
}

func AddRelay(l *logrus.Logger, relayHostInfo *HostInfo, hm *HostMap, vpnIp iputil.VpnIp, remoteIdx *uint32, relayType int) (uint32, error) {
	l.Infof("BRAD: AddRelay for HostInfo %v and peerIp %v!", relayHostInfo.vpnIp.String(), vpnIp)
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
			relayHostInfo.Lock()
			relayHostInfo.relays[index] = vpnIp
			newRelay := Relay{
				Type:       relayType,
				State:      Requested,
				LocalIndex: index,
				PeerIp:     vpnIp,
			}

			if remoteIdx != nil {
				l.Infof("BRAD: Set the relay's RemoteIndex appropriately %v", *remoteIdx)
				newRelay.RemoteIndex = *remoteIdx
			}

			relayHostInfo.relayForByIp[vpnIp] = &newRelay
			relayHostInfo.relayForByIdx[index] = &newRelay

			relayHostInfo.Unlock()
			l.Infof("BRAD: Generated Relay Index %v", index)
			return index, nil
		}
	}

	return 0, errors.New("failed to generate unique localIndexId")
}

func (rm *relayManager) SetRelay(l *logrus.Logger, relayHostInfo *HostInfo, m *NebulaControl) (*Relay, error) {
	l.Infof("BRAD: SetRelay on HostInfo %v, RelayFromIp=%v RelayToIp=%v InitiatorIdx=%v ResponderIdx=%v",
		relayHostInfo.vpnIp.String(), iputil.VpnIp(m.RelayFromIp).String(), iputil.VpnIp(m.RelayToIp).String(),
		m.InitiatorRelayIndex, m.ResponderRelayIndex)
	relayHostInfo.Lock()
	defer relayHostInfo.Unlock()
	relay, ok := relayHostInfo.relayForByIdx[m.InitiatorRelayIndex]
	if !ok {
		l.Infof("BRAD: I, HostInfo %v,  don't have host %v in my relayFor map :/", relayHostInfo.vpnIp, iputil.VpnIp(m.RelayFromIp).String())
		return &Relay{}, fmt.Errorf("wat")
	}
	relay.RemoteIndex = m.ResponderRelayIndex
	l.Infof("BRAD: Set relay.State=ESTABLISHED for Relay %v Peer %v", relayHostInfo.vpnIp.String(), relay.PeerIp.String())
	relay.State = Established
	//relayHostInfo.relayForByIp[iputil.VpnIp(m.RelayFromIp)] = relay
	//relayHostInfo.relayForByIdx[m.InitiatorRelayIndex] = relay

	l.Info("BRAD: Relay state updated.")
	return relay, nil
}

func (rm *relayManager) HandleControlMsg(h *HostInfo, m *NebulaControl, f *Interface) {

	switch m.Type {
	case NebulaControl_CreateRelayRequest:
		rm.handleCreateRelayRequest(h, f, m)
	case NebulaControl_CreateRelayResponse:
		rm.handleCreateRelayResponse(h, f, m)
	}

}

func (rm *relayManager) handleCreateRelayResponse(h *HostInfo, f *Interface, m *NebulaControl) {
	from := iputil.VpnIp(m.RelayFromIp)
	target := iputil.VpnIp(m.RelayToIp)
	rm.l.Infof("BRAD: Got a CreateRelayResponse from %v for from %v to %v. Woot!", h.vpnIp.String(), from.String(), target.String())
	relay, err := rm.SetRelay(rm.l, h, m)
	if err != nil {
		rm.l.Infof("BRAD: Failed to update relay for target %v: %v", target.String(), err)
		return
	}
	// Do I need to complete the relays now?
	if relay.Type == TerminalType {
		rm.l.Infof("BRAD: Terminal relay type, no need to look for another relay.")
		return
	}
	rm.l.Infof("BRAD: Look up relay PeerIP %v's HostInfo, peerHostInfo.", relay.PeerIp.String())
	peerHostInfo, err := rm.hostmap.QueryVpnIp(relay.PeerIp)
	if err != nil {
		rm.l.Infof("BRAD: I didn't find a HostInfo for peer IP %v", relay.PeerIp.String())
		return
	}
	peerHostInfo.RLock()
	peerRelay, ok := peerHostInfo.relayForByIp[target]
	peerHostInfo.RUnlock()
	if !ok {
		rm.l.Infof("BRAD: peerRelay %v does not have Relay state for %v", peerHostInfo.vpnIp.String(), target.String())
		return
	}
	rm.l.Infof("BRAD: Set the Relay state ESTABLISHED for the initial Relay requester %v!", peerRelay)
	peerRelay.State = Established
	rm.l.Infof("BRAD: send CreateRelayResponse initIdx=%v respIdx=%v relayFromIp=%v relayToIp=%v peerHostInfo=%v.",
		peerRelay.RemoteIndex, peerRelay.LocalIndex, peerHostInfo.vpnIp.String(), target.String(), peerHostInfo.vpnIp.String())
	resp := NebulaControl{
		Type:                NebulaControl_CreateRelayResponse,
		ResponderRelayIndex: peerRelay.LocalIndex,
		InitiatorRelayIndex: peerRelay.RemoteIndex,
		RelayFromIp:         uint32(peerHostInfo.vpnIp),
		RelayToIp:           uint32(target),
	}
	msg, err := proto.Marshal(&resp)
	if err != nil {
		rm.l.
			WithError(err).Error("BRAD: relayManager Failed to send Control CreateRelayResponse message to create relay")
	} else {
		rm.l.Infof("BRAD: Send CreateRelayResponse to %v", peerHostInfo.vpnIp)
		f.SendMessageToVpnIp(header.Control, 0, peerHostInfo.vpnIp, msg, make([]byte, 12), make([]byte, mtu))
	}
}

func (rm *relayManager) handleCreateRelayRequest(h *HostInfo, f *Interface, m *NebulaControl) {
	from := iputil.VpnIp(m.RelayFromIp)
	target := iputil.VpnIp(m.RelayToIp)
	f.l.Infof("BRAD: handleCreateRelay me=%v createRelay CB from %v for src %v to target %v", f.myVpnIp.String(), h.vpnIp.String(), from.String(), target.String())
	// Is the target of the relay me?
	if target == f.myVpnIp {
		f.l.Info("BRAD: I am the target of this relay. Yay!")

		h.RLock()
		_, ok := h.relayForByIp[from]
		h.RUnlock()
		if ok {
			rm.l.Infof("BRAD: I searched the relay HostInfo for IP %v, and got a hit.", from.String())
		}
		if !ok {
			rm.l.Infof("BRAD: Create a new Relay state thing for HostInfo %v PeerIP=%v from=%v target=%v", h.vpnIp.String(), from.String(), from.String(), target.String())
			idx, err := AddRelay(rm.l, h, f.hostMap, from, &m.InitiatorRelayIndex, TerminalType)
			if err != nil {
				rm.l.WithError(err).Warn("BRAD: Failed to generate an index for this relay. Oops.")
				return
			}
			h.AddRelay(idx, from)
		}

		h.RLock()
		relay := h.relayForByIp[from]
		h.RUnlock()
		if m.InitiatorRelayIndex != relay.RemoteIndex {
			// Do something, Something happened.
		}

		rm.l.Infof("BRAD: Generate a CreateRelayResponse for %v. ResponderIdx=%v InitIdx=%v, FromIP=%v, ToIp=%v",
			h.vpnIp.String(), relay.LocalIndex, relay.RemoteIndex, h.vpnIp.String(), target.String())
		resp := NebulaControl{
			Type:                NebulaControl_CreateRelayResponse,
			ResponderRelayIndex: relay.LocalIndex,
			InitiatorRelayIndex: relay.RemoteIndex,
			RelayFromIp:         uint32(from),
			RelayToIp:           uint32(target),
		}
		msg, err := proto.Marshal(&resp)
		if err != nil {
			rm.l.
				WithError(err).Error("BRAD: relayManager Failed to send Control CreateRelayResponse message to create relay")
		} else {
			f.SendMessageToVpnIp(header.Control, 0, h.vpnIp, msg, make([]byte, 12), make([]byte, mtu))
		}
		return
	} else {
		// the target is not me. Create a relay to the target, from me.
		f.l.Infof("BRAD: I am not the target of this relay. Attempt to create relay for target %v", target.String())
		peer, err := f.hostMap.QueryVpnIp(target)
		if err != nil {
			rm.l.WithError(err).Error("BRAD: I do not have a tunnel to the peer :/")
			return
		}
		sendCreateRequest := false
		var index uint32
		peer.RLock()
		relay, ok := peer.relayForByIp[from]
		peer.RUnlock()
		if ok {
			index = relay.LocalIndex
			rm.l.Infof("BRAD: I searched the relay HostInfo for IP %v, and found existing state with index %v, state %v.", target.String(), index, relay.State)
			if relay.State == Requested {
				sendCreateRequest = true
			}
		} else {
			rm.l.Infof("BRAD: I searched the relay HostInfo for IP %v, but didn't find anything.", target.String())
			// Allocate an index in the hostMap for this relay peer
			rm.l.Infof("BRAD: Create a new Relay state thing for HostInfo %v PeerIp=%v from=%v target=%v", peer.vpnIp.String(), from.String(), from.String(), target.String())
			index, err = AddRelay(rm.l, peer, f.hostMap, from, nil, RelayType)
			if err != nil {
				rm.l.WithError(err).Error("BRAD: I was unable to create an index.")
				return
			}
			rm.l.Infof("BRAD: Added new state to the Relay thing, with index %v", index)
		}
		if sendCreateRequest {
			// Send a CreateRelayRequest to the peer.
			rm.l.Infof("BRAD: Send CreateRelayRequest with initiator Index %v to %v", index, target.String())
			req := NebulaControl{
				Type:                NebulaControl_CreateRelayRequest,
				InitiatorRelayIndex: index,
				RelayFromIp:         uint32(h.vpnIp),
				RelayToIp:           uint32(target),
			}
			msg, err := proto.Marshal(&req)
			if err != nil {
				rm.l.
					WithError(err).Error("BRAD: relayManager Failed to send Control message to create relay")
			} else {
				f.SendMessageToVpnIp(header.Control, 0, target, msg, make([]byte, 12), make([]byte, mtu))
			}
		}
		// Also track the half-created Relay state just received
		h.RLock()
		relay, ok = h.relayForByIp[target]
		h.RUnlock()
		if !ok {
			rm.l.Infof("BRAD: Create relay state on host info %v for peerIp %v", h.vpnIp.String(), target.String())
			// Add the relay
			_, err := AddRelay(rm.l, h, f.hostMap, target, &m.InitiatorRelayIndex, RelayType)
			if err != nil {
				rm.l.Infof("BRAD: Failed to AddRelay on RelayRequest: %v", err)
				return
			}
		} else {
			rm.l.Infof("BRAD: Already tracking Relay object on host info %v for target %v, state=%v", h.vpnIp, target, relay.State)
			switch relay.State {
			case Established:
				rm.l.Info("BRAD: Send a RelayCreatedResponse.")
				resp := NebulaControl{
					Type:                NebulaControl_CreateRelayResponse,
					ResponderRelayIndex: relay.LocalIndex,
					InitiatorRelayIndex: relay.RemoteIndex,
					RelayFromIp:         uint32(h.vpnIp),
					RelayToIp:           uint32(target),
				}
				msg, err := proto.Marshal(&resp)
				if err != nil {
					rm.l.
						WithError(err).Error("BRAD: relayManager Failed to send Control CreateRelayResponse message to create relay")
				} else {
					rm.l.Infof("BRAD: Send CreateRelayResponse to %v", h.vpnIp)
					f.SendMessageToVpnIp(header.Control, 0, h.vpnIp, msg, make([]byte, 12), make([]byte, mtu))
				}

			case Requested:
				rm.l.Info("BRAD: Relay object not yet ESTABLISHED. I've re-sent the request to the peer. Keep waiting for the reply.")
			}
		}
	}
	// Queue up a retry request
	//rm.workManager.Add(func() { rm.handleCreateRelay(h, f, target) }, 500*time.Millisecond)
}

/*
func (rm *relayManager) AddRelayIndexHostInfo(h *HostInfo) error {
	c.pendingHostMap.Lock()
	defer c.pendingHostMap.Unlock()
	c.mainHostMap.RLock()
	defer c.mainHostMap.RUnlock()

	for i := 0; i < 32; i++ {
		index, err := generateIndex(rm.l)
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
func (rm *relayManager) Start(ctx context.Context) {
	go rm.Run(ctx)
}

func (rm *relayManager) Run(ctx context.Context) {
	clockSource := time.NewTicker(500 * time.Millisecond)
	defer clockSource.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case now := <-clockSource.C:
			rm.workManager.advance(now)
			rm.HandleMonitorTick(now)
		}
	}
}

func (rm *relayManager) HandleMonitorTick(now time.Time) {
	for {
		ep := rm.workManager.Purge()
		if ep == nil {
			break
		}
		ep.(func())()
	}
}

*/
