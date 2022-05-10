package nebula

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/header"
	"github.com/slackhq/nebula/iputil"
)

type relayManager struct {
	l             *logrus.Logger
	hostmap       *HostMap
	relayWheeler  *GenericTimerWheel
	checkInterval time.Duration

	in      map[uint32]struct{}
	inLock  *sync.RWMutex
	out     map[uint32]struct{}
	outLock *sync.RWMutex
}

func NewRelayManager(ctx context.Context, l *logrus.Logger, hostmap *HostMap) *relayManager {
	rm := &relayManager{
		l:             l,
		hostmap:       hostmap,
		relayWheeler:  NewGenericTimerWheel(time.Millisecond*500, time.Second*60),
		checkInterval: 5 * time.Second,
		in:            make(map[uint32]struct{}),
		inLock:        &sync.RWMutex{},
		out:           make(map[uint32]struct{}),
		outLock:       &sync.RWMutex{},
	}
	return rm
}

func (rm *relayManager) In(localIdx uint32) {
	rm.inLock.RLock()
	// If this already exists, return
	if _, ok := rm.in[localIdx]; ok {
		rm.inLock.RUnlock()
		return
	}
	rm.inLock.RUnlock()
	rm.inLock.Lock()
	rm.in[localIdx] = struct{}{}
	rm.inLock.Unlock()
}

// Out is used to indicate some outbound traffic to a relay, tracked by the relay's local index.
// We better see some traffic _in_ over that same relay tunnel, or we're gunna shut it all down.
func (rm *relayManager) Out(localIdx uint32) {
	rm.outLock.RLock()
	// If this already exists, return
	if _, ok := rm.out[localIdx]; ok {
		rm.outLock.RUnlock()
		return
	}
	rm.outLock.RUnlock()
	rm.outLock.Lock()
	// double check since we dropped the lock temporarily
	if _, ok := rm.out[localIdx]; ok {
		rm.outLock.Unlock()
		return
	}
	rm.out[localIdx] = struct{}{}
	rm.outLock.Unlock()
	rm.relayWheeler.Add(localIdx, rm.checkInterval)
}

func (rm *relayManager) CheckIn(localIdx uint32) bool {
	rm.inLock.RLock()
	if _, ok := rm.in[localIdx]; ok {
		rm.inLock.RUnlock()
		return true
	}
	rm.inLock.RUnlock()
	return false
}

func AddRelay(l *logrus.Logger, relayHostInfo *HostInfo, hm *HostMap, vpnIp iputil.VpnIp, remoteIdx *uint32, relayType int) (uint32, error) {
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
			relayHostInfo.relays[vpnIp] = struct{}{}
			newRelay := Relay{
				Type:       relayType,
				State:      Requested,
				LocalIndex: index,
				PeerIp:     vpnIp,
			}

			if remoteIdx != nil {
				newRelay.RemoteIndex = *remoteIdx
			}

			relayHostInfo.relayForByIp[vpnIp] = &newRelay
			relayHostInfo.relayForByIdx[index] = &newRelay

			relayHostInfo.Unlock()
			return index, nil
		}
	}

	return 0, errors.New("failed to generate unique localIndexId")
}

func (rm *relayManager) SetRelay(l *logrus.Logger, relayHostInfo *HostInfo, m *NebulaControl) (*Relay, error) {
	var relay *Relay
	err := func() error {
		relayHostInfo.Lock()
		defer relayHostInfo.Unlock()
		var ok bool
		relay, ok = relayHostInfo.relayForByIdx[m.InitiatorRelayIndex]
		if !ok {
			l.Infof("BRAD: I, HostInfo %v,  don't have host %v in my relayFor map :/", relayHostInfo.vpnIp, iputil.VpnIp(m.RelayFromIp).String())
			return fmt.Errorf("wat")
		}
		relay.RemoteIndex = m.ResponderRelayIndex
		relay.State = Established
		//relayHostInfo.relayForByIp[iputil.VpnIp(m.RelayFromIp)] = relay
		//relayHostInfo.relayForByIdx[m.InitiatorRelayIndex] = relay
		return nil
	}()
	if err != nil {
		return relay, err
	}
	rm.hostmap.Lock()
	defer rm.hostmap.Unlock()
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
	relay, err := rm.SetRelay(rm.l, h, m)
	if err != nil {
		rm.l.Infof("BRAD: Failed to update relay for target %v: %v", target.String(), err)
		return
	}
	// Do I need to complete the relays now?
	if relay.Type == TerminalType {
		return
	}
	// I'm the middle man. Let the initiator know that the I've established the relay they requested.
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
	peerRelay.State = Established
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
		f.SendMessageToVpnIp(header.Control, 0, peerHostInfo.vpnIp, msg, make([]byte, 12), make([]byte, mtu))
	}
}

func (rm *relayManager) handleCreateRelayRequest(h *HostInfo, f *Interface, m *NebulaControl) {
	from := iputil.VpnIp(m.RelayFromIp)
	target := iputil.VpnIp(m.RelayToIp)
	rm.l.Info("BRAD: relayManager CreateRelayReqest from %v to %v", from, target)
	// Is the target of the relay me?
	if target == f.myVpnIp {

		h.RLock()
		_, ok := h.relayForByIp[from]
		h.RUnlock()
		if !ok {
			idx, err := AddRelay(rm.l, h, f.hostMap, from, &m.InitiatorRelayIndex, TerminalType)
			if err != nil {
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
		peer := f.getOrHandshake(target)
		if peer == nil {
			return
		}
		sendCreateRequest := false
		var index uint32
		var err error
		peer.RLock()
		relay, ok := peer.relayForByIp[from]
		peer.RUnlock()
		if ok {
			index = relay.LocalIndex
			if relay.State == Requested {
				sendCreateRequest = true
			}
		} else {
			// Allocate an index in the hostMap for this relay peer
			index, err = AddRelay(rm.l, peer, f.hostMap, from, nil, RelayType)
			if err != nil {
				return
			}
		}
		if sendCreateRequest {
			// Send a CreateRelayRequest to the peer.
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
			// Add the relay
			_, err := AddRelay(rm.l, h, f.hostMap, target, &m.InitiatorRelayIndex, RelayType)
			if err != nil {
				return
			}
		} else {
			switch relay.State {
			case Established:
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

func (rm *relayManager) RemoveRelay(relay *Relay, h *HostInfo) {

	// Clean up HostInfo.relays
	h.Lock()
	// Clean up HostInfo relay object's relayForByIp, relayForByIdx
	delete(h.relayForByIp, relay.PeerIp)
	delete(h.relayForByIdx, relay.LocalIndex)
	h.Unlock()
	// Finally clean up the HostInfo of the peer, to indicate that this relay HostInfo doesn't work anymore
	peerHostInfo, err := rm.hostmap.QueryVpnIp(relay.PeerIp)
	if err != nil {
		rm.l.WithField("vpnIp", h.vpnIp).WithField("peerIp", relay.PeerIp).Info("BRAD: Failed to find peer's HostInfo")
		return
	}
	peerHostInfo.Lock()
	delete(peerHostInfo.relays, h.vpnIp)
	peerHostInfo.Unlock()
}

func (rm *relayManager) handleRemoveRelayRequest(h *HostInfo, f *Interface, m *NebulaControl) {
	// Find the Relay object based on the remote index and host IP that sent the message
	//rm.RemoveRelay(relay, h)
}

func (rm *relayManager) Start(ctx context.Context) {
	go rm.Run(ctx)
}

func (rm *relayManager) AddTrafficWatch(localIdx uint32, seconds int) {
	rm.relayWheeler.Add(localIdx, (time.Duration(seconds) * time.Second))
}

func (rm *relayManager) Run(ctx context.Context) {
	clockSource := time.NewTicker(500 * time.Millisecond)
	defer clockSource.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case now := <-clockSource.C:
			rm.relayWheeler.advance(now)
			rm.HandleMonitorTick(now)
		}
	}
}

func (rm *relayManager) HandleMonitorTick(now time.Time) {
	for {
		ep := rm.relayWheeler.Purge()
		if ep == nil {
			break
		}
		traf := rm.CheckIn(ep.(uint32))
		if traf {
			rm.l.Infof("BRAD: I've received traffic from this relay. Do nothing. %v", ep.(uint32))
		} else {
			rm.l.Infof("BRAD: I've seen no traffic from this relay. PURGE LOCAL IDX %v", ep.(uint32))
		}
	}
}
