package nebula

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sync/atomic"

	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/header"
)

type relayManager struct {
	l         *slog.Logger
	hostmap   *HostMap
	amRelay   atomic.Bool
	useRelays atomic.Bool
}

func NewRelayManager(ctx context.Context, l *slog.Logger, hostmap *HostMap, c *config.C) *relayManager {
	rm := &relayManager{
		l:       l,
		hostmap: hostmap,
	}
	rm.reload(c, true)
	c.RegisterReloadCallback(func(c *config.C) {
		err := rm.reload(c, false)
		if err != nil {
			rm.l.Error("Failed to reload relay_manager", "error", err)
		}
	})
	return rm
}

func (rm *relayManager) reload(c *config.C, initial bool) error {
	if initial || c.HasChanged("relay.am_relay") || c.HasChanged("relay.use_relays") {
		amRelay := c.GetBool("relay.am_relay", false)
		rm.amRelay.Store(amRelay)
		rm.useRelays.Store(c.GetBool("relay.use_relays", true) && !amRelay)
	}
	return nil
}

func (rm *relayManager) GetAmRelay() bool {
	return rm.amRelay.Load()
}

func (rm *relayManager) GetUseRelays() bool {
	return rm.useRelays.Load()
}

// StartRelays drives the relay-establishment side of an outbound handshake attempt.
// For each candidate relay it either kicks off a handshake to the relay, sends a CreateRelayRequest, retransmits
// one that may have been lost, or, once the relay is Established, forwards the in-progress
// stage 0 handshake packet for vpnIp through it.
func (rm *relayManager) StartRelays(f *Interface, vpnIp netip.Addr, hostinfo *HostInfo, stage0 []byte) {
	if !rm.GetUseRelays() || len(hostinfo.remotes.relays) == 0 {
		return
	}

	hostinfo.logger(rm.l).Info("Attempt to relay through hosts", "relays", hostinfo.remotes.relays)
	// Send a RelayRequest to all known Relay IP's
	for _, relay := range hostinfo.remotes.relays {
		// Don't relay through the host I'm trying to connect to
		if relay == vpnIp {
			continue
		}

		// Don't relay to myself
		if f.myVpnAddrsTable.Contains(relay) {
			continue
		}

		relayHostInfo := rm.hostmap.QueryVpnAddr(relay)
		if relayHostInfo == nil || !relayHostInfo.remote.IsValid() {
			hostinfo.logger(rm.l).Info("Establish tunnel to relay target", "relay", relay.String())
			f.Handshake(relay)
			continue
		}
		// Check the relay HostInfo to see if we already established a relay through
		existingRelay, ok := relayHostInfo.relayState.QueryRelayForByIp(vpnIp)
		if !ok {
			// No relays exist or requested yet.
			if relayHostInfo.remote.IsValid() {
				idx, err := AddRelay(rm.l, relayHostInfo, rm.hostmap, vpnIp, nil, TerminalType, Requested)
				if err != nil {
					hostinfo.logger(rm.l).Info("Failed to add relay to hostmap", "relay", relay.String(), "error", err)
				}

				m := NebulaControl{
					Type:                NebulaControl_CreateRelayRequest,
					InitiatorRelayIndex: idx,
				}

				switch relayHostInfo.GetCert().Certificate.Version() {
				case cert.Version1:
					if !f.myVpnAddrs[0].Is4() {
						hostinfo.logger(rm.l).Error("can not establish v1 relay with a v6 network because the relay is not running a current nebula version")
						continue
					}

					if !vpnIp.Is4() {
						hostinfo.logger(rm.l).Error("can not establish v1 relay with a v6 remote network because the relay is not running a current nebula version")
						continue
					}

					b := f.myVpnAddrs[0].As4()
					m.OldRelayFromAddr = binary.BigEndian.Uint32(b[:])
					b = vpnIp.As4()
					m.OldRelayToAddr = binary.BigEndian.Uint32(b[:])
				case cert.Version2:
					m.RelayFromAddr = netAddrToProtoAddr(f.myVpnAddrs[0])
					m.RelayToAddr = netAddrToProtoAddr(vpnIp)
				default:
					hostinfo.logger(rm.l).Error("Unknown certificate version found while creating relay")
					continue
				}

				msg, err := m.Marshal()
				if err != nil {
					hostinfo.logger(rm.l).Error("Failed to marshal Control message to create relay", "error", err)
				} else {
					f.SendMessageToHostInfo(header.Control, 0, relayHostInfo, msg, make([]byte, 12), make([]byte, mtu))
					rm.l.Info("send CreateRelayRequest",
						"relayFrom", f.myVpnAddrs[0],
						"relayTo", vpnIp,
						"initiatorRelayIndex", idx,
						"relay", relay,
					)
				}
			}
			continue
		}

		switch existingRelay.State {
		case Established:
			hostinfo.logger(rm.l).Info("Send handshake via relay", "relay", relay.String())
			f.SendVia(relayHostInfo, existingRelay, stage0, make([]byte, 12), make([]byte, mtu), false)
		case Disestablished:
			// Mark this relay as 'requested'
			relayHostInfo.relayState.UpdateRelayForByIpState(vpnIp, Requested)
			fallthrough
		case Requested:
			hostinfo.logger(rm.l).Info("Re-send CreateRelay request", "relay", relay.String())
			// Re-send the CreateRelay request, in case the previous one was lost.
			m := NebulaControl{
				Type:                NebulaControl_CreateRelayRequest,
				InitiatorRelayIndex: existingRelay.LocalIndex,
			}

			switch relayHostInfo.GetCert().Certificate.Version() {
			case cert.Version1:
				if !f.myVpnAddrs[0].Is4() {
					hostinfo.logger(rm.l).Error("can not establish v1 relay with a v6 network because the relay is not running a current nebula version")
					continue
				}

				if !vpnIp.Is4() {
					hostinfo.logger(rm.l).Error("can not establish v1 relay with a v6 remote network because the relay is not running a current nebula version")
					continue
				}

				b := f.myVpnAddrs[0].As4()
				m.OldRelayFromAddr = binary.BigEndian.Uint32(b[:])
				b = vpnIp.As4()
				m.OldRelayToAddr = binary.BigEndian.Uint32(b[:])
			case cert.Version2:
				m.RelayFromAddr = netAddrToProtoAddr(f.myVpnAddrs[0])
				m.RelayToAddr = netAddrToProtoAddr(vpnIp)
			default:
				hostinfo.logger(rm.l).Error("Unknown certificate version found while creating relay")
				continue
			}
			msg, err := m.Marshal()
			if err != nil {
				hostinfo.logger(rm.l).Error("Failed to marshal Control message to create relay", "error", err)
			} else {
				// This must send over the hostinfo, not over hm.Hosts[ip]
				f.SendMessageToHostInfo(header.Control, 0, relayHostInfo, msg, make([]byte, 12), make([]byte, mtu))
				rm.l.Info("send CreateRelayRequest",
					"relayFrom", f.myVpnAddrs[0],
					"relayTo", vpnIp,
					"initiatorRelayIndex", existingRelay.LocalIndex,
					"relay", relay,
				)
			}
		case PeerRequested:
			// PeerRequested only occurs in Forwarding relays, not Terminal relays, and this is a Terminal relay case.
			fallthrough
		default:
			hostinfo.logger(rm.l).Error("Relay unexpected state",
				"vpnIp", vpnIp,
				"state", existingRelay.State,
				"relay", relay,
			)

		}
	}
}

// AddRelay finds an available relay index on the hostmap, and associates the relay info with it.
// relayHostInfo is the Nebula peer which can be used as a relay to access the target vpnIp.
func AddRelay(l *slog.Logger, relayHostInfo *HostInfo, hm *HostMap, vpnIp netip.Addr, remoteIdx *uint32, relayType int, state int) (uint32, error) {
	hm.Lock()
	defer hm.Unlock()
	for range 32 {
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
		var relayFrom, relayTo any
		if m.RelayFromAddr == nil {
			relayFrom = m.OldRelayFromAddr
		} else {
			relayFrom = m.RelayFromAddr
		}
		if m.RelayToAddr == nil {
			relayTo = m.OldRelayToAddr
		} else {
			relayTo = m.RelayToAddr
		}

		rm.l.Info("relayManager failed to update relay",
			"relay", relayHostInfo.vpnAddrs[0],
			"initiatorRelayIndex", m.InitiatorRelayIndex,
			"relayFrom", relayFrom,
			"relayTo", relayTo,
		)
		return nil, fmt.Errorf("unknown relay")
	}

	return relay, nil
}

func (rm *relayManager) HandleControlMsg(h *HostInfo, d []byte, f *Interface) {
	msg := &NebulaControl{}
	err := msg.Unmarshal(d)
	if err != nil {
		h.logger(f.l).Error("Failed to unmarshal control message", "error", err)
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
	rm.l.Info("handleCreateRelayResponse",
		"relayFrom", protoAddrToNetAddr(m.RelayFromAddr),
		"relayTo", protoAddrToNetAddr(m.RelayToAddr),
		"initiatorRelayIndex", m.InitiatorRelayIndex,
		"responderRelayIndex", m.ResponderRelayIndex,
		"vpnAddrs", h.vpnAddrs,
	)

	target := m.RelayToAddr
	targetAddr := protoAddrToNetAddr(target)

	relay, err := rm.EstablishRelay(h, m)
	if err != nil {
		rm.l.Error("Failed to update relay for relayTo", "error", err)
		return
	}
	// Do I need to complete the relays now?
	if relay.Type == TerminalType {
		return
	}
	// I'm the middle man. Let the initiator know that the I've established the relay they requested.
	peerHostInfo := rm.hostmap.QueryVpnAddr(relay.PeerAddr)
	if peerHostInfo == nil {
		rm.l.Error("Can't find a HostInfo for peer", "relayTo", relay.PeerAddr)
		return
	}
	peerRelay, ok := peerHostInfo.relayState.QueryRelayForByIp(targetAddr)
	if !ok {
		rm.l.Error("peerRelay does not have Relay state for relayTo", "relayTo", peerHostInfo.vpnAddrs[0])
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
				rm.l.Error("Refusing to CreateRelayResponse for a v1 relay with an ipv6 address",
					"relayFrom", peer,
					"relayTo", target,
					"initiatorRelayIndex", resp.InitiatorRelayIndex,
					"responderRelayIndex", resp.ResponderRelayIndex,
					"vpnAddrs", peerHostInfo.vpnAddrs,
				)
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
			rm.l.Error("relayManager Failed to marshal Control CreateRelayResponse message to create relay", "error", err)
		} else {
			f.SendMessageToHostInfo(header.Control, 0, peerHostInfo, msg, make([]byte, 12), make([]byte, mtu))
			rm.l.Info("send CreateRelayResponse",
				"relayFrom", resp.RelayFromAddr,
				"relayTo", resp.RelayToAddr,
				"initiatorRelayIndex", resp.InitiatorRelayIndex,
				"responderRelayIndex", resp.ResponderRelayIndex,
				"vpnAddrs", peerHostInfo.vpnAddrs,
			)
		}
	}
}

func (rm *relayManager) handleCreateRelayRequest(v cert.Version, h *HostInfo, f *Interface, m *NebulaControl) {
	from := protoAddrToNetAddr(m.RelayFromAddr)
	target := protoAddrToNetAddr(m.RelayToAddr)

	logMsg := rm.l.With(
		"relayFrom", from,
		"relayTo", target,
		"initiatorRelayIndex", m.InitiatorRelayIndex,
		"vpnAddrs", h.vpnAddrs,
	)

	logMsg.Info("handleCreateRelayRequest")
	// Is the source of the relay me? This should never happen, but did happen due to
	// an issue migrating relays over to newly re-handshaked host info objects.
	if f.myVpnAddrsTable.Contains(from) {
		logMsg.Error("Discarding relay request from myself", "myIP", from)
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
					logMsg.Error("Existing relay mismatch with CreateRelayRequest",
						"existingRemoteIndex", existingRelay.RemoteIndex)
					return
				}
			case Disestablished:
				if existingRelay.RemoteIndex != m.InitiatorRelayIndex {
					// We got a brand new Relay request, because its index is different than what we saw before.
					// This should never happen. The peer should never change an index, once created.
					logMsg.Error("Existing relay mismatch with CreateRelayRequest",
						"existingRemoteIndex", existingRelay.RemoteIndex)
					return
				}
				// Mark the relay as 'Established' because it's safe to use again
				h.relayState.UpdateRelayForByIpState(from, Established)
			case PeerRequested:
				// I should never be in this state, because I am terminal, not forwarding.
				logMsg.Error("Unexpected Relay State found",
					"existingRemoteIndex", existingRelay.RemoteIndex,
					"state", existingRelay.State)
			}
		} else {
			_, err := AddRelay(rm.l, h, f.hostMap, from, &m.InitiatorRelayIndex, TerminalType, Established)
			if err != nil {
				logMsg.Error("Failed to add relay", "error", err)
				return
			}
		}

		relay, ok := h.relayState.QueryRelayForByIp(from)
		if !ok {
			logMsg.Error("Relay State not found", "from", from)
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
			logMsg.Error("relayManager Failed to marshal Control CreateRelayResponse message to create relay", "error", err)
		} else {
			f.SendMessageToHostInfo(header.Control, 0, h, msg, make([]byte, 12), make([]byte, mtu))
			rm.l.Info("send CreateRelayResponse",
				"relayFrom", from,
				"relayTo", target,
				"initiatorRelayIndex", resp.InitiatorRelayIndex,
				"responderRelayIndex", resp.ResponderRelayIndex,
				"vpnAddrs", h.vpnAddrs,
			)
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
				rm.l.Error("Refusing to CreateRelayRequest for a v1 relay with an ipv6 address",
					"relayFrom", h.vpnAddrs[0],
					"relayTo", target,
					"initiatorRelayIndex", req.InitiatorRelayIndex,
					"responderRelayIndex", req.ResponderRelayIndex,
					"vpnAddr", target,
				)
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
			logMsg.Error("relayManager Failed to marshal Control message to create relay", "error", err)
		} else {
			f.SendMessageToHostInfo(header.Control, 0, peer, msg, make([]byte, 12), make([]byte, mtu))
			rm.l.Info("send CreateRelayRequest",
				"relayFrom", h.vpnAddrs[0],
				"relayTo", target,
				"initiatorRelayIndex", req.InitiatorRelayIndex,
				"responderRelayIndex", req.ResponderRelayIndex,
				"vpnAddr", target,
			)
		}

		// Also track the half-created Relay state just received
		_, ok = h.relayState.QueryRelayForByIp(target)
		if !ok {
			_, err := AddRelay(rm.l, h, f.hostMap, target, &m.InitiatorRelayIndex, ForwardingType, PeerRequested)
			if err != nil {
				logMsg.Error("relayManager Failed to allocate a local index for relay", "error", err)
				return
			}
		}
	}
}
