// Package events defines the opt-in firewall event reporting interface.
//
// Nebula emits raw packet-level events (drops, flow creations, flow evictions,
// rule reloads) and does no aggregation, counting, batching, rule-description,
// transport, or timestamping. Embedders correlate events back to yaml rules
// out of band and capture whatever clock they need themselves. All Report*
// methods are invoked while nebula holds internal locks and must be
// non-blocking.
//
// Events are passed to Report* methods by value. Implementations must not
// take the address of a received event: doing so forces Go's escape
// analysis to move the event to the heap and costs one allocation per call.
// To forward an event, either copy its fields into the reporter's own
// pooled record or send it through a value-typed channel (chan DropEvent,
// not chan *DropEvent).
package events

import (
	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/firewall"
)

type DropReason uint8

const (
	DropInvalidLocalIP DropReason = iota
	DropInvalidRemoteIP
	DropPeerRejected
	DropUnknownNetwork
	DropNoMatchingRule
)

func (r DropReason) String() string {
	switch r {
	case DropInvalidLocalIP:
		return "invalid_local_ip"
	case DropInvalidRemoteIP:
		return "invalid_remote_ip"
	case DropPeerRejected:
		return "peer_rejected"
	case DropUnknownNetwork:
		return "unknown_network"
	case DropNoMatchingRule:
		return "no_matching_rule"
	default:
		return "unknown"
	}
}

// DropEvent is emitted for every packet that fails the firewall check. Drops
// are not aggregated; every drop produces one event.
type DropEvent struct {
	Incoming     bool
	Reason       DropReason
	Packet       firewall.Packet
	Context      firewall.PacketContext
	PeerCert     *cert.CachedCertificate
	RulesVersion uint16
}

// FlowCreateEvent is emitted when a packet is allowed and a new conntrack
// entry is created. Subsequent packets in the same flow do not re-emit.
type FlowCreateEvent struct {
	Incoming     bool
	Packet       firewall.Packet
	Context      firewall.PacketContext
	PeerCert     *cert.CachedCertificate
	RulesVersion uint16
}

// FlowEvictEvent is emitted when a conntrack entry is removed. Context is
// not carried: timer-wheel eviction has no packet in hand, and reload
// revalidation evicts the OLD flow rather than the triggering packet.
// RulesVersion is the version under which the flow was originally allowed,
// which may differ from the current firewall version.
type FlowEvictEvent struct {
	Incoming     bool
	Packet       firewall.Packet
	RulesVersion uint16
	// Expired is true when eviction was due to conntrack timeout; false when
	// the entry was removed because it failed re-validation after a reload.
	Expired bool
}

// RulesReloadEvent is emitted once after each successful firewall reload.
// Reporters that bucket state by RulesVersion should close the old bucket
// and open a new one on receipt.
type RulesReloadEvent struct {
	OldVersion uint16
	NewVersion uint16
}

// Reporter is the embedder-supplied sink for firewall events. Implementations
// that want a timestamp should call time.Now() themselves at the top of the
// method; nebula does not provide one. See the package doc for the
// do-not-take-address rule.
type Reporter interface {
	ReportDrop(DropEvent)
	ReportFlowCreate(FlowCreateEvent)
	ReportFlowEvict(FlowEvictEvent)
	ReportRulesReload(RulesReloadEvent)
}
