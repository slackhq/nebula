package nebula

import (
	"fmt"

	"github.com/rcrowley/go-metrics"
	"github.com/slackhq/nebula/header"
)

type MessageMetrics struct {
	rx [][]metrics.Counter
	tx [][]metrics.Counter

	rxUnknown metrics.Counter
	txUnknown metrics.Counter

	rxInvalid   metrics.Counter
	txExhausted metrics.Counter
}

func (m *MessageMetrics) Rx(t header.MessageType, s header.MessageSubType, i int64) {
	if m != nil {
		if t >= 0 && int(t) < len(m.rx) && s >= 0 && int(s) < len(m.rx[t]) && m.rx[t][s] != nil {
			m.rx[t][s].Inc(i)
		} else if m.rxUnknown != nil {
			m.rxUnknown.Inc(i)
		}
	}
}
func (m *MessageMetrics) Tx(t header.MessageType, s header.MessageSubType, i int64) {
	if m != nil {
		if t >= 0 && int(t) < len(m.tx) && s >= 0 && int(s) < len(m.tx[t]) && m.tx[t][s] != nil {
			m.tx[t][s].Inc(i)
		} else if m.txUnknown != nil {
			m.txUnknown.Inc(i)
		}
	}
}
func (m *MessageMetrics) RxInvalid(i int64) {
	if m != nil && m.rxInvalid != nil {
		m.rxInvalid.Inc(i)
	}
}

// TxExhausted counts outbound packets dropped because the tunnel's message counter is spent.
func (m *MessageMetrics) TxExhausted(i int64) {
	if m != nil && m.txExhausted != nil {
		m.txExhausted.Inc(i)
	}
}

func newMessageMetrics() *MessageMetrics {
	gen := func(t string) [][]metrics.Counter {
		// Handshake subtypes are sparse: the fragmented ones sit at 0x80 and up. The gaps are nil and count as other.
		handshake := make([]metrics.Counter, header.HandshakeIXHybridFragmented+1)
		handshake[header.HandshakeIXPSK0] = metrics.GetOrRegisterCounter(fmt.Sprintf("messages.%s.handshake_ixpsk0", t), nil)
		handshake[header.HandshakeIXPSK0Fragmented] = metrics.GetOrRegisterCounter(fmt.Sprintf("messages.%s.handshake_ixpsk0_fragmented", t), nil)
		handshake[header.HandshakeXXPSK0Fragmented] = metrics.GetOrRegisterCounter(fmt.Sprintf("messages.%s.handshake_xxpsk0_fragmented", t), nil)
		handshake[header.HandshakeIXHybridFragmented] = metrics.GetOrRegisterCounter(fmt.Sprintf("messages.%s.handshake_ixhybrid_fragmented", t), nil)
		return [][]metrics.Counter{
			handshake,
			nil,
			{metrics.GetOrRegisterCounter(fmt.Sprintf("messages.%s.recv_error", t), nil)},
			{metrics.GetOrRegisterCounter(fmt.Sprintf("messages.%s.lighthouse", t), nil)},
			{
				metrics.GetOrRegisterCounter(fmt.Sprintf("messages.%s.test_request", t), nil),
				metrics.GetOrRegisterCounter(fmt.Sprintf("messages.%s.test_response", t), nil),
			},
			{metrics.GetOrRegisterCounter(fmt.Sprintf("messages.%s.close_tunnel", t), nil)},
		}
	}
	return &MessageMetrics{
		rx: gen("rx"),
		tx: gen("tx"),

		rxUnknown:   metrics.GetOrRegisterCounter("messages.rx.other", nil),
		txUnknown:   metrics.GetOrRegisterCounter("messages.tx.other", nil),
		rxInvalid:   metrics.GetOrRegisterCounter("messages.rx.invalid", nil),
		txExhausted: metrics.GetOrRegisterCounter("messages.tx.exhausted", nil),
	}
}

// Historically we only recorded recv_error, so this is backwards compat
func newMessageMetricsOnlyRecvError() *MessageMetrics {
	gen := func(t string) [][]metrics.Counter {
		return [][]metrics.Counter{
			nil,
			nil,
			{metrics.GetOrRegisterCounter(fmt.Sprintf("messages.%s.recv_error", t), nil)},
		}
	}
	return &MessageMetrics{
		rx: gen("rx"),
		tx: gen("tx"),
	}
}

func newLighthouseMetrics() *MessageMetrics {
	gen := func(t string) [][]metrics.Counter {
		h := make([][]metrics.Counter, len(NebulaMeta_MessageType_name))
		used := []NebulaMeta_MessageType{
			NebulaMeta_HostQuery,
			NebulaMeta_HostQueryReply,
			NebulaMeta_HostUpdateNotification,
			NebulaMeta_HostPunchNotification,
			NebulaMeta_HostUpdateNotificationAck,
		}
		for _, i := range used {
			h[i] = []metrics.Counter{metrics.GetOrRegisterCounter(fmt.Sprintf("lighthouse.%s.%s", t, i.String()), nil)}
		}
		return h
	}
	return &MessageMetrics{
		rx: gen("rx"),
		tx: gen("tx"),

		rxUnknown: metrics.GetOrRegisterCounter("lighthouse.rx.other", nil),
		txUnknown: metrics.GetOrRegisterCounter("lighthouse.tx.other", nil),
	}
}
