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
}

func (m *MessageMetrics) Rx(t header.MessageType, s header.MessageSubType, i int64) {
	if m != nil {
		if t >= 0 && int(t) < len(m.rx) && s >= 0 && int(s) < len(m.rx[t]) {
			m.rx[t][s].Inc(i)
		} else if m.rxUnknown != nil {
			m.rxUnknown.Inc(i)
		}
	}
}
func (m *MessageMetrics) Tx(t header.MessageType, s header.MessageSubType, i int64) {
	if m != nil {
		if t >= 0 && int(t) < len(m.tx) && s >= 0 && int(s) < len(m.tx[t]) {
			m.tx[t][s].Inc(i)
		} else if m.txUnknown != nil {
			m.txUnknown.Inc(i)
		}
	}
}

func newMessageMetrics() *MessageMetrics {
	gen := func(t string) [][]metrics.Counter {
		return [][]metrics.Counter{
			{
				metrics.GetOrRegisterCounter(fmt.Sprintf("messages.%s.handshake_ixpsk0", t), nil),
			},
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

		rxUnknown: metrics.GetOrRegisterCounter("messages.rx.other", nil),
		txUnknown: metrics.GetOrRegisterCounter("messages.tx.other", nil),
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
