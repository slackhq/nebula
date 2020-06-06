package nebula

import (
	"fmt"

	"github.com/rcrowley/go-metrics"
)

type MessageMetrics struct {
	rx [][]metrics.Counter
	tx [][]metrics.Counter

	rxUnknown metrics.Counter
	txUnknown metrics.Counter
}

func (f *MessageMetrics) Rx(t NebulaMessageType, s NebulaMessageSubType, i int64) {
	if f != nil {
		if t >= 0 && int(t) < len(f.rx) && s >= 0 && int(s) < len(f.rx[t]) {
			f.rx[t][s].Inc(i)
		} else if f.rxUnknown != nil {
			f.rxUnknown.Inc(i)
		}
	}
}
func (f *MessageMetrics) Tx(t NebulaMessageType, s NebulaMessageSubType, i int64) {
	if f != nil {
		if t >= 0 && int(t) < len(f.tx) && s >= 0 && int(s) < len(f.tx[t]) {
			f.tx[t][s].Inc(i)
		} else if f.txUnknown != nil {
			f.txUnknown.Inc(i)
		}
	}
}

func newMessageMetrics() *MessageMetrics {
	gen := func(t string) [][]metrics.Counter {
		return [][]metrics.Counter{
			{
				metrics.GetOrRegisterCounter(fmt.Sprintf("messages.%s.handshake_stage1", t), nil),
				metrics.GetOrRegisterCounter(fmt.Sprintf("messages.%s.handshake_stage2", t), nil),
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
	return &MessageMetrics{
		rx: [][]metrics.Counter{
			nil,
			nil,
			{metrics.GetOrRegisterCounter("messages.rx.recv_error", nil)},
		},
		tx: [][]metrics.Counter{
			nil,
			nil,
			{metrics.GetOrRegisterCounter("messages.tx.recv_error", nil)},
		},
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
