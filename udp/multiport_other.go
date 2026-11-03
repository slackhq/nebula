//go:build !linux || android || e2e_testing

package udp

import "log/slog"

// sendQueues returns n ways for queues to send through c, all c, whose writes are safe for concurrent use
func sendQueues(_ *slog.Logger, c Conn, n int, _ bool) []Conn {
	qs := make([]Conn, n)
	for q := range qs {
		qs[q] = c
	}
	return qs
}
