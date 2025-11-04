//go:build linux && !android && !e2e_testing

package overlay

import "fmt"

func (t *tun) batchIO() (*wireguardTunIO, bool) {
	io, ok := t.ReadWriteCloser.(*wireguardTunIO)
	return io, ok
}

func (t *tun) ReadIntoBatch(pool *PacketPool) ([]*Packet, error) {
	io, ok := t.batchIO()
	if !ok {
		return nil, fmt.Errorf("wireguard batch I/O not enabled")
	}
	return io.ReadIntoBatch(pool)
}

func (t *tun) WriteBatch(packets []*Packet) (int, error) {
	io, ok := t.batchIO()
	if ok {
		return io.WriteBatch(packets)
	}
	for _, pkt := range packets {
		if pkt == nil {
			continue
		}
		if _, err := t.Write(pkt.Payload()[:pkt.Len]); err != nil {
			return 0, err
		}
		pkt.Release()
	}
	return len(packets), nil
}

func (t *tun) BatchHeadroom() int {
	if io, ok := t.batchIO(); ok {
		return io.BatchHeadroom()
	}
	return 0
}

func (t *tun) BatchPayloadCap() int {
	if io, ok := t.batchIO(); ok {
		return io.BatchPayloadCap()
	}
	return 0
}

func (t *tun) BatchSize() int {
	if io, ok := t.batchIO(); ok {
		return io.BatchSize()
	}
	return 1
}
