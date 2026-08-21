package batch

//TODO refactor this away
// This file holds the lanes' self-parsing Commit entries and the proto-checking parsers behind
// them. Production traffic enters the lanes only through MultiCoalescer.dispatch and the At
// parsers; these wrappers reproduce that path (including seal-all on unparseable shapes) on top
// of a local parse, so tests and benches can drive one lane with nothing but a packet.

// parseIPPrologue resolves the IP version, requires the L4 protocol to match wantProto (6 TCP,
// 17 UDP), and defers to the shared per-version cores. Returns the trimmed packet and the L4
// offset; fk must be zero on entry and is filled in place.
func (fk *flowKey) parseIPPrologue(pkt []byte, wantProto byte) ([]byte, int, bool) {
	if len(pkt) < 20 {
		return nil, 0, false
	}
	switch pkt[0] >> 4 {
	case 4:
		if pkt[9] != wantProto {
			return nil, 0, false
		}
		trimmed, ok := fk.parseIPv4Prologue(pkt)
		return trimmed, 20, ok
	case 6:
		if len(pkt) < 40 {
			return nil, 0, false
		}
		if pkt[6] != wantProto {
			return nil, 0, false
		}
		trimmed, ok := fk.parseIPv6Prologue(pkt)
		return trimmed, 40, ok
	}
	return nil, 0, false
}

// parseBase extracts the flow key and IP/TCP offsets for any TCP packet, admissible for
// coalescing or not. Returns false for non-TCP or malformed input.
func (p *parsedTCP) parseBase(pkt []byte) bool {
	trimmed, ipHdrLen, ok := p.fk.parseIPPrologue(pkt, ipProtoTCP)
	if !ok {
		return false
	}
	return p.parseTail(trimmed, ipHdrLen)
}

// parseBase extracts the flow key and IP/UDP offsets for a UDP packet.
func (p *parsedUDP) parseBase(pkt []byte) bool {
	trimmed, ipHdrLen, ok := p.fk.parseIPPrologue(pkt, ipProtoUDP)
	if !ok {
		return false
	}
	return p.parseTail(trimmed, ipHdrLen)
}

// Commit borrows pkt. The caller must keep pkt valid until the next Flush.
func (c *TCPCoalescer) Commit(pkt []byte) error {
	var info parsedTCP
	if !info.parseBase(pkt) {
		// Unparseable: flow key unknown, seal everything so later data cannot emit ahead of it.
		c.sealAllOpen()
		c.addVerbatim(pkt)
		return nil
	}
	return c.commitParsed(pkt, &info)
}

// Commit borrows pkt. The caller must keep pkt valid until the next Flush.
func (c *UDPCoalescer) Commit(pkt []byte) error {
	var info parsedUDP
	if !info.parseBase(pkt) {
		c.sealAllOpen()
		c.addVerbatim(pkt)
		return nil
	}
	return c.commitParsed(pkt, &info)
}
