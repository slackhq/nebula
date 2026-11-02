package handshake

import (
	"math"

	"google.golang.org/protobuf/encoding/protowire"
)

// PayloadMultiPortDetails is a peer's multiport support, sent in the handshake payload
type PayloadMultiPortDetails struct {
	RxSupported bool
	TxSupported bool
	BasePort    uint32
	TotalPorts  uint32
}

// Proto field numbers for the MultiPortDetails in NebulaHandshakeDetails
const (
	fieldInitiatorMultiPort = 6 // MultiPortDetails
	fieldResponderMultiPort = 7 // MultiPortDetails
)

// Proto field numbers for MultiPortDetails
const (
	fieldMultiportRxSupported = 1 // bool
	fieldMultiportTxSupported = 2 // bool
	fieldMultiportBasePort    = 3 // uint32
	fieldMultiportTotalPorts  = 4 // uint32
)

// marshalMultiPort appends p's multiport details to the encoded NebulaHandshakeDetails
func (p Payload) marshalMultiPort(details []byte) []byte {
	for _, f := range []struct {
		num protowire.Number
		d   *PayloadMultiPortDetails
	}{{fieldInitiatorMultiPort, p.InitiatorMultiPort}, {fieldResponderMultiPort, p.ResponderMultiPort}} {
		if f.d != nil {
			details = protowire.AppendTag(details, f.num, protowire.BytesType)
			details = protowire.AppendVarint(details, uint64(f.d.size()))
			details = f.d.marshal(details)
		}
	}
	return details
}

// consumeMultiPort decodes the multiport details field num from b into p and returns how much of b it used
func (p *Payload) consumeMultiPort(num protowire.Number, typ protowire.Type, b []byte) (int, error) {
	if typ != protowire.BytesType {
		return 0, errInvalidHandshakeDetails
	}
	d, n := protowire.ConsumeBytes(b)
	if n < 0 {
		return 0, errInvalidHandshakeMessage
	}
	details := new(PayloadMultiPortDetails)
	if err := unmarshalPayloadMultiPortDetails(details, d); err != nil {
		return 0, err
	}
	if num == fieldInitiatorMultiPort {
		p.InitiatorMultiPort = details
	} else {
		p.ResponderMultiPort = details
	}
	return n, nil
}

func (p PayloadMultiPortDetails) marshal(details []byte) []byte {
	details = protowire.AppendTag(details, fieldMultiportRxSupported, protowire.VarintType)
	details = protowire.AppendVarint(details, protowire.EncodeBool(p.RxSupported))
	details = protowire.AppendTag(details, fieldMultiportTxSupported, protowire.VarintType)
	details = protowire.AppendVarint(details, protowire.EncodeBool(p.TxSupported))
	details = protowire.AppendTag(details, fieldMultiportBasePort, protowire.VarintType)
	details = protowire.AppendVarint(details, uint64(p.BasePort))
	details = protowire.AppendTag(details, fieldMultiportTotalPorts, protowire.VarintType)
	details = protowire.AppendVarint(details, uint64(p.TotalPorts))

	return details
}

func (p PayloadMultiPortDetails) size() int {
	return 4 + 2 + protowire.SizeVarint(uint64(p.BasePort)) + protowire.SizeVarint(uint64(p.TotalPorts))
}

func unmarshalPayloadMultiPortDetails(p *PayloadMultiPortDetails, b []byte) error {
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return errInvalidHandshakeDetails
		}
		b = b[n:]

		// For known field numbers, reject any non-matching wire type as a
		// hard error rather than silently skipping. The caller will catch
		// missing-field cases downstream, but a wire-type mismatch on a tag
		// we know is a peer protocol violation worth flagging here.
		// Repeated occurrences of a singular field follow proto3 last-wins.
		switch num {
		case fieldMultiportRxSupported:
			if typ != protowire.VarintType {
				return errInvalidHandshakeDetails
			}
			v, n := protowire.ConsumeVarint(b)
			if n < 0 || v > math.MaxUint32 {
				return errInvalidHandshakeDetails
			}
			p.RxSupported = protowire.DecodeBool(v)
			b = b[n:]
		case fieldMultiportTxSupported:
			if typ != protowire.VarintType {
				return errInvalidHandshakeDetails
			}
			v, n := protowire.ConsumeVarint(b)
			if n < 0 || v > math.MaxUint32 {
				return errInvalidHandshakeDetails
			}
			p.TxSupported = protowire.DecodeBool(v)
			b = b[n:]
		case fieldMultiportBasePort:
			if typ != protowire.VarintType {
				return errInvalidHandshakeDetails
			}
			v, n := protowire.ConsumeVarint(b)
			if n < 0 || v > math.MaxUint32 {
				return errInvalidHandshakeDetails
			}
			p.BasePort = uint32(v)
			b = b[n:]
		case fieldMultiportTotalPorts:
			if typ != protowire.VarintType {
				return errInvalidHandshakeDetails
			}
			v, n := protowire.ConsumeVarint(b)
			if n < 0 || v > math.MaxUint32 {
				return errInvalidHandshakeDetails
			}
			p.TotalPorts = uint32(v)
			b = b[n:]
		default:
			n := protowire.ConsumeFieldValue(num, typ, b)
			if n < 0 {
				return errInvalidHandshakeDetails
			}
			b = b[n:]
		}
	}
	return nil
}

// multiportDetails returns the multiport details to advertise, nil when multiport is off
func (m *Machine) multiportDetails() *PayloadMultiPortDetails {
	if !m.multiport.Rx && !m.multiport.Tx {
		return nil
	}
	return &PayloadMultiPortDetails{
		RxSupported: m.multiport.Rx,
		TxSupported: m.multiport.Tx,
		BasePort:    uint32(m.multiport.TxBasePort),
		TotalPorts:  uint32(m.multiport.TxPorts),
	}
}

// setMultiport records the peer's multiport details. A peer claiming tx with a base port we can't send to is treated
// as not supporting tx, otherwise we would send to port 0 or a truncated port.
func (r *Result) setMultiport(d *PayloadMultiPortDetails) {
	if d == nil {
		return
	}
	r.MultiportRx = d.RxSupported
	if d.TxSupported && d.BasePort > 0 && d.BasePort <= math.MaxUint16 {
		r.MultiportTx = true
		r.MultiportBasePort = uint16(d.BasePort)
	}
}
