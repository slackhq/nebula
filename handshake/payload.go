package handshake

import (
	"errors"
	"math"

	"google.golang.org/protobuf/encoding/protowire"
)

var (
	errInvalidHandshakeMessage = errors.New("invalid handshake message")
	errInvalidHandshakeDetails = errors.New("invalid handshake details")
)

// Payload represents the decoded fields of a handshake message.
// Wire format is protobuf-compatible with NebulaHandshake{Details: NebulaHandshakeDetails{...}}.
type Payload struct {
	Cert           []byte
	InitiatorIndex uint32
	ResponderIndex uint32
	Time           uint64
	CertVersion    uint32

	// Multiport lane negotiation; nil when the sender has multiport disabled
	// (which keeps the encoded payload byte-identical to a vanilla one).
	InitiatorLanes *LaneDetails
	ResponderLanes *LaneDetails
}

// LaneDetails advertises multiport lane capability: the contiguous UDP port
// range the sender bound, and how many lanes it may send on. The receiver needs
// PortCount/BasePort to aim its own lanes and TxLanes to know how many lane
// sessions to derive for receiving.
type LaneDetails struct {
	PortCount uint32
	BasePort  uint32
	TxLanes   uint32
}

// Proto field numbers for NebulaHandshakeDetails
const (
	fieldCert           = 1  // bytes
	fieldInitiatorIndex = 2  // uint32
	fieldResponderIndex = 3  // uint32
	fieldTime           = 5  // uint64
	fieldCertVersion    = 8  // uint32
	fieldInitiatorLanes = 9  // LaneDetails
	fieldResponderLanes = 10 // LaneDetails
)

// Proto field numbers for LaneDetails.
// Field 3 was a per-lane handshake index and is permanently reserved.
const (
	fieldLanePortCount = 1 // uint32
	fieldLaneBasePort  = 2 // uint32
	fieldLaneTxLanes   = 4 // uint32
)

// MarshalPayload encodes a handshake payload in protobuf wire format compatible
// with NebulaHandshake{Details: NebulaHandshakeDetails{...}}.
// Returns out (which may be nil), with the marshalled Payload appended to it.
func MarshalPayload(out []byte, p Payload) []byte {
	var details []byte

	if len(p.Cert) > 0 {
		details = protowire.AppendTag(details, fieldCert, protowire.BytesType)
		details = protowire.AppendBytes(details, p.Cert)
	}
	if p.InitiatorIndex != 0 {
		details = protowire.AppendTag(details, fieldInitiatorIndex, protowire.VarintType)
		details = protowire.AppendVarint(details, uint64(p.InitiatorIndex))
	}
	if p.ResponderIndex != 0 {
		details = protowire.AppendTag(details, fieldResponderIndex, protowire.VarintType)
		details = protowire.AppendVarint(details, uint64(p.ResponderIndex))
	}
	if p.Time != 0 {
		details = protowire.AppendTag(details, fieldTime, protowire.VarintType)
		details = protowire.AppendVarint(details, p.Time)
	}
	if p.CertVersion != 0 {
		details = protowire.AppendTag(details, fieldCertVersion, protowire.VarintType)
		details = protowire.AppendVarint(details, uint64(p.CertVersion))
	}
	// Emitted last to keep the encoding in ascending field-number order, which
	// is what protoc-gen-go would produce for the same message.
	if p.InitiatorLanes != nil {
		details = protowire.AppendTag(details, fieldInitiatorLanes, protowire.BytesType)
		details = protowire.AppendBytes(details, p.InitiatorLanes.marshal(nil))
	}
	if p.ResponderLanes != nil {
		details = protowire.AppendTag(details, fieldResponderLanes, protowire.BytesType)
		details = protowire.AppendBytes(details, p.ResponderLanes.marshal(nil))
	}

	out = protowire.AppendTag(out, 1, protowire.BytesType)
	out = protowire.AppendBytes(out, details)

	return out
}

// marshal appends the LaneDetails submessage fields to out. All fields are
// emitted unconditionally: a LaneDetails is only present at all when multiport
// is negotiating, and explicit zeros keep the parser's presence semantics
// trivial.
func (d *LaneDetails) marshal(out []byte) []byte {
	out = protowire.AppendTag(out, fieldLanePortCount, protowire.VarintType)
	out = protowire.AppendVarint(out, uint64(d.PortCount))
	out = protowire.AppendTag(out, fieldLaneBasePort, protowire.VarintType)
	out = protowire.AppendVarint(out, uint64(d.BasePort))
	out = protowire.AppendTag(out, fieldLaneTxLanes, protowire.VarintType)
	out = protowire.AppendVarint(out, uint64(d.TxLanes))
	return out
}

// UnmarshalPayload decodes a protobuf-encoded NebulaHandshake message.
func UnmarshalPayload(b []byte) (Payload, error) {
	var p Payload

	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return p, errInvalidHandshakeMessage
		}
		b = b[n:]

		switch {
		case num == 1 && typ == protowire.BytesType:
			details, n := protowire.ConsumeBytes(b)
			if n < 0 {
				return p, errInvalidHandshakeMessage
			}
			b = b[n:]
			if err := unmarshalPayloadDetails(&p, details); err != nil {
				return p, err
			}
		default:
			n := protowire.ConsumeFieldValue(num, typ, b)
			if n < 0 {
				return p, errInvalidHandshakeMessage
			}
			b = b[n:]
		}
	}

	return p, nil
}

func unmarshalPayloadDetails(p *Payload, b []byte) error {
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
		case fieldCert:
			if typ != protowire.BytesType {
				return errInvalidHandshakeDetails
			}
			v, n := protowire.ConsumeBytes(b)
			if n < 0 {
				return errInvalidHandshakeDetails
			}
			p.Cert = append([]byte(nil), v...)
			b = b[n:]
		case fieldInitiatorIndex:
			if typ != protowire.VarintType {
				return errInvalidHandshakeDetails
			}
			v, n := protowire.ConsumeVarint(b)
			if n < 0 || v > math.MaxUint32 {
				return errInvalidHandshakeDetails
			}
			p.InitiatorIndex = uint32(v)
			b = b[n:]
		case fieldResponderIndex:
			if typ != protowire.VarintType {
				return errInvalidHandshakeDetails
			}
			v, n := protowire.ConsumeVarint(b)
			if n < 0 || v > math.MaxUint32 {
				return errInvalidHandshakeDetails
			}
			p.ResponderIndex = uint32(v)
			b = b[n:]
		case fieldTime:
			if typ != protowire.VarintType {
				return errInvalidHandshakeDetails
			}
			v, n := protowire.ConsumeVarint(b)
			if n < 0 {
				return errInvalidHandshakeDetails
			}
			p.Time = v
			b = b[n:]
		case fieldCertVersion:
			if typ != protowire.VarintType {
				return errInvalidHandshakeDetails
			}
			v, n := protowire.ConsumeVarint(b)
			if n < 0 || v > math.MaxUint32 {
				return errInvalidHandshakeDetails
			}
			p.CertVersion = uint32(v)
			b = b[n:]
		case fieldInitiatorLanes:
			if typ != protowire.BytesType {
				return errInvalidHandshakeDetails
			}
			v, n := protowire.ConsumeBytes(b)
			if n < 0 {
				return errInvalidHandshakeDetails
			}
			p.InitiatorLanes = new(LaneDetails)
			if err := unmarshalLaneDetails(p.InitiatorLanes, v); err != nil {
				return err
			}
			b = b[n:]
		case fieldResponderLanes:
			if typ != protowire.BytesType {
				return errInvalidHandshakeDetails
			}
			v, n := protowire.ConsumeBytes(b)
			if n < 0 {
				return errInvalidHandshakeDetails
			}
			p.ResponderLanes = new(LaneDetails)
			if err := unmarshalLaneDetails(p.ResponderLanes, v); err != nil {
				return err
			}
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

func unmarshalLaneDetails(d *LaneDetails, b []byte) error {
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return errInvalidHandshakeDetails
		}
		b = b[n:]

		// Same contract as the details parser: known fields hard-fail on a
		// wire-type mismatch, unknown fields are skipped, repeated singular
		// fields follow proto3 last-wins.
		switch num {
		case fieldLanePortCount, fieldLaneBasePort, fieldLaneTxLanes:
			if typ != protowire.VarintType {
				return errInvalidHandshakeDetails
			}
			v, n := protowire.ConsumeVarint(b)
			if n < 0 || v > math.MaxUint32 {
				return errInvalidHandshakeDetails
			}
			switch num {
			case fieldLanePortCount:
				d.PortCount = uint32(v)
			case fieldLaneBasePort:
				d.BasePort = uint32(v)
			case fieldLaneTxLanes:
				d.TxLanes = uint32(v)
			}
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
