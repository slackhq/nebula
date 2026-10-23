package handshake

import (
	"encoding/binary"
	"errors"
	"math"
	"slices"

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
}

// Proto field numbers for NebulaHandshakeDetails
const (
	fieldCert           = 1 // bytes
	fieldInitiatorIndex = 2 // uint32
	fieldResponderIndex = 3 // uint32
	fieldTime           = 5 // uint64
	fieldCertVersion    = 8 // uint32
)

// MarshalPayload encodes a handshake payload in protobuf wire format compatible
// with NebulaHandshake{Details: NebulaHandshakeDetails{...}}.
// Returns out (which may be nil), with the marshalled Payload appended to it.
func MarshalPayload(out []byte, p Payload) []byte {
	// Everything but the certificate fits on the stack, which leaves the
	// certificate the only variable size and out grown just once.
	var scalars [4 * (1 + binary.MaxVarintLen64)]byte
	rest := scalars[:0]
	if p.InitiatorIndex != 0 {
		rest = protowire.AppendTag(rest, fieldInitiatorIndex, protowire.VarintType)
		rest = protowire.AppendVarint(rest, uint64(p.InitiatorIndex))
	}
	if p.ResponderIndex != 0 {
		rest = protowire.AppendTag(rest, fieldResponderIndex, protowire.VarintType)
		rest = protowire.AppendVarint(rest, uint64(p.ResponderIndex))
	}
	if p.Time != 0 {
		rest = protowire.AppendTag(rest, fieldTime, protowire.VarintType)
		rest = protowire.AppendVarint(rest, p.Time)
	}
	if p.CertVersion != 0 {
		rest = protowire.AppendTag(rest, fieldCertVersion, protowire.VarintType)
		rest = protowire.AppendVarint(rest, uint64(p.CertVersion))
	}

	detailsLen := len(rest)
	if len(p.Cert) > 0 {
		detailsLen += protowire.SizeTag(fieldCert) + protowire.SizeBytes(len(p.Cert))
	}
	out = slices.Grow(out, protowire.SizeTag(1)+protowire.SizeBytes(detailsLen))
	out = protowire.AppendTag(out, 1, protowire.BytesType)
	out = protowire.AppendVarint(out, uint64(detailsLen))
	if len(p.Cert) > 0 {
		out = protowire.AppendTag(out, fieldCert, protowire.BytesType)
		out = protowire.AppendBytes(out, p.Cert)
	}
	return append(out, rest...)
}

// UnmarshalPayload decodes a protobuf-encoded NebulaHandshake message. The
// returned Cert aliases b.
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
			p.Cert = v
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
