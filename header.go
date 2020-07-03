package nebula

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
)

//Version 1 header:
// 0                                                                       31
// |-----------------------------------------------------------------------|
// | Version (uint4) | Type (uint4) |  Subtype (uint8) | Reserved (uint16) | 32
// |-----------------------------------------------------------------------|
// |                        Remote index (uint32)                          | 64
// |-----------------------------------------------------------------------|
// |                           Message counter                             | 96
// |                               (uint64)                                | 128
// |-----------------------------------------------------------------------|
// |                               payload...                              |

const (
	Version   uint8 = 1
	HeaderLen       = 16
)

var eHeaderTooShort = errors.New("header is too short")

type Header struct {
	Version        uint8
	Type           NebulaMessageType
	Subtype        NebulaMessageSubType
	Reserved       uint16
	RemoteIndex    uint32
	MessageCounter uint64
}

// HeaderEncode uses the provided byte array to encode the provided header values into.
// Byte array must be capped higher than HeaderLen or this will panic
func HeaderEncode(b []byte, v uint8, t uint8, st uint8, ri uint32, c uint64) []byte {
	b = b[:HeaderLen]
	b[0] = byte(v<<4 | (t & 0x0f))
	b[1] = byte(st)
	binary.BigEndian.PutUint16(b[2:4], 0)
	binary.BigEndian.PutUint32(b[4:8], ri)
	binary.BigEndian.PutUint64(b[8:16], c)
	return b
}

// String creates a readable string representation of a header
func (h *Header) String() string {
	if h == nil {
		return "<nil>"
	}
	return fmt.Sprintf("ver=%d type=%s subtype=%s reserved=%#x remoteindex=%v messagecounter=%v",
		h.Version, h.TypeName(), h.SubTypeName(), h.Reserved, h.RemoteIndex, h.MessageCounter)
}

// MarshalJSON creates a json string representation of a header
func (h *Header) MarshalJSON() ([]byte, error) {
	return json.Marshal(m{
		"version":        h.Version,
		"type":           h.TypeName(),
		"subType":        h.SubTypeName(),
		"reserved":       h.Reserved,
		"remoteIndex":    h.RemoteIndex,
		"messageCounter": h.MessageCounter,
	})
}

// Encode turns header into bytes
func (h *Header) Encode(b []byte) ([]byte, error) {
	if h == nil {
		return nil, errors.New("nil header")
	}

	return HeaderEncode(b, h.Version, uint8(h.Type), uint8(h.Subtype), h.RemoteIndex, h.MessageCounter), nil
}

// Parse is a helper function to parses given bytes into new Header struct
func (h *Header) Parse(b []byte) error {
	if len(b) < HeaderLen {
		return eHeaderTooShort
	}
	// get upper 4 bytes
	h.Version = uint8((b[0] >> 4) & 0x0f)
	// get lower 4 bytes
	h.Type = NebulaMessageType(b[0] & 0x0f)
	h.Subtype = NebulaMessageSubType(b[1])
	h.Reserved = binary.BigEndian.Uint16(b[2:4])
	h.RemoteIndex = binary.BigEndian.Uint32(b[4:8])
	h.MessageCounter = binary.BigEndian.Uint64(b[8:16])
	return nil
}

// TypeName will transform the headers message type into a human string
func (h *Header) TypeName() string {
	return TypeName(h.Type)
}

// SubTypeName will transform the headers message sub type into a human string
func (h *Header) SubTypeName() string {
	return SubTypeName(h.Type, h.Subtype)
}

// NewHeader turns bytes into a header
func NewHeader(b []byte) (*Header, error) {
	h := new(Header)
	if err := h.Parse(b); err != nil {
		return nil, err
	}
	return h, nil
}
