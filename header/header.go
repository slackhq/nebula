package header

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

type m = map[string]any

const (
	Version uint8 = 1
	Len           = 16
)

type MessageType uint8
type MessageSubType uint8

const (
	Handshake   MessageType = 0
	Message     MessageType = 1
	RecvError   MessageType = 2
	LightHouse  MessageType = 3
	Test        MessageType = 4
	CloseTunnel MessageType = 5
	Control     MessageType = 6
)

var typeMap = map[MessageType]string{
	Handshake:   "handshake",
	Message:     "message",
	RecvError:   "recvError",
	LightHouse:  "lightHouse",
	Test:        "test",
	CloseTunnel: "closeTunnel",
	Control:     "control",
}

const (
	MessageNone  MessageSubType = 0
	MessageRelay MessageSubType = 1
)

const (
	TestRequest MessageSubType = 0
	TestReply   MessageSubType = 1
)

const (
	HandshakeIXPSK0 MessageSubType = 0
	HandshakeXXPSK0 MessageSubType = 1
)

var ErrHeaderTooShort = errors.New("header is too short")

var subTypeTestMap = map[MessageSubType]string{
	TestRequest: "testRequest",
	TestReply:   "testReply",
}

var subTypeNoneMap = map[MessageSubType]string{0: "none"}

var subTypeMap = map[MessageType]*map[MessageSubType]string{
	Message: {
		MessageNone:  "none",
		MessageRelay: "relay",
	},
	RecvError:   &subTypeNoneMap,
	LightHouse:  &subTypeNoneMap,
	Test:        &subTypeTestMap,
	CloseTunnel: &subTypeNoneMap,
	Handshake: {
		HandshakeIXPSK0: "ix_psk0",
	},
	Control: &subTypeNoneMap,
}

type H struct {
	Version        uint8
	Type           MessageType
	Subtype        MessageSubType
	Reserved       uint16
	RemoteIndex    uint32
	MessageCounter uint64
}

// Encode uses the provided byte array to encode the provided header values into.
// Byte array must be capped higher than HeaderLen or this will panic
func Encode(b []byte, v uint8, t MessageType, st MessageSubType, ri uint32, c uint64) []byte {
	b = b[:Len]
	b[0] = v<<4 | byte(t&0x0f)
	b[1] = byte(st)
	binary.BigEndian.PutUint16(b[2:4], 0)
	binary.BigEndian.PutUint32(b[4:8], ri)
	binary.BigEndian.PutUint64(b[8:16], c)
	return b
}

// String creates a readable string representation of a header
func (h *H) String() string {
	if h == nil {
		return "<nil>"
	}
	return fmt.Sprintf("ver=%d type=%s subtype=%s reserved=%#x remoteindex=%v messagecounter=%v",
		h.Version, h.TypeName(), h.SubTypeName(), h.Reserved, h.RemoteIndex, h.MessageCounter)
}

// MarshalJSON creates a json string representation of a header
func (h *H) MarshalJSON() ([]byte, error) {
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
func (h *H) Encode(b []byte) ([]byte, error) {
	if h == nil {
		return nil, errors.New("nil header")
	}

	return Encode(b, h.Version, h.Type, h.Subtype, h.RemoteIndex, h.MessageCounter), nil
}

// Parse is a helper function to parses given bytes into new Header struct
func (h *H) Parse(b []byte) error {
	if len(b) < Len {
		return ErrHeaderTooShort
	}
	// get upper 4 bytes
	h.Version = uint8((b[0] >> 4) & 0x0f)
	// get lower 4 bytes
	h.Type = MessageType(b[0] & 0x0f)
	h.Subtype = MessageSubType(b[1])
	h.Reserved = binary.BigEndian.Uint16(b[2:4])
	h.RemoteIndex = binary.BigEndian.Uint32(b[4:8])
	h.MessageCounter = binary.BigEndian.Uint64(b[8:16])
	return nil
}

// TypeName will transform the headers message type into a human string
func (h *H) TypeName() string {
	return TypeName(h.Type)
}

// TypeName will transform a nebula message type into a human string
func TypeName(t MessageType) string {
	if n, ok := typeMap[t]; ok {
		return n
	}

	return "unknown"
}

// SubTypeName will transform the headers message sub type into a human string
func (h *H) SubTypeName() string {
	return SubTypeName(h.Type, h.Subtype)
}

// SubTypeName will transform a nebula message sub type into a human string
func SubTypeName(t MessageType, s MessageSubType) string {
	if n, ok := subTypeMap[t]; ok {
		if x, ok := (*n)[s]; ok {
			return x
		}
	}

	return "unknown"
}

// NewHeader turns bytes into a header
func NewHeader(b []byte) (*H, error) {
	h := new(H)
	if err := h.Parse(b); err != nil {
		return nil, err
	}
	return h, nil
}
