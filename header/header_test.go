package header

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type headerTest struct {
	expectedBytes []byte
	*H
}

// 0001 0010 00010010
var headerBigEndianTests = []headerTest{{
	expectedBytes: []byte{0x54, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xa, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x9},
	// 1010 0000
	H: &H{
		// 1111 1+2+4+8 = 15
		Version:        5,
		Type:           4,
		Subtype:        0,
		Reserved:       0,
		RemoteIndex:    10,
		MessageCounter: 9,
	},
},
}

func TestEncode(t *testing.T) {
	for _, tt := range headerBigEndianTests {
		b, err := tt.Encode(make([]byte, Len))
		if err != nil {
			t.Fatal(err)
		}

		assert.Equal(t, tt.expectedBytes, b)
	}
}

func TestParse(t *testing.T) {
	for _, tt := range headerBigEndianTests {
		b := tt.expectedBytes
		parsedHeader := &H{}
		parsedHeader.Parse(b)

		if !reflect.DeepEqual(tt.H, parsedHeader) {
			t.Fatalf("got %#v; want %#v", parsedHeader, tt.H)
		}
	}
}

func TestTypeName(t *testing.T) {
	assert.Equal(t, "test", TypeName(Test))
	assert.Equal(t, "test", (&H{Type: Test}).TypeName())

	assert.Equal(t, "unknown", TypeName(99))
	assert.Equal(t, "unknown", (&H{Type: 99}).TypeName())
}

func TestSubTypeName(t *testing.T) {
	assert.Equal(t, "testRequest", SubTypeName(Test, TestRequest))
	assert.Equal(t, "testRequest", (&H{Type: Test, Subtype: TestRequest}).SubTypeName())

	assert.Equal(t, "unknown", SubTypeName(99, TestRequest))
	assert.Equal(t, "unknown", (&H{Type: 99, Subtype: TestRequest}).SubTypeName())

	assert.Equal(t, "unknown", SubTypeName(Test, 99))
	assert.Equal(t, "unknown", (&H{Type: Test, Subtype: 99}).SubTypeName())

	assert.Equal(t, "none", SubTypeName(Message, 0))
	assert.Equal(t, "none", (&H{Type: Message, Subtype: 0}).SubTypeName())
}

func TestTypeMap(t *testing.T) {
	// Force people to document this stuff
	assert.Equal(t, map[MessageType]string{
		Handshake:   "handshake",
		Message:     "message",
		RecvError:   "recvError",
		LightHouse:  "lightHouse",
		Test:        "test",
		CloseTunnel: "closeTunnel",
		Control:     "control",
	}, typeMap)

	assert.Equal(t, map[MessageType]*map[MessageSubType]string{
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
	}, subTypeMap)
}

// mapIsValidSubType is the pre-refactor, map-driven definition of a valid
// subtype. IsValidSubType was reimplemented as an explicit switch; this keeps
// the original behavior around so we can prove the switch is equivalent to it.
func mapIsValidSubType(t MessageType, s MessageSubType) bool {
	if n, ok := subTypeMap[t]; ok {
		if _, ok := (*n)[s]; ok {
			return true
		}
	}
	return false
}

func TestIsValidSubType(t *testing.T) {
	// Explicit intent table: documents exactly which subtypes are valid so the
	// test stays meaningful even if both the switch and subTypeMap change.
	assert.True(t, IsValidSubType(Message, MessageNone))
	assert.True(t, IsValidSubType(Message, MessageRelay))
	assert.False(t, IsValidSubType(Message, 2))

	assert.True(t, IsValidSubType(Handshake, HandshakeIXPSK0))
	// HandshakeXXPSK0 is defined but not a wire-valid subtype.
	assert.False(t, IsValidSubType(Handshake, HandshakeXXPSK0))

	assert.True(t, IsValidSubType(Test, TestRequest))
	assert.True(t, IsValidSubType(Test, TestReply))
	assert.False(t, IsValidSubType(Test, 2))

	// These types only ever carry subtype 0.
	for _, mt := range []MessageType{Control, CloseTunnel, RecvError, LightHouse} {
		assert.True(t, IsValidSubType(mt, 0), "type %d subtype 0 should be valid", mt)
		assert.False(t, IsValidSubType(mt, 1), "type %d subtype 1 should be invalid", mt)
	}

	// Unknown/unassigned types are never valid.
	assert.False(t, IsValidSubType(99, 0))

	// Exhaustive proof of equivalence with the original map-driven logic across
	// the entire (type, subtype) input space.
	for ti := 0; ti <= 0xff; ti++ {
		for si := 0; si <= 0xff; si++ {
			mt, mst := MessageType(ti), MessageSubType(si)
			assert.Equalf(t, mapIsValidSubType(mt, mst), IsValidSubType(mt, mst),
				"IsValidSubType(%d, %d) diverged from map-driven definition", ti, si)
		}
	}

	// H method must delegate to the package function.
	assert.True(t, (&H{Type: Test, Subtype: TestReply}).IsValidSubType())
	assert.False(t, (&H{Type: Handshake, Subtype: HandshakeXXPSK0}).IsValidSubType())
}

func TestHeader_String(t *testing.T) {
	assert.Equal(
		t,
		"ver=100 type=test subtype=testRequest reserved=0x63 remoteindex=98 messagecounter=97",
		(&H{100, Test, TestRequest, 99, 98, 97}).String(),
	)
}

func TestHeader_MarshalJSON(t *testing.T) {
	b, err := (&H{100, Test, TestRequest, 99, 98, 97}).MarshalJSON()
	require.NoError(t, err)
	assert.Equal(
		t,
		"{\"messageCounter\":97,\"remoteIndex\":98,\"reserved\":99,\"subType\":\"testRequest\",\"type\":\"test\",\"version\":100}",
		string(b),
	)
}
