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
