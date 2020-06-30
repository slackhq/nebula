package nebula

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
)

type headerTest struct {
	expectedBytes []byte
	*Header
}

// 0001 0010 00010010
var headerBigEndianTests = []headerTest{{
	expectedBytes: []byte{0x54, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xa, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x9},
	// 1010 0000
	Header: &Header{
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
		b, err := tt.Encode(make([]byte, HeaderLen))
		if err != nil {
			t.Fatal(err)
		}

		assert.Equal(t, tt.expectedBytes, b)
	}
}

func TestParse(t *testing.T) {
	for _, tt := range headerBigEndianTests {
		b := tt.expectedBytes
		parsedHeader := &Header{}
		parsedHeader.Parse(b)

		if !reflect.DeepEqual(tt.Header, parsedHeader) {
			t.Fatalf("got %#v; want %#v", parsedHeader, tt.Header)
		}
	}
}

func TestTypeName(t *testing.T) {
	assert.Equal(t, "test", TypeName(test))
	assert.Equal(t, "test", (&Header{Type: test}).TypeName())

	assert.Equal(t, "unknown", TypeName(99))
	assert.Equal(t, "unknown", (&Header{Type: 99}).TypeName())
}

func TestSubTypeName(t *testing.T) {
	assert.Equal(t, "testRequest", SubTypeName(test, testRequest))
	assert.Equal(t, "testRequest", (&Header{Type: test, Subtype: testRequest}).SubTypeName())

	assert.Equal(t, "unknown", SubTypeName(99, testRequest))
	assert.Equal(t, "unknown", (&Header{Type: 99, Subtype: testRequest}).SubTypeName())

	assert.Equal(t, "unknown", SubTypeName(test, 99))
	assert.Equal(t, "unknown", (&Header{Type: test, Subtype: 99}).SubTypeName())

	assert.Equal(t, "none", SubTypeName(message, 0))
	assert.Equal(t, "none", (&Header{Type: message, Subtype: 0}).SubTypeName())
}

func TestTypeMap(t *testing.T) {
	// Force people to document this stuff
	assert.Equal(t, map[NebulaMessageType]string{
		handshake:       "handshake",
		message:         "message",
		recvError:       "recvError",
		lightHouse:      "lightHouse",
		test:            "test",
		closeTunnel:     "closeTunnel",
		testRemote:      "testRemote",
		testRemoteReply: "testRemoteReply",
	}, typeMap)

	assert.Equal(t, map[NebulaMessageType]*map[NebulaMessageSubType]string{
		message:     &subTypeNoneMap,
		recvError:   &subTypeNoneMap,
		lightHouse:  &subTypeNoneMap,
		test:        &subTypeTestMap,
		closeTunnel: &subTypeNoneMap,
		handshake: {
			handshakeIXPSK0: "ix_psk0",
		},
		testRemote:      &subTypeNoneMap,
		testRemoteReply: &subTypeNoneMap,
	}, subTypeMap)
}

func TestHeader_String(t *testing.T) {
	assert.Equal(
		t,
		"ver=100 type=test subtype=testRequest reserved=0x63 remoteindex=98 messagecounter=97",
		(&Header{100, test, testRequest, 99, 98, 97}).String(),
	)
}

func TestHeader_MarshalJSON(t *testing.T) {
	b, err := (&Header{100, test, testRequest, 99, 98, 97}).MarshalJSON()
	assert.Nil(t, err)
	assert.Equal(
		t,
		"{\"messageCounter\":97,\"remoteIndex\":98,\"reserved\":99,\"subType\":\"testRequest\",\"type\":\"test\",\"version\":100}",
		string(b),
	)
}
