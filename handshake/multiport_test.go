package handshake

import (
	"math"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protowire"
)

// detailsPayload wraps raw NebulaHandshakeDetails bytes in a NebulaHandshake
func detailsPayload(details []byte) []byte {
	return protowire.AppendBytes(protowire.AppendTag(nil, 1, protowire.BytesType), details)
}

// multiportField appends field num of the NebulaHandshakeDetails holding the raw MultiPortDetails bytes d
func multiportField(details []byte, num protowire.Number, d []byte) []byte {
	return protowire.AppendBytes(protowire.AppendTag(details, num, protowire.BytesType), d)
}

func varintField(b []byte, num protowire.Number, v uint64) []byte {
	return protowire.AppendVarint(protowire.AppendTag(b, num, protowire.VarintType), v)
}

func TestPayloadMultiPortRoundTrip(t *testing.T) {
	for _, p := range []Payload{
		{InitiatorIndex: 1, Time: 2},
		{InitiatorIndex: 1, Time: 2, InitiatorMultiPort: &PayloadMultiPortDetails{RxSupported: true}},
		{
			Cert: []byte("cert"), InitiatorIndex: 1, ResponderIndex: 2, Time: 3, CertVersion: 2,
			InitiatorMultiPort: &PayloadMultiPortDetails{RxSupported: true, TxSupported: true, BasePort: 4242, TotalPorts: 100},
			ResponderMultiPort: &PayloadMultiPortDetails{TxSupported: true, BasePort: 65535, TotalPorts: math.MaxUint32},
		},
		{ResponderIndex: 9, Time: 1, ResponderMultiPort: &PayloadMultiPortDetails{}},
	} {
		got, err := UnmarshalPayload(MarshalPayload(nil, p))
		require.NoError(t, err)
		assert.Equal(t, p, got)
	}
}

func TestPayloadMultiPortDecode(t *testing.T) {
	valid := varintField(varintField(nil, fieldMultiportTxSupported, 1), fieldMultiportBasePort, 4242)

	t.Run("each field reaches its side", func(t *testing.T) {
		var details []byte
		details = multiportField(details, fieldInitiatorMultiPort, varintField(nil, fieldMultiportRxSupported, 1))
		details = multiportField(details, fieldResponderMultiPort, valid)
		got, err := UnmarshalPayload(detailsPayload(details))
		require.NoError(t, err)
		assert.Equal(t, &PayloadMultiPortDetails{RxSupported: true}, got.InitiatorMultiPort)
		assert.Equal(t, &PayloadMultiPortDetails{TxSupported: true, BasePort: 4242}, got.ResponderMultiPort)
	})

	t.Run("unknown fields are skipped", func(t *testing.T) {
		d := varintField(append([]byte(nil), valid...), 9, 7)
		got, err := UnmarshalPayload(detailsPayload(multiportField(nil, fieldInitiatorMultiPort, d)))
		require.NoError(t, err)
		assert.Equal(t, &PayloadMultiPortDetails{TxSupported: true, BasePort: 4242}, got.InitiatorMultiPort)
	})

	t.Run("a repeated field keeps the last value", func(t *testing.T) {
		d := varintField(append([]byte(nil), valid...), fieldMultiportBasePort, 5000)
		got, err := UnmarshalPayload(detailsPayload(multiportField(nil, fieldInitiatorMultiPort, d)))
		require.NoError(t, err)
		assert.Equal(t, uint32(5000), got.InitiatorMultiPort.BasePort)
	})

	t.Run("an empty message is all zero", func(t *testing.T) {
		got, err := UnmarshalPayload(detailsPayload(multiportField(nil, fieldResponderMultiPort, nil)))
		require.NoError(t, err)
		assert.Equal(t, &PayloadMultiPortDetails{}, got.ResponderMultiPort)
	})

	for _, tc := range []struct {
		name    string
		details []byte
	}{
		{"field 7 as a varint", varintField(nil, fieldResponderMultiPort, 1)},
		{"truncated length", append(protowire.AppendTag(nil, fieldInitiatorMultiPort, protowire.BytesType), 10, 1)},
		{"a field with the wrong wire type", multiportField(nil, fieldInitiatorMultiPort,
			protowire.AppendBytes(protowire.AppendTag(nil, fieldMultiportRxSupported, protowire.BytesType), []byte{1}))},
		{"a truncated varint", multiportField(nil, fieldInitiatorMultiPort,
			append(protowire.AppendTag(nil, fieldMultiportBasePort, protowire.VarintType), 0x80))},
		{"a base port past 32 bits", multiportField(nil, fieldInitiatorMultiPort, varintField(nil, fieldMultiportBasePort, math.MaxUint32+1))},
		{"a truncated tag", multiportField(nil, fieldResponderMultiPort, []byte{0x80})},
	} {
		t.Run(tc.name+" is malformed", func(t *testing.T) {
			_, err := UnmarshalPayload(detailsPayload(tc.details))
			assert.Error(t, err)
		})
	}
}

// FuzzPayloadMultiPort is FuzzPayload seeded with multiport details, comparing them across the re-marshal too
func FuzzPayloadMultiPort(f *testing.F) {
	f.Add(MarshalPayload(nil, Payload{InitiatorIndex: 1, Time: 1,
		InitiatorMultiPort: &PayloadMultiPortDetails{RxSupported: true, TxSupported: true, BasePort: 4242, TotalPorts: 100}}))
	f.Add(MarshalPayload(nil, Payload{ResponderIndex: 2, InitiatorIndex: 1, Time: 1,
		ResponderMultiPort: &PayloadMultiPortDetails{TxSupported: true, BasePort: 65535}}))
	f.Add(detailsPayload(multiportField(nil, fieldInitiatorMultiPort, nil)))
	f.Add(detailsPayload(varintField(nil, fieldInitiatorMultiPort, 1)))

	f.Fuzz(func(t *testing.T, data []byte) {
		p1, err := UnmarshalPayload(data)
		if err != nil {
			return
		}
		b2 := MarshalPayload(nil, p1)
		p2, err := UnmarshalPayload(b2)
		if err != nil {
			t.Fatalf("re-parse of self-marshaled payload failed: %v\nintermediate: %x\n", err, b2)
		}
		if !payloadsEqual(p1, p2) || !reflect.DeepEqual(p1.InitiatorMultiPort, p2.InitiatorMultiPort) ||
			!reflect.DeepEqual(p1.ResponderMultiPort, p2.ResponderMultiPort) {
			t.Fatalf("re-marshal not idempotent\nfirst:  %+v\nsecond: %+v", p1, p2)
		}
	})
}
