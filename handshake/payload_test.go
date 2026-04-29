package handshake

import (
	"bytes"
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protowire"
)

func TestPayloadRoundTrip(t *testing.T) {
	t.Run("all fields set", func(t *testing.T) {
		data := MarshalPayload(nil, Payload{
			Cert:           []byte("test-cert-bytes"),
			CertVersion:    2,
			InitiatorIndex: 12345,
			ResponderIndex: 67890,
			Time:           1234567890,
		})

		got, err := UnmarshalPayload(data)
		require.NoError(t, err)

		assert.Equal(t, []byte("test-cert-bytes"), got.Cert)
		assert.Equal(t, uint32(12345), got.InitiatorIndex)
		assert.Equal(t, uint32(67890), got.ResponderIndex)
		assert.Equal(t, uint64(1234567890), got.Time)
		assert.Equal(t, uint32(2), got.CertVersion)
	})

	t.Run("minimal fields", func(t *testing.T) {
		data := MarshalPayload(nil, Payload{InitiatorIndex: 1})

		got, err := UnmarshalPayload(data)
		require.NoError(t, err)

		assert.Equal(t, uint32(1), got.InitiatorIndex)
		assert.Equal(t, uint32(0), got.ResponderIndex)
		assert.Equal(t, uint64(0), got.Time)
		assert.Nil(t, got.Cert)
	})

	t.Run("empty payload", func(t *testing.T) {
		data := MarshalPayload(nil, Payload{})

		got, err := UnmarshalPayload(data)
		require.NoError(t, err)

		assert.Equal(t, uint32(0), got.InitiatorIndex)
	})

	t.Run("large cert bytes", func(t *testing.T) {
		bigCert := make([]byte, 4096)
		for i := range bigCert {
			bigCert[i] = byte(i % 256)
		}

		data := MarshalPayload(nil, Payload{
			Cert:           bigCert,
			CertVersion:    2,
			InitiatorIndex: 999,
		})

		got, err := UnmarshalPayload(data)
		require.NoError(t, err)

		assert.Equal(t, bigCert, got.Cert)
		assert.Equal(t, uint32(999), got.InitiatorIndex)
	})

	t.Run("append to existing buffer", func(t *testing.T) {
		prefix := []byte("prefix")
		data := MarshalPayload(prefix, Payload{InitiatorIndex: 42})

		assert.Equal(t, []byte("prefix"), data[:6])

		got, err := UnmarshalPayload(data[6:])
		require.NoError(t, err)
		assert.Equal(t, uint32(42), got.InitiatorIndex)
	})
}

func TestPayloadUnknownFields(t *testing.T) {
	t.Run("unknown field in outer message is skipped", func(t *testing.T) {
		// Marshal a normal payload then append an unknown field (field 99, varint)
		data := MarshalPayload(nil, Payload{InitiatorIndex: 42})
		data = protowire.AppendTag(data, 99, protowire.VarintType)
		data = protowire.AppendVarint(data, 12345)

		got, err := UnmarshalPayload(data)
		require.NoError(t, err)
		assert.Equal(t, uint32(42), got.InitiatorIndex)
	})

	t.Run("unknown field in details is skipped", func(t *testing.T) {
		// Build details with a known field + unknown field
		var details []byte
		details = protowire.AppendTag(details, fieldInitiatorIndex, protowire.VarintType)
		details = protowire.AppendVarint(details, 77)
		// Unknown field 50, varint
		details = protowire.AppendTag(details, 50, protowire.VarintType)
		details = protowire.AppendVarint(details, 9999)
		// Another known field after the unknown one
		details = protowire.AppendTag(details, fieldResponderIndex, protowire.VarintType)
		details = protowire.AppendVarint(details, 88)

		// Wrap in outer message
		var data []byte
		data = protowire.AppendTag(data, 1, protowire.BytesType)
		data = protowire.AppendBytes(data, details)

		got, err := UnmarshalPayload(data)
		require.NoError(t, err)
		assert.Equal(t, uint32(77), got.InitiatorIndex)
		assert.Equal(t, uint32(88), got.ResponderIndex)
	})

	t.Run("reserved fields 6 and 7 are skipped", func(t *testing.T) {
		// Fields 6 and 7 are reserved in the proto definition
		var details []byte
		details = protowire.AppendTag(details, fieldInitiatorIndex, protowire.VarintType)
		details = protowire.AppendVarint(details, 100)
		details = protowire.AppendTag(details, 6, protowire.VarintType)
		details = protowire.AppendVarint(details, 1)
		details = protowire.AppendTag(details, 7, protowire.VarintType)
		details = protowire.AppendVarint(details, 2)

		var data []byte
		data = protowire.AppendTag(data, 1, protowire.BytesType)
		data = protowire.AppendBytes(data, details)

		got, err := UnmarshalPayload(data)
		require.NoError(t, err)
		assert.Equal(t, uint32(100), got.InitiatorIndex)
	})
}

func TestPayloadBytesConsumed(t *testing.T) {
	t.Run("all bytes consumed on valid input", func(t *testing.T) {
		original := Payload{
			Cert:           []byte("cert"),
			CertVersion:    2,
			InitiatorIndex: 100,
			ResponderIndex: 200,
			Time:           999,
		}
		data := MarshalPayload(nil, original)

		got, err := UnmarshalPayload(data)
		require.NoError(t, err)

		// Re-marshal and compare — proves we consumed and reproduced all fields
		remarshaled := MarshalPayload(nil, got)
		assert.Equal(t, data, remarshaled)
	})
}

// wrapDetails wraps raw detail bytes in the outer NebulaHandshake envelope
// so UnmarshalPayload can reach unmarshalPayloadDetails.
func wrapDetails(details []byte) []byte {
	var out []byte
	out = protowire.AppendTag(out, 1, protowire.BytesType)
	out = protowire.AppendBytes(out, details)
	return out
}

func TestPayloadUnmarshalErrors(t *testing.T) {
	t.Run("nil input", func(t *testing.T) {
		got, err := UnmarshalPayload(nil)
		require.NoError(t, err)
		assert.Equal(t, uint32(0), got.InitiatorIndex)
	})

	t.Run("truncated outer tag", func(t *testing.T) {
		_, err := UnmarshalPayload([]byte{0x80})
		assert.Error(t, err)
	})

	t.Run("truncated outer details field", func(t *testing.T) {
		_, err := UnmarshalPayload([]byte{0x0a, 0x64, 0x01, 0x02, 0x03, 0x04, 0x05})
		assert.Error(t, err)
	})

	t.Run("truncated outer unknown field", func(t *testing.T) {
		// Valid tag for unknown field 99 varint, but no value follows
		var data []byte
		data = protowire.AppendTag(data, 99, protowire.VarintType)
		_, err := UnmarshalPayload(data)
		assert.Error(t, err)
	})

	t.Run("truncated details tag", func(t *testing.T) {
		_, err := UnmarshalPayload(wrapDetails([]byte{0x80}))
		assert.Error(t, err)
	})

	t.Run("truncated cert bytes", func(t *testing.T) {
		// Field 1 (cert), bytes type, length 10 but only 2 bytes
		var details []byte
		details = protowire.AppendTag(details, fieldCert, protowire.BytesType)
		details = append(details, 0x0a, 0x01, 0x02) // length 10, only 2 bytes
		_, err := UnmarshalPayload(wrapDetails(details))
		assert.Error(t, err)
	})

	t.Run("truncated initiator index varint", func(t *testing.T) {
		var details []byte
		details = protowire.AppendTag(details, fieldInitiatorIndex, protowire.VarintType)
		details = append(details, 0x80) // incomplete varint
		_, err := UnmarshalPayload(wrapDetails(details))
		assert.Error(t, err)
	})

	t.Run("truncated responder index varint", func(t *testing.T) {
		var details []byte
		details = protowire.AppendTag(details, fieldResponderIndex, protowire.VarintType)
		details = append(details, 0x80)
		_, err := UnmarshalPayload(wrapDetails(details))
		assert.Error(t, err)
	})

	t.Run("truncated time varint", func(t *testing.T) {
		var details []byte
		details = protowire.AppendTag(details, fieldTime, protowire.VarintType)
		details = append(details, 0x80)
		_, err := UnmarshalPayload(wrapDetails(details))
		assert.Error(t, err)
	})

	t.Run("truncated cert version varint", func(t *testing.T) {
		var details []byte
		details = protowire.AppendTag(details, fieldCertVersion, protowire.VarintType)
		details = append(details, 0x80)
		_, err := UnmarshalPayload(wrapDetails(details))
		assert.Error(t, err)
	})

	t.Run("truncated unknown field in details", func(t *testing.T) {
		var details []byte
		details = protowire.AppendTag(details, 50, protowire.VarintType)
		details = append(details, 0x80) // incomplete varint
		_, err := UnmarshalPayload(wrapDetails(details))
		assert.Error(t, err)
	})

	t.Run("cert with wrong wire type rejected", func(t *testing.T) {
		// fieldCert as Varint instead of Bytes.
		var details []byte
		details = protowire.AppendTag(details, fieldCert, protowire.VarintType)
		details = protowire.AppendVarint(details, 42)
		_, err := UnmarshalPayload(wrapDetails(details))
		assert.Error(t, err)
	})

	t.Run("initiator index with wrong wire type rejected", func(t *testing.T) {
		// fieldInitiatorIndex as Bytes instead of Varint.
		var details []byte
		details = protowire.AppendTag(details, fieldInitiatorIndex, protowire.BytesType)
		details = protowire.AppendBytes(details, []byte{1, 2, 3})
		_, err := UnmarshalPayload(wrapDetails(details))
		assert.Error(t, err)
	})

	t.Run("time with wrong wire type rejected", func(t *testing.T) {
		var details []byte
		details = protowire.AppendTag(details, fieldTime, protowire.BytesType)
		details = protowire.AppendBytes(details, []byte{1, 2, 3})
		_, err := UnmarshalPayload(wrapDetails(details))
		assert.Error(t, err)
	})

	t.Run("cert version with wrong wire type rejected", func(t *testing.T) {
		var details []byte
		details = protowire.AppendTag(details, fieldCertVersion, protowire.BytesType)
		details = protowire.AppendBytes(details, []byte{1, 2, 3})
		_, err := UnmarshalPayload(wrapDetails(details))
		assert.Error(t, err)
	})

	t.Run("repeated singular field follows proto3 last-wins", func(t *testing.T) {
		// Per proto3, multiple instances of a singular field are accepted and
		// the last value wins. We keep this behavior so that peers using
		// alternative encoders aren't rejected.
		var details []byte
		details = protowire.AppendTag(details, fieldInitiatorIndex, protowire.VarintType)
		details = protowire.AppendVarint(details, 1)
		details = protowire.AppendTag(details, fieldInitiatorIndex, protowire.VarintType)
		details = protowire.AppendVarint(details, 42)
		got, err := UnmarshalPayload(wrapDetails(details))
		require.NoError(t, err)
		assert.Equal(t, uint32(42), got.InitiatorIndex)
	})

	t.Run("initiator index varint overflow rejected", func(t *testing.T) {
		var details []byte
		details = protowire.AppendTag(details, fieldInitiatorIndex, protowire.VarintType)
		details = protowire.AppendVarint(details, math.MaxUint32+1)
		_, err := UnmarshalPayload(wrapDetails(details))
		assert.Error(t, err)
	})

	t.Run("cert version varint overflow rejected", func(t *testing.T) {
		var details []byte
		details = protowire.AppendTag(details, fieldCertVersion, protowire.VarintType)
		details = protowire.AppendVarint(details, math.MaxUint32+1)
		_, err := UnmarshalPayload(wrapDetails(details))
		assert.Error(t, err)
	})

}

// FuzzPayload feeds arbitrary bytes through UnmarshalPayload to confirm it
// never panics, and for any input that parses cleanly, that re-marshal +
// re-parse is a fix-point. Inputs come from an authenticated peer (post-
// noise-decrypt), so the threat model is "valid peer behaving arbitrarily,"
// not "unauthenticated injection."
func FuzzPayload(f *testing.F) {
	// Seed corpus with a handful of known-good shapes.
	f.Add(MarshalPayload(nil, Payload{}))
	f.Add(MarshalPayload(nil, Payload{Cert: []byte{1, 2, 3}, CertVersion: 2}))
	f.Add(MarshalPayload(nil, Payload{InitiatorIndex: 42, Time: 1}))
	f.Add(MarshalPayload(nil, Payload{
		Cert:           []byte("seed-cert"),
		InitiatorIndex: 1,
		ResponderIndex: 2,
		Time:           3,
		CertVersion:    2,
	}))
	f.Add([]byte{})
	f.Add([]byte{0xff})

	f.Fuzz(func(t *testing.T, data []byte) {
		p1, err := UnmarshalPayload(data)
		if err != nil {
			return
		}

		// For any input that parses, re-marshaling and re-parsing must
		// yield an equivalent Payload. This catches dispatch bugs (e.g.
		// emitting a field on marshal that we don't accept on parse) and
		// any non-idempotent parsing behavior.
		b2 := MarshalPayload(nil, p1)
		p2, err := UnmarshalPayload(b2)
		if err != nil {
			t.Fatalf("re-parse of self-marshaled payload failed: %v\nintermediate: %x\n", err, b2)
		}
		if !payloadsEqual(p1, p2) {
			t.Fatalf("re-marshal not idempotent\nfirst:  %+v\nsecond: %+v", p1, p2)
		}
	})
}

func payloadsEqual(a, b Payload) bool {
	return bytes.Equal(a.Cert, b.Cert) &&
		a.InitiatorIndex == b.InitiatorIndex &&
		a.ResponderIndex == b.ResponderIndex &&
		a.Time == b.Time &&
		a.CertVersion == b.CertVersion
}
