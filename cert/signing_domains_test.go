package cert

import (
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// A CA's classical key signs v1 and v2 certificates and the classical half of v3 composite signatures. That reuse is
// sound only while no message signed in one context can be read as one of another (see Classical key reuse in
// docs/pq-handshake.md), which here holds because each context's signed messages start with bytes no other context's
// can. This pins those first bytes. A new format the CA signs must be added here, with first bytes of its own.
func TestCASigningInputsAreDisjoint(t *testing.T) {
	// A v1 signed message is the canonical protobuf of its details, which starts with the tag of the lowest field
	// present. Every v1 certificate has a public key, validate refuses one without when signing and parsing alike, so
	// the lowest field present is the public key or one numbered below it, and the first bytes are their tags.
	var v1 []byte
	fields := (&RawNebulaCertificateDetails{}).ProtoReflect().Descriptor().Fields()
	publicKey := fields.ByName("PublicKey").Number()
	for i := range fields.Len() {
		f := fields.Get(i)
		if f.Number() > publicKey {
			continue
		}
		wireType := protowire.VarintType
		switch {
		case f.IsList() && f.IsPacked(), f.Kind() == protoreflect.StringKind, f.Kind() == protoreflect.BytesKind:
			wireType = protowire.BytesType
		case f.Kind() == protoreflect.MessageKind, f.Kind() == protoreflect.GroupKind,
			f.Kind() == protoreflect.Fixed32Kind, f.Kind() == protoreflect.Fixed64Kind,
			f.Kind() == protoreflect.FloatKind, f.Kind() == protoreflect.DoubleKind:
			t.Fatalf("v1 field %s is a %v, extend this test for it", f.Name(), f.Kind())
		}
		v1 = append(v1, protowire.AppendTag(nil, f.Number(), wireType)[0])
	}
	slices.Sort(v1)
	assert.Equal(t, []byte{0x0a, 0x12, 0x1a, 0x22, 0x28, 0x30, 0x3a}, v1,
		"the first bytes of v1 signed messages, as docs/pq-handshake.md lists them")
	noKey := &certificateV1{details: detailsV1{name: "ca", isCA: true}}
	require.ErrorIs(t, noKey.validate(), ErrInvalidPublicKey, "the public key the first bytes rest on is required")

	// A v2 signed message starts with its details element, which the parser requires.
	const v2 = byte(TagCertDetails)
	assert.Equal(t, byte(0xa0), v2)

	// A v3 composite signed message starts with the prefix of draft-ietf-lamps-pq-composite-sigs.
	v3 := compositeSignaturePrefix[0]
	assert.Equal(t, byte(0x43), v3)

	// No two contexts share a first byte.
	assert.NotContains(t, v1, v2)
	assert.NotContains(t, v1, v3)
	assert.NotEqual(t, v2, v3)

	// And the certificates really are signed over messages that start so.
	now := time.Now()
	for _, curve := range []Curve{Curve_CURVE25519, Curve_P256} {
		ca1, _, caKey1, _ := NewTestCaCert(Version1, curve, now, now.Add(time.Hour), nil, nil, nil)
		host1, _, _, _ := NewTestCert(Version1, curve, ca1, caKey1, "host", now, now.Add(time.Hour), []netip.Prefix{netip.MustParsePrefix("10.1.0.1/16")}, nil, nil)
		for _, c := range []Certificate{ca1, host1} {
			b, err := c.(*certificateV1).marshalForSigning()
			require.NoError(t, err)
			assert.Contains(t, v1, b[0])
		}

		ca2, _, caKey2, _ := NewTestCaCert(Version2, curve, now, now.Add(time.Hour), nil, nil, nil)
		host2, _, _, _ := NewTestCert(Version2, curve, ca2, caKey2, "host", now, now.Add(time.Hour), []netip.Prefix{netip.MustParsePrefix("10.1.0.1/16")}, nil, nil)
		for _, c := range []Certificate{ca2, host2} {
			b, err := c.(*certificateV2).marshalForSigning()
			require.NoError(t, err)
			assert.Equal(t, v2, b[0])
		}

		skipWithoutPQ(t)
		ca3, _, host3, _ := newTestV3(t, curve)
		for _, c := range []Certificate{ca3, host3} {
			m, err := c.(*certificateV3).messagePrime()
			require.NoError(t, err)
			assert.Equal(t, compositeSignaturePrefix, string(m[:len(compositeSignaturePrefix)]))
			// The v2 form inside is signed as any v2 certificate is.
			b, err := c.(*certificateV3).v2.marshalForSigning()
			require.NoError(t, err)
			assert.Equal(t, v2, b[0])
		}
	}
}
