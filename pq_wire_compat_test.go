package nebula

import (
	"bytes"
	"testing"

	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/pq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPqPskIdentityWireFieldNumber is a wire-compatibility guard. The canonical
// opaque PQ-PSK identity gossip MUST stay on protobuf field number 11 (it moved
// off tag 8 when the deprecated legacy RosenpassPubkeySha256/Port/DiscoveryPort
// fields were restored at 8/9/10 for one-release interop). Changing the field
// number would silently break gossip interop between mixed-version nodes, so we
// assert the encoded tag byte directly: field 11, wire type 2
// (length-delimited) => 11<<3 | 2 = 0x5a.
func TestPqPskIdentityWireFieldNumber(t *testing.T) {
	d := &NebulaMetaDetails{PqPskIdentity: []byte{1, 2, 3}}
	b, err := d.Marshal()
	require.NoError(t, err)
	require.NotEmpty(t, b, "empty marshal output")

	const wantTag = byte(11<<3 | 2) // 0x5a
	if b[0] != wantTag {
		t.Fatalf("PqPskIdentity not on wire field 11: first tag byte = %#x, want %#x", b[0], wantTag)
	}
}

// TestLegacyPqGossipWireFieldNumbers guards that the deprecated legacy PQ
// gossip fields still marshal at their historical tags 8/9/10, so this binary
// stays interop-readable by pre-opaque-blob (master-format) peers. The first
// tag byte for each field, marshalled in isolation, is field<<3 | wiretype:
//   - RosenpassPubkeySha256 (bytes, wt 2)  => 8<<3 | 2  = 0x42
//   - RosenpassPort         (varint, wt 0) => 9<<3 | 0  = 0x48
//   - DiscoveryPort         (varint, wt 0) => 10<<3 | 0 = 0x50
func TestLegacyPqGossipWireFieldNumbers(t *testing.T) {
	t.Run("RosenpassPubkeySha256", func(t *testing.T) {
		b, err := (&NebulaMetaDetails{RosenpassPubkeySha256: []byte{1, 2, 3}}).Marshal()
		require.NoError(t, err)
		require.NotEmpty(t, b)
		assert.Equal(t, byte(8<<3|2), b[0], "RosenpassPubkeySha256 must marshal at field 8")
	})
	t.Run("RosenpassPort", func(t *testing.T) {
		b, err := (&NebulaMetaDetails{RosenpassPort: 51820}).Marshal()
		require.NoError(t, err)
		require.NotEmpty(t, b)
		assert.Equal(t, byte(9<<3|0), b[0], "RosenpassPort must marshal at field 9")
	})
	t.Run("DiscoveryPort", func(t *testing.T) {
		b, err := (&NebulaMetaDetails{DiscoveryPort: 51840}).Marshal()
		require.NoError(t, err)
		require.NotEmpty(t, b)
		assert.Equal(t, byte(10<<3|0), b[0], "DiscoveryPort must marshal at field 10")
	})
}

// TestPqIdentityFromDetails_MasterFormatInbound proves backward-compat READ:
// a NebulaMetaDetails populated with ONLY the legacy 8/9/10 fields (as a
// pre-opaque-blob "master" peer would emit) is correctly understood by the
// receive-path precedence helper, recovering the hash + both ports even
// though PqPskIdentity (field 11) is empty.
func TestPqIdentityFromDetails_MasterFormatInbound(t *testing.T) {
	hash := bytes.Repeat([]byte{0xab}, cert.PqPskBindingLen)
	d := &NebulaMetaDetails{
		RosenpassPubkeySha256: hash,
		RosenpassPort:         51820,
		DiscoveryPort:         51840,
		// PqPskIdentity intentionally empty — old peer.
	}

	// Round-trip through the actual wire to be faithful to a real inbound msg.
	b, err := d.Marshal()
	require.NoError(t, err)
	var got NebulaMetaDetails
	require.NoError(t, got.Unmarshal(b))

	// Any codec works here since the blob is empty and we fall back to legacy;
	// use the noop codec to prove no provider is consulted on the legacy path.
	gotHash, gotRP, gotDisc, apply := pqIdentityFromDetails(pq.NoopIdentityCodec{}, &got)
	require.True(t, apply, "legacy-only inbound must be applied")
	assert.Equal(t, hash, gotHash, "must recover legacy hash from master-format peer")
	assert.Equal(t, uint32(51820), gotRP, "must recover legacy rosenpass port")
	assert.Equal(t, uint32(51840), gotDisc, "must recover legacy discovery port")
}

// TestPqIdentityFromDetails_BlobPreferredOverLegacy verifies the precedence
// rule: when both the opaque blob (field 11) and the legacy fields are
// present, the decoded blob wins.
func TestPqIdentityFromDetails_BlobPreferredOverLegacy(t *testing.T) {
	legacyHash := bytes.Repeat([]byte{0x11}, cert.PqPskBindingLen)
	blobHash := bytes.Repeat([]byte{0x22}, cert.PqPskBindingLen)

	d := &NebulaMetaDetails{
		RosenpassPubkeySha256: legacyHash,
		RosenpassPort:         1111,
		DiscoveryPort:         2222,
		PqPskIdentity:         fakeEncode(blobHash, 3333, 4444),
	}

	gotHash, gotRP, gotDisc, apply := pqIdentityFromDetails(fakeCodec{}, d)
	require.True(t, apply)
	assert.Equal(t, blobHash, gotHash, "blob hash must win over legacy")
	assert.Equal(t, uint32(3333), gotRP, "blob rosenpass port must win over legacy")
	assert.Equal(t, uint32(4444), gotDisc, "blob discovery port must win over legacy")
}

// TestPqIdentityFromDetails_GarbageBlobFallsBackToLegacy verifies that a
// non-decodable blob does not shadow usable legacy fields — the helper falls
// through to 8/9/10 rather than returning empty.
func TestPqIdentityFromDetails_GarbageBlobFallsBackToLegacy(t *testing.T) {
	legacyHash := bytes.Repeat([]byte{0x11}, cert.PqPskBindingLen)
	d := &NebulaMetaDetails{
		RosenpassPubkeySha256: legacyHash,
		RosenpassPort:         1111,
		DiscoveryPort:         2222,
		PqPskIdentity:         []byte{0x01, 0x02, 0x03}, // garbage: fakeDecode rejects.
	}

	gotHash, gotRP, gotDisc, apply := pqIdentityFromDetails(fakeCodec{}, d)
	require.True(t, apply, "garbage blob WITH legacy fallback must still be applied")
	assert.Equal(t, legacyHash, gotHash, "must fall back to legacy hash on garbage blob")
	assert.Equal(t, uint32(1111), gotRP)
	assert.Equal(t, uint32(2222), gotDisc)
}

// TestPqIdentityFromDetails_GarbageBlobNoLegacyIsNoop verifies that a
// non-decodable blob with NO legacy fields is reported apply=false: corruption
// must not masquerade as a retraction and clear a valid prior claim.
func TestPqIdentityFromDetails_GarbageBlobNoLegacyIsNoop(t *testing.T) {
	d := &NebulaMetaDetails{PqPskIdentity: []byte{0x01, 0x02, 0x03}}
	_, _, _, apply := pqIdentityFromDetails(fakeCodec{}, d)
	assert.False(t, apply, "garbage blob with no legacy fallback must be a no-op")
}

// TestPqIdentityFromDetails_EmptyIsRetraction verifies that a fully empty
// update (no blob, no legacy fields) is reported apply=true so the setter's
// clear-on-empty branch runs and a peer can retract a prior claim.
func TestPqIdentityFromDetails_EmptyIsRetraction(t *testing.T) {
	hash, rpPort, discPort, apply := pqIdentityFromDetails(fakeCodec{}, &NebulaMetaDetails{})
	assert.True(t, apply, "empty update must be applied (retraction)")
	assert.Empty(t, hash)
	assert.Zero(t, rpPort)
	assert.Zero(t, discPort)
}
