package pq

// IdentityCodec encodes/decodes the opaque PqPskIdentity blob gossiped in
// NebulaMetaDetails. The wire bytes are provider-defined; core obtains them
// via Encode and recovers the binding hash + the two provider ports via
// Decode. Core stores those to serve its PQ-PSK provider, but never parses
// the blob layout itself — that lives in the provider's codec.
type IdentityCodec interface {
	// Encode packs this node's binding hash and the two provider ports into
	// the opaque wire blob. Returns nil to advertise nothing (e.g. no hash).
	Encode(bindingHash []byte, portA, portB uint16) []byte
	// Decode parses a peer's opaque blob into the binding hash and the two
	// provider ports. ok is false for absent/garbage blobs. The returned
	// bindingHash is expected to be cert.PqPskBindingLen bytes; core drops
	// (and warns about) any other length, so a codec that returns a
	// different-length hash effectively gossips no usable binding.
	Decode(blob []byte) (bindingHash []byte, portA, portB uint16, ok bool)
}

// NoopIdentityCodec is the default when no PQ-PSK provider is active: it
// advertises nothing and parses nothing, preserving pre-PQ wire behaviour.
type NoopIdentityCodec struct{}

func (NoopIdentityCodec) Encode([]byte, uint16, uint16) []byte              { return nil }
func (NoopIdentityCodec) Decode([]byte) (hash []byte, a, b uint16, ok bool) { return nil, 0, 0, false }
