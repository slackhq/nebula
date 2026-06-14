// Package rpidentity packs the rosenpass provider's identity (a 32-byte
// pubkey digest plus the rosenpass and discovery ports) into the opaque
// PqPskIdentity blob that nebula core gossips verbatim. Core never parses
// this; only the rosenpass provider does, through this package.
package rpidentity

import "encoding/binary"

const version = 1

// Encode packs the rosenpass pubkey digest plus the two ports into the
// opaque PqPskIdentity blob. hash must be exactly 32 bytes; otherwise
// Encode returns nil so a malformed identity is never gossiped.
func Encode(hash []byte, rpPort, discPort uint16) []byte {
	if len(hash) != 32 {
		return nil
	}
	b := make([]byte, 37)
	b[0] = version
	copy(b[1:33], hash)
	binary.BigEndian.PutUint16(b[33:35], rpPort)
	binary.BigEndian.PutUint16(b[35:37], discPort)
	return b
}

// Decode reverses Encode. ok is false for any blob that is nil, shorter
// than 37 bytes, or carries an unknown version byte — callers then treat
// the peer as advertising no PQ identity.
func Decode(blob []byte) (hash []byte, rpPort, discPort uint16, ok bool) {
	if len(blob) < 37 || blob[0] != version {
		return nil, 0, 0, false
	}
	hash = make([]byte, 32)
	copy(hash, blob[1:33])
	rpPort = binary.BigEndian.Uint16(blob[33:35])
	discPort = binary.BigEndian.Uint16(blob[35:37])
	return hash, rpPort, discPort, true
}

// Codec adapts this package's Encode/Decode to the pq.IdentityCodec interface
// so core can hold it without importing rosenpass-specific internals.
type Codec struct{}

func (Codec) Encode(hash []byte, portA, portB uint16) []byte    { return Encode(hash, portA, portB) }
func (Codec) Decode(blob []byte) ([]byte, uint16, uint16, bool) { return Decode(blob) }
