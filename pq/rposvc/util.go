//go:build rosenpass_embedded

package rposvc

import (
	"crypto/sha256"
	"encoding/hex"
)

// hexFingerprint computes the lowercase hex SHA-256 of the input.
// Used to key peer registration tables by the nebula peer's static
// public key, matching the convention in the pq package.
func hexFingerprint(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// pubkeyHex computes the lowercase hex SHA-256 of the local
// Rosenpass static public key. This is the value that ends up in a
// nebula cert extension if cert binding is desired.
func pubkeyHex(pub []byte) string {
	return hexFingerprint(pub)
}
