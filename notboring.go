//go:build !boringcrypto
// +build !boringcrypto

package nebula

var boringEnabled = func() bool { return false }
