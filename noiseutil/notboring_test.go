//go:build !boringcrypto
// +build !boringcrypto

package noiseutil

import (
	// NOTE: We have to force these imports here or boring_test.go fails to
	// compile correctly. This seems to be a Go bug:
	//
	//     $ GOEXPERIMENT=boringcrypto go test ./noiseutil
	//     # github.com/slackhq/nebula/noiseutil
	//     boring_test.go:10:2: cannot find package

	_ "github.com/stretchr/testify/assert"
)
