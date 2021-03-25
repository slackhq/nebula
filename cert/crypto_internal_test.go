package cert

import (
	"fmt"
	"testing"

	"golang.org/x/crypto/argon2"
)

func BenchmarkAes256DeriveKey(b *testing.B) {
	for i := 0; i < b.N; i++ {
		aes256DeriveKey([]byte("test passphrase"), nil)
	}
}

var testMatrix = []struct {
	memory      uint32
	parallelism uint8
	iterations  uint32
}{
	// 1 GiB, parallelism = 4
	{1 * 1024 * 1024, 4, 3},
	{1 * 1024 * 1024, 4, 4},
	{1 * 1024 * 1024, 4, 6},
	{1 * 1024 * 1024, 4, 8},
	// 1 GiB, parallelism = 8
	{1 * 1024 * 1024, 8, 3},
	{1 * 1024 * 1024, 8, 4},
	{1 * 1024 * 1024, 8, 6},
	{1 * 1024 * 1024, 8, 8},

	// 2 GiB, parallelism = 4
	{2 * 1024 * 1024, 4, 3},
	{2 * 1024 * 1024, 4, 4},
	{2 * 1024 * 1024, 4, 6},
	{2 * 1024 * 1024, 4, 8},
	// 2 GiB, parallelism = 8
	{2 * 1024 * 1024, 8, 3},
	{2 * 1024 * 1024, 8, 4},
	{2 * 1024 * 1024, 8, 6},
	{2 * 1024 * 1024, 8, 8},
}

func BenchmarkAes256DeriveKeyMatrix(b *testing.B) {
	for _, tc := range testMatrix {
		b.Run(
			fmt.Sprintf("memory = %d, iterations = %d, parallelism = %d", tc.memory, tc.iterations, tc.parallelism),
			func(b *testing.B) {
				params := &argon2Parameters{
					version:     argon2.Version,
					memory:      tc.memory,
					iterations:  tc.iterations,
					parallelism: tc.parallelism,
				}

				for i := 0; i < b.N; i++ {
					aes256DeriveKey([]byte("test passphrase"), params)
				}
			})
	}
}
