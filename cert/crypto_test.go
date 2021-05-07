package cert

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/argon2"
)

func TestNewArgon2Parameters(t *testing.T) {
	p := NewArgon2Parameters(64*1024, 4, 3)
	assert.EqualValues(t, &Argon2Parameters{
		version:     argon2.Version,
		Memory:      64 * 1024,
		Parallelism: 4,
		Iterations:  3,
	}, p)
	p = NewArgon2Parameters(2*1024*1024, 2, 1)
	assert.EqualValues(t, &Argon2Parameters{
		version:     argon2.Version,
		Memory:      2 * 1024 * 1024,
		Parallelism: 2,
		Iterations:  1,
	}, p)
}
