package nebula

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewPsk(t *testing.T) {
	t.Run("mode none", func(t *testing.T) {
		p, err := NewPsk(PskNone, nil, 1)
		assert.NoError(t, err)
		assert.Equal(t, PskNone, p.mode)
		assert.Empty(t, p.key)

		assert.Len(t, p.Cache, 1)
		assert.Nil(t, p.Cache[0])

		b, err := p.MakeFor(0)
		assert.Equal(t, []byte{}, b)
	})

	t.Run("mode transitional", func(t *testing.T) {
		p, err := NewPsk(PskTransitional, nil, 1)
		assert.Error(t, ErrNotEnoughPskKeys, err)

		p, err = NewPsk(PskTransitional, []string{"1234567"}, 1)
		assert.Error(t, ErrKeyTooShort)

		p, err = NewPsk(PskTransitional, []string{"hi there friends"}, 1)
		assert.NoError(t, err)
		assert.Equal(t, PskTransitional, p.mode)
		assert.Empty(t, p.key)

		assert.Len(t, p.Cache, 2)
		assert.Nil(t, p.Cache[0])

		expectedCache := []byte{146, 120, 135, 31, 158, 102, 45, 189, 128, 190, 37, 101, 58, 254, 6, 166, 91, 209, 148, 131, 27, 193, 24, 25, 170, 65, 130, 189, 7, 179, 255, 17}
		assert.Equal(t, expectedCache, p.Cache[1])

		b, err := p.MakeFor(0)
		assert.Equal(t, []byte{}, b)
	})

	t.Run("mode enforced", func(t *testing.T) {
		p, err := NewPsk(PskEnforced, nil, 1)
		assert.Error(t, ErrNotEnoughPskKeys, err)

		p, err = NewPsk(PskEnforced, []string{"hi there friends"}, 1)
		assert.NoError(t, err)
		assert.Equal(t, PskEnforced, p.mode)

		expectedKey := []byte{156, 103, 171, 88, 121, 92, 138, 240, 170, 240, 76, 108, 154, 66, 107, 14, 226, 148, 177, 0, 40, 28, 220, 136, 68, 53, 63, 183, 213, 9, 192, 218}
		assert.Equal(t, expectedKey, p.key)

		assert.Len(t, p.Cache, 1)
		expectedCache := []byte{146, 120, 135, 31, 158, 102, 45, 189, 128, 190, 37, 101, 58, 254, 6, 166, 91, 209, 148, 131, 27, 193, 24, 25, 170, 65, 130, 189, 7, 179, 255, 17}
		assert.Equal(t, expectedCache, p.Cache[0])

		expectedPsk := []byte{0xd9, 0x16, 0xa3, 0x66, 0x6a, 0x20, 0x26, 0xcf, 0x5d, 0x93, 0xad, 0xa3, 0x88, 0x2d, 0x57, 0xac, 0x9b, 0xc3, 0x5a, 0xb7, 0x8f, 0x6, 0x71, 0xc4, 0x3e, 0x5, 0x9e, 0xbc, 0x4e, 0xc8, 0x24, 0x17}
		b, err := p.MakeFor(0)
		assert.Equal(t, expectedPsk, b)

		// Make sure different vpn ips generate different psks
		expectedPsk = []byte{0x92, 0x78, 0x87, 0x1f, 0x9e, 0x66, 0x2d, 0xbd, 0x80, 0xbe, 0x25, 0x65, 0x3a, 0xfe, 0x6, 0xa6, 0x5b, 0xd1, 0x94, 0x83, 0x1b, 0xc1, 0x18, 0x19, 0xaa, 0x41, 0x82, 0xbd, 0x7, 0xb3, 0xff, 0x11}
		b, err = p.MakeFor(1)
		assert.Equal(t, expectedPsk, b)
	})
}

func BenchmarkPsk_MakeFor(b *testing.B) {
	p, err := NewPsk(PskEnforced, []string{"hi there friends"}, 1)
	assert.NoError(b, err)

	for n := 0; n < b.N; n++ {
		p.MakeFor(99)
	}
}
