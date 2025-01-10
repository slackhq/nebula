package nebula

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewPsk(t *testing.T) {
	t.Run("mode accepting", func(t *testing.T) {
		p, err := NewPsk(PskAccepting, nil)
		assert.NoError(t, err)
		assert.Equal(t, PskAccepting, p.mode)
		assert.Nil(t, p.keys[0])
		assert.Nil(t, p.primary)

		p, err = NewPsk(PskAccepting, []string{"1234567"})
		assert.Error(t, ErrKeyTooShort)

		p, err = NewPsk(PskAccepting, []string{"hi there friends"})
		assert.NoError(t, err)
		assert.Equal(t, PskAccepting, p.mode)
		assert.Nil(t, p.primary)
		assert.Len(t, p.keys, 2)
		assert.Nil(t, p.keys[1])

		expectedCache := []byte{
			0xb9, 0x8c, 0xdc, 0xac, 0x77, 0xf4, 0x8c, 0xf8, 0x1d, 0xe7, 0xe7, 0xb, 0x53, 0x25, 0xd3, 0x65,
			0xa3, 0x9f, 0x78, 0xb2, 0xc7, 0x2d, 0xa5, 0xd8, 0x84, 0x81, 0x7b, 0xb5, 0xdb, 0xe0, 0x9a, 0xef,
		}
		assert.Equal(t, expectedCache, p.keys[0])
	})

	t.Run("mode sending", func(t *testing.T) {
		p, err := NewPsk(PskSending, nil)
		assert.Error(t, ErrNotEnoughPskKeys, err)

		p, err = NewPsk(PskSending, []string{"1234567"})
		assert.Error(t, ErrKeyTooShort)

		p, err = NewPsk(PskSending, []string{"hi there friends"})
		assert.NoError(t, err)
		assert.Equal(t, PskSending, p.mode)
		assert.Len(t, p.keys, 2)
		assert.Nil(t, p.keys[1])

		expectedCache := []byte{
			0xb9, 0x8c, 0xdc, 0xac, 0x77, 0xf4, 0x8c, 0xf8, 0x1d, 0xe7, 0xe7, 0xb, 0x53, 0x25, 0xd3, 0x65,
			0xa3, 0x9f, 0x78, 0xb2, 0xc7, 0x2d, 0xa5, 0xd8, 0x84, 0x81, 0x7b, 0xb5, 0xdb, 0xe0, 0x9a, 0xef,
		}
		assert.Equal(t, expectedCache, p.keys[0])
		assert.Equal(t, p.keys[0], p.primary)
	})

	t.Run("mode enforced", func(t *testing.T) {
		p, err := NewPsk(PskEnforced, nil)
		assert.Error(t, ErrNotEnoughPskKeys, err)

		p, err = NewPsk(PskEnforced, []string{"hi there friends"})
		assert.NoError(t, err)
		assert.Equal(t, PskEnforced, p.mode)
		assert.Len(t, p.keys, 1)

		expectedCache := []byte{
			0xb9, 0x8c, 0xdc, 0xac, 0x77, 0xf4, 0x8c, 0xf8, 0x1d, 0xe7, 0xe7, 0xb, 0x53, 0x25, 0xd3, 0x65,
			0xa3, 0x9f, 0x78, 0xb2, 0xc7, 0x2d, 0xa5, 0xd8, 0x84, 0x81, 0x7b, 0xb5, 0xdb, 0xe0, 0x9a, 0xef,
		}
		assert.Equal(t, expectedCache, p.keys[0])
		assert.Equal(t, p.keys[0], p.primary)
	})
}
