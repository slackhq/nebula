package handshake

import (
	"testing"

	"github.com/flynn/noise"
	"github.com/slackhq/nebula/header"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSubtypeInfo(t *testing.T) {
	t.Run("IX", func(t *testing.T) {
		info, err := subtypeInfoFor(header.HandshakeIXPSK0)
		require.NoError(t, err)
		assert.Equal(t, noise.HandshakeIX.Name, info.pattern.Name)
		require.Len(t, info.msgs, 2)
		// msg1: payload + cert
		assert.True(t, info.msgs[0].expectsPayload)
		assert.True(t, info.msgs[0].expectsCert)
		// msg2: payload + cert
		assert.True(t, info.msgs[1].expectsPayload)
		assert.True(t, info.msgs[1].expectsCert)
	})

	t.Run("XX", func(t *testing.T) {
		registerTestXXInfo(t)
		info, err := subtypeInfoFor(header.HandshakeXXPSK0)
		require.NoError(t, err)
		assert.Equal(t, noise.HandshakeXX.Name, info.pattern.Name)
		require.Len(t, info.msgs, 3)
		// msg1: payload only
		assert.True(t, info.msgs[0].expectsPayload)
		assert.False(t, info.msgs[0].expectsCert)
		// msg2: payload + cert
		assert.True(t, info.msgs[1].expectsPayload)
		assert.True(t, info.msgs[1].expectsCert)
		// msg3: cert only
		assert.False(t, info.msgs[2].expectsPayload)
		assert.True(t, info.msgs[2].expectsCert)
	})

	t.Run("unknown subtype returns error", func(t *testing.T) {
		_, err := subtypeInfoFor(99)
		require.ErrorIs(t, err, ErrUnknownSubtype)
	})
}

// registerTestXXInfo temporarily registers XX subtype info for testing.
func registerTestXXInfo(t *testing.T) {
	t.Helper()
	subtypeInfos[header.HandshakeXXPSK0] = subtypeInfo{
		pattern: noise.HandshakeXX,
		msgs: []msgFlags{
			{expectsPayload: true, expectsCert: false},
			{expectsPayload: true, expectsCert: true},
			{expectsPayload: false, expectsCert: true},
		},
	}
	t.Cleanup(func() {
		delete(subtypeInfos, header.HandshakeXXPSK0)
	})
}
