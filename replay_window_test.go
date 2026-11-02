package nebula

import (
	"testing"

	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/header"
	"github.com/slackhq/nebula/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBitsGrow(t *testing.T) {
	l := test.NewLogger()
	b := NewBits(16)
	b.lostCounter.Clear()
	b.dupeCounter.Clear()

	// Accept 1..40 except 30 and 35
	for i := uint64(1); i <= 40; i++ {
		if i != 30 && i != 35 {
			require.True(t, b.Update(l, i))
		}
	}
	lost := b.lostCounter.Count()
	b.grow(64)
	assert.Equal(t, uint64(64), b.length)
	assert.Equal(t, uint64(40), b.current)

	// The old window's state is kept, 30 and 35 are still unseen and 40 is seen
	assert.True(t, b.Check(l, 30))
	assert.True(t, b.Check(l, 35))
	assert.False(t, b.Check(l, 40))
	// Counters the old window had slid past are marked seen, they can't be told apart from replays
	assert.False(t, b.Check(l, 20))
	assert.False(t, b.Check(l, 1))

	// Moving on through the new window counts nothing lost for the marked range
	require.True(t, b.Update(l, 30))
	for i := uint64(41); i <= 200; i++ {
		require.True(t, b.Update(l, i))
	}
	assert.Equal(t, lost+1, b.lostCounter.Count(), "only 35 is lost once the window slides past it")
}

func TestBitsGrowWarmup(t *testing.T) {
	l := test.NewLogger()
	b := NewBits(16)
	for i := uint64(1); i <= 10; i++ {
		if i != 4 {
			require.True(t, b.Update(l, i))
		}
	}
	b.grow(64)
	assert.True(t, b.Check(l, 4))
	assert.False(t, b.Check(l, 5))
	assert.True(t, b.Check(l, 11))
}

// sealAt encrypts a one byte payload as counter c
func sealAt(t *testing.T, send *ConnectionState, c uint64, payload byte) []byte {
	t.Helper()
	nb := make([]byte, 12)
	hdr := header.Encode(make([]byte, header.Len, header.Len+64), header.Version, header.Message, 0, 1, c)
	out, err := send.eKey.EncryptDanger(hdr, hdr, []byte{payload}, c, nb)
	require.NoError(t, err)
	return out
}

func TestGrowReplayWindow(t *testing.T) {
	l := test.NewLogger()
	nb := make([]byte, 12)
	setup := func(t *testing.T, max uint64) (send, recv *ConnectionState) {
		initR, respR := runTestHandshake(t)
		send, err := newConnectionStateFromResult(initR, ReplayWindow, 0)
		require.NoError(t, err)
		recv, err = newTunnelConnectionState(respR, config.MultiPortConfig{ReplayWindow: ReplayWindow, ReplayWindowMax: max})
		require.NoError(t, err)
		return send, recv
	}
	decrypt := func(recv *ConnectionState, c uint64, pkt []byte) error {
		_, err := recv.Decrypt(l, c, pkt, nb)
		return err
	}

	t.Run("grows on an authentic late packet", func(t *testing.T) {
		send, recv := setup(t, 1<<16)
		require.NoError(t, decrypt(recv, 20000, sealAt(t, send, 20000, 1)))

		// 10000 behind is past the 8192 window, within 4x: dropped, and the window grows 4x
		assert.ErrorIs(t, decrypt(recv, 10000, sealAt(t, send, 10000, 2)), ErrAlreadySeen)
		assert.Equal(t, uint64(4*ReplayWindow), recv.window.length)

		// The next packet that late is accepted
		require.NoError(t, decrypt(recv, 30000, sealAt(t, send, 30000, 3)))
		require.NoError(t, decrypt(recv, 20001, sealAt(t, send, 20001, 4)))

		// Still late at the new size grows again, capped at the max
		require.NoError(t, decrypt(recv, 100000, sealAt(t, send, 100000, 5)))
		assert.ErrorIs(t, decrypt(recv, 60000, sealAt(t, send, 60000, 6)), ErrAlreadySeen)
		assert.Equal(t, uint64(1<<16), recv.window.length)

		// At the max nothing grows
		require.NoError(t, decrypt(recv, 300000, sealAt(t, send, 300000, 7)))
		assert.ErrorIs(t, decrypt(recv, 200000, sealAt(t, send, 200000, 8)), ErrAlreadySeen)
		assert.Equal(t, uint64(1<<16), recv.window.length)
	})

	t.Run("forged packets don't grow it", func(t *testing.T) {
		send, recv := setup(t, 1<<16)
		require.NoError(t, decrypt(recv, 20000, sealAt(t, send, 20000, 1)))
		forged := sealAt(t, send, 10000, 2)
		forged[len(forged)-1] ^= 1
		assert.ErrorIs(t, decrypt(recv, 10000, forged), ErrAlreadySeen)
		assert.Equal(t, uint64(ReplayWindow), recv.window.length)
	})

	t.Run("further than 4x behind doesn't grow it", func(t *testing.T) {
		send, recv := setup(t, 1<<16)
		require.NoError(t, decrypt(recv, 50000, sealAt(t, send, 50000, 1)))
		assert.ErrorIs(t, decrypt(recv, 50000-5*ReplayWindow, sealAt(t, send, 50000-5*ReplayWindow, 2)), ErrAlreadySeen)
		assert.Equal(t, uint64(ReplayWindow), recv.window.length)
	})

	t.Run("duplicates in the window don't grow it", func(t *testing.T) {
		send, recv := setup(t, 1<<16)
		pkt := sealAt(t, send, 20000, 1)
		dup := append([]byte(nil), pkt...)
		require.NoError(t, decrypt(recv, 20000, pkt))
		assert.ErrorIs(t, decrypt(recv, 20000, dup), ErrAlreadySeen)
		assert.Equal(t, uint64(ReplayWindow), recv.window.length)
	})

	t.Run("max at the window turns growth off", func(t *testing.T) {
		send, recv := setup(t, ReplayWindow)
		require.NoError(t, decrypt(recv, 20000, sealAt(t, send, 20000, 1)))
		assert.ErrorIs(t, decrypt(recv, 10000, sealAt(t, send, 10000, 2)), ErrAlreadySeen)
		assert.Equal(t, uint64(ReplayWindow), recv.window.length)
	})
}
