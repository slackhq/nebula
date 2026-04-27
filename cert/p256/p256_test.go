package p256

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFlipping(t *testing.T) {
	priv, err1 := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err1)

	out, err := ecdsa.SignASN1(rand.Reader, priv, []byte("big chungus"))
	require.NoError(t, err)

	r, s, err := parseSignature(out)
	require.NoError(t, err)

	r, s1, err := swap(r, s)
	require.NoError(t, err)
	r, s2, err := swap(r, s1)
	require.NoError(t, err)
	require.Equal(t, s, s2)
	require.NotEqual(t, s, s1)
}
