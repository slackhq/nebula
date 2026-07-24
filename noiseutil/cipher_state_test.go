package noiseutil

import (
	"crypto/fips140"
	"testing"

	"github.com/flynn/noise"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCipherStateAESGCMRoundtrip(t *testing.T) {
	enc, dec := buildCipherStates(t, CipherAESGCM)
	roundtrip(t, NewCipherState(enc, CipherAESGCM), NewCipherState(dec, CipherAESGCM))
}

func TestCipherStateChaChaPolyRoundtrip(t *testing.T) {
	enc, dec := buildCipherStates(t, noise.CipherChaChaPoly)
	roundtrip(t, NewCipherState(enc, noise.CipherChaChaPoly), NewCipherState(dec, noise.CipherChaChaPoly))
}

func TestNewCipherStateDispatch(t *testing.T) {
	encA, _ := buildCipherStates(t, CipherAESGCM)
	encC, _ := buildCipherStates(t, noise.CipherChaChaPoly)

	if !boringEnabled && !fips140.Enabled() {
		assert.IsType(t, &CipherStateAESGCM{}, NewCipherState(encA, CipherAESGCM))
	} else {
		// fips140
		assert.IsType(t, encA.Cipher(), NewCipherState(encA, CipherAESGCM))
	}

	assert.IsType(t, &CipherStateChaChaPoly{}, NewCipherState(encC, noise.CipherChaChaPoly))
}

func TestNewCipherStateUnsupportedPanics(t *testing.T) {
	enc, _ := buildCipherStates(t, noise.CipherChaChaPoly)
	assert.Panics(t, func() {
		NewCipherState(enc, fakeCipher{})
	})
}

type fakeCipher struct{}

func (fakeCipher) Cipher(k [32]byte) noise.Cipher { return nil }
func (fakeCipher) CipherName() string             { return "Fake" }

// buildCipherStates runs an in-memory NN handshake with the requested cipher
// to produce a pair of post-handshake CipherStates that share keys.
func buildCipherStates(t *testing.T, c noise.CipherFunc) (*noise.CipherState, *noise.CipherState) {
	t.Helper()
	suite := noise.NewCipherSuite(noise.DH25519, c, noise.HashSHA256)
	cfg := noise.Config{CipherSuite: suite, Pattern: noise.HandshakeNN}
	cfg.Initiator = true
	hsI, err := noise.NewHandshakeState(cfg)
	require.NoError(t, err)
	cfg.Initiator = false
	hsR, err := noise.NewHandshakeState(cfg)
	require.NoError(t, err)

	msg, _, _, err := hsI.WriteMessage(nil, nil)
	require.NoError(t, err)
	_, _, _, err = hsR.ReadMessage(nil, msg)
	require.NoError(t, err)

	msg, dR, _, err := hsR.WriteMessage(nil, nil)
	require.NoError(t, err)
	_, eI, _, err := hsI.ReadMessage(nil, msg)
	require.NoError(t, err)
	require.NotNil(t, eI)
	require.NotNil(t, dR)

	// noise returns (cs1, cs2) where cs1 is the initiator->responder cipher.
	return eI, dR
}

func roundtrip(t *testing.T, enc, dec CipherState) {
	t.Helper()
	plaintext := []byte("nebula cipher state roundtrip")
	ad := []byte("aad")
	nb := make([]byte, 12)

	ct, err := enc.EncryptDanger(nil, ad, plaintext, 1, nb)
	require.NoError(t, err)
	assert.NotEqual(t, plaintext, ct)

	pt, err := dec.DecryptDanger(nil, ad, ct, 1, nb)
	require.NoError(t, err)
	assert.Equal(t, plaintext, pt)

	// Wrong nonce must fail authentication.
	_, err = dec.DecryptDanger(nil, ad, ct, 2, nb)
	require.Error(t, err)

	assert.Equal(t, enc.Overhead(), dec.Overhead())
	assert.Equal(t, 16, enc.Overhead())
}

func BenchmarkCipherStateEncryptAESGCM(b *testing.B) {
	enc, _ := buildCipherStatesB(b, CipherAESGCM)
	benchEncryptCipherState(b, NewCipherState(enc, CipherAESGCM))
}

func BenchmarkCipherStateEncryptChaChaPoly(b *testing.B) {
	enc, _ := buildCipherStatesB(b, noise.CipherChaChaPoly)
	benchEncryptCipherState(b, NewCipherState(enc, noise.CipherChaChaPoly))
}

func benchEncryptCipherState(b *testing.B, cs CipherState) {
	plaintext := make([]byte, 1280)
	ad := make([]byte, 16)
	nb := make([]byte, 12)
	out := make([]byte, 0, len(plaintext)+cs.Overhead())
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		var err error
		out, err = cs.EncryptDanger(out[:0], ad, plaintext, uint64(i+1), nb)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func buildCipherStatesB(b *testing.B, c noise.CipherFunc) (*noise.CipherState, *noise.CipherState) {
	b.Helper()
	suite := noise.NewCipherSuite(noise.DH25519, c, noise.HashSHA256)
	cfg := noise.Config{CipherSuite: suite, Pattern: noise.HandshakeNN}
	cfg.Initiator = true
	hsI, err := noise.NewHandshakeState(cfg)
	if err != nil {
		b.Fatal(err)
	}
	cfg.Initiator = false
	hsR, err := noise.NewHandshakeState(cfg)
	if err != nil {
		b.Fatal(err)
	}
	msg, _, _, err := hsI.WriteMessage(nil, nil)
	if err != nil {
		b.Fatal(err)
	}
	if _, _, _, err := hsR.ReadMessage(nil, msg); err != nil {
		b.Fatal(err)
	}
	msg, dR, _, err := hsR.WriteMessage(nil, nil)
	if err != nil {
		b.Fatal(err)
	}
	_, eI, _, err := hsI.ReadMessage(nil, msg)
	if err != nil {
		b.Fatal(err)
	}
	return eI, dR
}

func TestCipherStateNilSafety(t *testing.T) {
	var aes *CipherStateAESGCM
	_, err := aes.EncryptDanger(nil, nil, nil, 0, make([]byte, 12))
	require.Error(t, err)
	out, err := aes.DecryptDanger(nil, nil, nil, 0, make([]byte, 12))
	require.NoError(t, err)
	assert.Empty(t, out)
	assert.Equal(t, 0, aes.Overhead())

	var cc *CipherStateChaChaPoly
	_, err = cc.EncryptDanger(nil, nil, nil, 0, make([]byte, 12))
	require.Error(t, err)
	out, err = cc.DecryptDanger(nil, nil, nil, 0, make([]byte, 12))
	require.NoError(t, err)
	assert.Empty(t, out)
	assert.Equal(t, 0, cc.Overhead())
}
