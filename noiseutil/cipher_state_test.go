package noiseutil

import (
	"testing"

	"github.com/flynn/noise"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCipherStateAESGCMRoundtrip(t *testing.T) {
	enc, dec := buildCipherStates(t, CipherAESGCM)
	roundtrip(t, NewCipherStateAESGCM(enc), NewCipherStateAESGCM(dec))
}

func TestCipherStateChaChaPolyRoundtrip(t *testing.T) {
	enc, dec := buildCipherStates(t, noise.CipherChaChaPoly)
	roundtrip(t, NewCipherStateChaChaPoly(enc), NewCipherStateChaChaPoly(dec))
}

func TestNewCipherStateDispatch(t *testing.T) {
	encA, _ := buildCipherStates(t, CipherAESGCM)
	encC, _ := buildCipherStates(t, noise.CipherChaChaPoly)

	assert.IsType(t, &CipherStateAESGCM{}, NewCipherState(encA, CipherAESGCM))
	assert.IsType(t, &CipherStateChaChaPoly{}, NewCipherState(encC, noise.CipherChaChaPoly))
}

func TestNewCipherStateUnsupportedPanics(t *testing.T) {
	enc, _ := buildCipherStates(t, CipherAESGCM)
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

// TestDecryptDangerRelayShapeNoAlloc covers the AD-only relay path used in
// outside.go's handleOutsideRelayPacket: the body is AD, the trailing 16 bytes
// are the AEAD tag, the plaintext is empty, and the caller passes nil as the
// destination because it only needs the auth side-effect. The call must
// succeed, return an empty plaintext, and not allocate on the hot path.
func TestDecryptDangerRelayShapeNoAlloc(t *testing.T) {
	cases := []struct {
		name string
		c    noise.CipherFunc
		wrap func(*noise.CipherState) CipherState
	}{
		{"AESGCM", CipherAESGCM, func(cs *noise.CipherState) CipherState { return NewCipherStateAESGCM(cs) }},
		{"ChaChaPoly", noise.CipherChaChaPoly, func(cs *noise.CipherState) CipherState { return NewCipherStateChaChaPoly(cs) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			encCS, decCS := buildCipherStates(t, tc.c)
			enc, dec := tc.wrap(encCS), tc.wrap(decCS)

			ad := make([]byte, 1200) // typical relay packet body size
			for i := range ad {
				ad[i] = byte(i)
			}
			nb := make([]byte, 12)

			// Build the "signature value" the way handleOutsideRelayPacket sees it:
			// empty plaintext encrypted with the body as AD yields just the 16-byte tag.
			tag, err := enc.EncryptDanger(nil, ad, nil, 1, nb)
			require.NoError(t, err)
			require.Len(t, tag, dec.Overhead())

			// Sanity: the relay-shaped call returns empty plaintext, no error.
			out, err := dec.DecryptDanger(nil, ad, tag, 1, nb)
			require.NoError(t, err)
			assert.Empty(t, out)

			// Tampering with the AD must fail authentication.
			ad[0] ^= 0xff
			_, err = dec.DecryptDanger(nil, ad, tag, 1, nb)
			require.Error(t, err)
			ad[0] ^= 0xff

			// The hot path must not allocate. AllocsPerRun does a warm-up run, so any
			// one-time setup is excluded. Counter has to advance so the AEAD nonce is
			// unique per call, but we don't care whether the auth succeeds — we only
			// care about whether the call path allocates.
			var counter uint64 = 2
			allocs := testing.AllocsPerRun(100, func() {
				_, _ = dec.DecryptDanger(nil, ad, tag, counter, nb)
				counter++
			})
			assert.Equal(t, 0.0, allocs, "DecryptDanger(nil, ...) must not allocate")
		})
	}
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
