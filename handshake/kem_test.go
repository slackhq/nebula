package handshake

import (
	"bytes"
	"crypto/mlkem"
	"net/netip"
	"testing"
	"time"

	"github.com/flynn/noise"
	"github.com/slackhq/nebula/cert"
	ct "github.com/slackhq/nebula/cert_test"
	"github.com/slackhq/nebula/header"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newKEMMachine(t *testing.T, cs *testCertState, v CertVerifier, initiator bool, index uint32) *Machine {
	t.Helper()
	m, err := NewMachine(
		cs.version, cs.getCredential, v,
		func() (uint32, error) { return index, nil },
		initiator, header.HandshakeIXPSK2MLKEM1024,
	)
	require.NoError(t, err)
	return m
}

type kemFixture struct {
	initCS, respCS *testCertState
	v              CertVerifier
}

func newKEMFixture(t *testing.T, cipher noise.CipherFunc) kemFixture {
	ca, _, caKey, _ := ct.NewTestCaCert(
		cert.Version2, cert.Curve_CURVE25519, time.Time{}, time.Time{}, nil, nil, nil,
	)
	return kemFixture{
		initCS: newTestCertStateWithCipher(t, ca, caKey, "initiator", []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")}, cipher),
		respCS: newTestCertStateWithCipher(t, ca, caKey, "responder", []netip.Prefix{netip.MustParsePrefix("10.0.0.2/24")}, cipher),
		v:      testVerifier(ct.NewTestCAPool(ca)),
	}
}

func requireKeysMatch(t *testing.T, a, b *Result) {
	t.Helper()
	c, err := a.EKey.Encrypt(nil, nil, []byte("hello"))
	require.NoError(t, err)
	p, err := b.DKey.Decrypt(nil, nil, c)
	require.NoError(t, err)
	assert.Equal(t, []byte("hello"), p)

	c, err = b.EKey.Encrypt(nil, nil, []byte("world"))
	require.NoError(t, err)
	p, err = a.DKey.Decrypt(nil, nil, c)
	require.NoError(t, err)
	assert.Equal(t, []byte("world"), p)
}

func TestKEMHandshake(t *testing.T) {
	for _, cipher := range []noise.CipherFunc{noise.CipherChaChaPoly, noise.CipherAESGCM} {
		t.Run(cipher.CipherName(), func(t *testing.T) {
			f := newKEMFixture(t, cipher)
			initM := newKEMMachine(t, f.initCS, f.v, true, 1000)
			respM := newKEMMachine(t, f.respCS, f.v, false, 2000)

			msg1, err := initM.Initiate(nil)
			require.NoError(t, err)
			assert.Equal(t, header.HandshakeIXPSK2MLKEM1024, header.MessageSubType(msg1[1]))
			assert.Greater(t, len(msg1), header.Len+mlkem.EncapsulationKeySize1024)

			msg2, respR, err := respM.ProcessPacket(nil, msg1)
			require.NoError(t, err)
			require.NotNil(t, respR)
			assert.Greater(t, len(msg2), header.Len+mlkem.CiphertextSize1024)

			_, initR, err := initM.ProcessPacket(nil, msg2)
			require.NoError(t, err)
			require.NotNil(t, initR)

			assert.Equal(t, "responder", initR.RemoteCert.Certificate.Name())
			assert.Equal(t, "initiator", respR.RemoteCert.Certificate.Name())
			assert.Equal(t, uint32(2000), initR.RemoteIndex)
			assert.Equal(t, uint32(1000), respR.RemoteIndex)
			requireKeysMatch(t, initR, respR)
		})
	}
}

// TestKEMSecretMatters checks the ML-KEM secret really reaches the transport
// keys: an initiator holding a different decapsulation key cannot complete even
// though every DH input is genuine.
func TestKEMSecretMatters(t *testing.T) {
	f := newKEMFixture(t, noise.CipherChaChaPoly)
	initM := newKEMMachine(t, f.initCS, f.v, true, 1000)
	respM := newKEMMachine(t, f.respCS, f.v, false, 2000)

	msg1, err := initM.Initiate(nil)
	require.NoError(t, err)
	msg2, _, err := respM.ProcessPacket(nil, msg1)
	require.NoError(t, err)

	other, err := mlkem.GenerateKey1024()
	require.NoError(t, err)
	initM.kemKey = other

	_, res, err := initM.ProcessPacket(nil, msg2)
	require.Error(t, err)
	assert.Nil(t, res)
}

func TestKEMTamperedCiphertext(t *testing.T) {
	f := newKEMFixture(t, noise.CipherChaChaPoly)
	initM := newKEMMachine(t, f.initCS, f.v, true, 1000)
	respM := newKEMMachine(t, f.respCS, f.v, false, 2000)

	msg1, err := initM.Initiate(nil)
	require.NoError(t, err)
	msg2, respR, err := respM.ProcessPacket(nil, msg1)
	require.NoError(t, err)

	t.Run("truncated", func(t *testing.T) {
		_, res, err := initM.ProcessPacket(nil, msg2[:header.Len+mlkem.CiphertextSize1024-1])
		require.ErrorIs(t, err, ErrPacketTooShort)
		assert.Nil(t, res)
		assert.False(t, initM.Failed())
	})

	t.Run("flipped ciphertext bit", func(t *testing.T) {
		bad := bytes.Clone(msg2)
		bad[header.Len+10] ^= 1
		_, res, err := initM.ProcessPacket(nil, bad)
		require.Error(t, err)
		assert.Nil(t, res)
		assert.False(t, initM.Failed(), "a forged ciphertext must not kill the handshake")
	})

	t.Run("genuine response still completes", func(t *testing.T) {
		_, initR, err := initM.ProcessPacket(nil, msg2)
		require.NoError(t, err)
		require.NotNil(t, initR)
		requireKeysMatch(t, initR, respR)
	})
}

// TestKEMBadMsg1 drives processPayload by hand. With the psk modifier msg1's
// payload is encrypted under a key derived from the public ephemeral, so a
// forged payload would need re-encrypting; the parsing rules are what matter.
func TestKEMBadMsg1(t *testing.T) {
	f := newKEMFixture(t, noise.CipherChaChaPoly)
	msg1Flags := subtypeInfos[header.HandshakeIXPSK2MLKEM1024].msgs[0]
	cert := f.initCS.creds[cert.Version2]
	payload := func(kemKey []byte) []byte {
		return MarshalPayload(nil, Payload{
			Cert:           cert.Bytes,
			CertVersion:    uint32(cert.Cert.Version()),
			InitiatorIndex: 1000,
			Time:           1,
			KEMKey:         kemKey,
		})
	}
	dk, err := mlkem.GenerateKey1024()
	require.NoError(t, err)

	t.Run("missing KEM key", func(t *testing.T) {
		m := newKEMMachine(t, f.respCS, f.v, false, 2000)
		err := m.processPayload(payload(nil), msg1Flags)
		require.ErrorIs(t, err, ErrUnexpectedContent)
		assert.True(t, m.Failed())
	})

	t.Run("invalid KEM key", func(t *testing.T) {
		m := newKEMMachine(t, f.respCS, f.v, false, 2000)
		// Coefficients of 0xfff exceed the modulus, which ML-KEM must reject.
		bad := bytes.Repeat([]byte{0xff}, mlkem.EncapsulationKeySize1024)
		err := m.kemEncapsulate(bad)
		require.ErrorIs(t, err, ErrInvalidKEMKey)
		err = m.kemEncapsulate(bad[:100])
		require.ErrorIs(t, err, ErrInvalidKEMKey)
	})

	t.Run("valid KEM key", func(t *testing.T) {
		m := newKEMMachine(t, f.respCS, f.v, false, 2000)
		require.NoError(t, m.kemEncapsulate(dk.EncapsulationKey().Bytes()))
		assert.Len(t, m.kemCiphertext, mlkem.CiphertextSize1024)
	})

	t.Run("KEM key on the classical subtype", func(t *testing.T) {
		m := newTestMachine(t, f.respCS, f.v, false, 2000)
		classical := subtypeInfos[header.HandshakeIXPSK0].msgs[0]
		err := m.processPayload(payload(dk.EncapsulationKey().Bytes()), classical)
		require.ErrorIs(t, err, ErrUnexpectedContent)
		assert.True(t, m.Failed())
	})
}

// TestKEMDistinctFromClassical makes sure the two subtypes cannot be mixed: a
// classical responder cannot answer a KEM initiator.
func TestKEMDistinctFromClassical(t *testing.T) {
	f := newKEMFixture(t, noise.CipherChaChaPoly)
	initM := newKEMMachine(t, f.initCS, f.v, true, 1000)
	respM := newTestMachine(t, f.respCS, f.v, false, 2000)

	msg1, err := initM.Initiate(nil)
	require.NoError(t, err)
	_, _, err = respM.ProcessPacket(nil, msg1)
	require.ErrorIs(t, err, ErrSubtypeMismatch)
}
