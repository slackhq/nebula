package handshake

import (
	"net/netip"
	"testing"
	"time"

	"github.com/DefinedNet/noise"
	"github.com/slackhq/nebula/cert"
	ct "github.com/slackhq/nebula/cert_test"
	"github.com/slackhq/nebula/header"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const pureCurve = cert.Curve_MLKEM1024_MLDSA87

var pureCipherSuite = noise.NewKEMCipherSuite(noise.CipherAESGCM, noise.HashSHA512)

func pureCertStateFor(t *testing.T, c cert.Certificate, priv []byte) *testCertState {
	t.Helper()
	hs, err := c.MarshalForHandshakes()
	require.NoError(t, err)
	return &testCertState{
		version: cert.Version2,
		creds:   map[cert.Version]*Credential{cert.Version2: NewCredential(c, hs, priv, pureCipherSuite)},
	}
}

func newPureCertState(t *testing.T, ca cert.Certificate, caKey []byte, name, network string) (*testCertState, []byte) {
	t.Helper()
	c, _, rawPrivKey, _ := ct.NewTestCert(
		cert.Version2, pureCurve, ca, caKey,
		name, ca.NotBefore(), ca.NotAfter(), []netip.Prefix{netip.MustParsePrefix(network)}, nil, nil,
	)
	priv, _, _, err := cert.UnmarshalPrivateKeyFromPEM(rawPrivKey)
	require.NoError(t, err)
	return pureCertStateFor(t, c, priv), priv
}

func newPQMachine(t *testing.T, cs *testCertState, verifier CertVerifier, initiator bool, localIndex uint32) *Machine {
	t.Helper()
	m, err := NewMachine(
		cert.Version2, cs.getCredential,
		verifier, func() (uint32, error) { return localIndex, nil },
		initiator, header.HandshakeIXPQ,
	)
	require.NoError(t, err)
	return m
}

func newPurePeers(t *testing.T) (pool *cert.CAPool, initCS, respCS *testCertState) {
	t.Helper()
	skipWithoutHybrid(t)
	ca, _, caKey, _ := ct.NewTestCaCert(cert.Version2, pureCurve, time.Now().Add(-time.Hour), time.Now().Add(time.Hour), nil, nil, nil)
	pool = cert.NewCAPool()
	require.NoError(t, pool.AddCA(ca))
	initCS, _ = newPureCertState(t, ca, caKey, "initiator", "10.0.0.1/24")
	respCS, _ = newPureCertState(t, ca, caKey, "responder", "10.0.0.2/24")
	return pool, initCS, respCS
}

func TestPQIX(t *testing.T) {
	pool, initCS, respCS := newPurePeers(t)
	v := testVerifier(pool)
	initM := newPQMachine(t, initCS, v, true, 1000)
	respM := newPQMachine(t, respCS, v, false, 2000)

	msg1, err := initM.Initiate(nil)
	require.NoError(t, err)
	msg2, respResult, err := respM.ProcessPacket(nil, msg1)
	require.NoError(t, err)
	require.Nil(t, respResult, "the responder waits for msg3")
	msg3, initResult, err := initM.ProcessPacket(nil, msg2)
	require.NoError(t, err)
	require.NotNil(t, initResult)
	out, respResult, err := respM.ProcessPacket(nil, msg3)
	require.NoError(t, err)
	require.Nil(t, out)
	require.NotNil(t, respResult)

	t.Logf("msg1 %d B, msg2 %d B, msg3 %d B", len(msg1)-header.Len, len(msg2)-header.Len, len(msg3)-header.Len)
	for i, msg := range [][]byte{msg1, msg2, msg3} {
		h := &header.H{}
		require.NoError(t, h.Parse(msg))
		assert.Equal(t, header.HandshakeIXPQ, h.Subtype)
		assert.Equal(t, uint64(i+1), h.MessageCounter)
	}
	assert.Equal(t, "responder", initResult.RemoteCert.Certificate.Name())
	assert.Equal(t, "initiator", respResult.RemoteCert.Certificate.Name())
	assert.Equal(t, pureCurve, initResult.RemoteCert.Certificate.Curve())

	for _, pair := range [][2]*Result{{initResult, respResult}, {respResult, initResult}} {
		c, err := pair[0].EKey.Encrypt(nil, nil, []byte("hello"))
		require.NoError(t, err)
		pt, err := pair[1].DKey.Decrypt(nil, nil, c)
		require.NoError(t, err)
		assert.Equal(t, []byte("hello"), pt)
	}
}

// Each curve goes with its own pattern: pure with ix_pq, hybrid with ix_hybrid, classical with ix_psk0.
func TestPQIX_Curves(t *testing.T) {
	pool, initCS, _ := newPurePeers(t)
	v := testVerifier(pool)
	alloc := func() (uint32, error) { return 1, nil }

	for _, st := range []header.MessageSubType{header.HandshakeIXPSK0, header.HandshakeIXHybrid} {
		_, err := NewMachine(cert.Version2, initCS.getCredential, v, alloc, true, st)
		require.ErrorIs(t, err, ErrCurveMismatch, "%s", header.SubTypeName(header.Handshake, st))
	}

	hca, _, hcaKey, _ := ct.NewTestCaCert(cert.Version2, hybridCurve, time.Now().Add(-time.Hour), time.Now().Add(time.Hour), nil, nil, nil)
	hybrid, _ := newHybridCertState(t, hca, hcaKey, "hybrid", "10.0.0.3/24")
	_, err := NewMachine(cert.Version2, hybrid.getCredential, v, alloc, true, header.HandshakeIXPQ)
	require.ErrorIs(t, err, ErrCurveMismatch)

	ca, _, caKey, _ := ct.NewTestCaCert(cert.Version2, cert.Curve_CURVE25519, time.Now().Add(-time.Hour), time.Now().Add(time.Hour), nil, nil, nil)
	classical := newTestCertState(t, ca, caKey, "classical", []netip.Prefix{netip.MustParsePrefix("10.0.0.4/24")})
	_, err = NewMachine(cert.Version2, classical.getCredential, v, alloc, true, header.HandshakeIXPQ)
	require.ErrorIs(t, err, ErrCurveMismatch)
}

// A corrupted msg3 is dropped without killing the responder, and the real one still completes.
func TestPQIX_CorruptMsg3(t *testing.T) {
	pool, initCS, respCS := newPurePeers(t)
	v := testVerifier(pool)
	initM := newPQMachine(t, initCS, v, true, 1000)
	respM := newPQMachine(t, respCS, v, false, 2000)
	msg1, err := initM.Initiate(nil)
	require.NoError(t, err)
	msg2, _, err := respM.ProcessPacket(nil, msg1)
	require.NoError(t, err)
	msg3, _, err := initM.ProcessPacket(nil, msg2)
	require.NoError(t, err)

	bad := append([]byte(nil), msg3...)
	bad[header.Len+10] ^= 1
	_, res, err := respM.ProcessPacket(nil, bad)
	require.Error(t, err)
	require.Nil(t, res)
	require.False(t, respM.Failed())
	_, res, err = respM.ProcessPacket(nil, msg3)
	require.NoError(t, err)
	require.NotNil(t, res)
}

// A responder that does not trust the initiator's CA refuses its msg1.
func TestPQIX_UntrustedCA(t *testing.T) {
	pool, initCS, respCS := newPurePeers(t)
	other, _, _, _ := ct.NewTestCaCert(cert.Version2, pureCurve, time.Now().Add(-time.Hour), time.Now().Add(time.Hour), nil, nil, nil)
	otherPool := cert.NewCAPool()
	require.NoError(t, otherPool.AddCA(other))

	initM := newPQMachine(t, initCS, testVerifier(pool), true, 1000)
	respM := newPQMachine(t, respCS, testVerifier(otherPool), false, 2000)
	msg1, err := initM.Initiate(nil)
	require.NoError(t, err)
	_, _, err = respM.ProcessPacket(nil, msg1)
	require.ErrorIs(t, err, cert.ErrCaNotFound)
}

// Someone holding a peer's certificate but not its ML-KEM key gets nowhere as either end: as the initiator it can not
// read msg2, as the responder it can not read msg3.
func TestPQIX_WrongKey(t *testing.T) {
	pool, initCS, respCS := newPurePeers(t)
	v := testVerifier(pool)
	_, otherKey, err := cert.GeneratePureKeypair()
	require.NoError(t, err)

	t.Run("initiator", func(t *testing.T) {
		attacker := pureCertStateFor(t, initCS.creds[cert.Version2].Cert, otherKey)
		initM := newPQMachine(t, attacker, v, true, 1000)
		respM := newPQMachine(t, respCS, v, false, 2000)
		msg1, err := initM.Initiate(nil)
		require.NoError(t, err)
		msg2, _, err := respM.ProcessPacket(nil, msg1)
		require.NoError(t, err)
		_, res, err := initM.ProcessPacket(nil, msg2)
		require.Error(t, err)
		require.Nil(t, res)
	})
	t.Run("responder", func(t *testing.T) {
		attacker := pureCertStateFor(t, respCS.creds[cert.Version2].Cert, otherKey)
		initM := newPQMachine(t, initCS, v, true, 1000)
		respM := newPQMachine(t, attacker, v, false, 2000)
		msg1, err := initM.Initiate(nil)
		require.NoError(t, err)
		msg2, _, err := respM.ProcessPacket(nil, msg1)
		require.NoError(t, err)
		msg3, initResult, err := initM.ProcessPacket(nil, msg2)
		require.NoError(t, err)
		require.NotNil(t, initResult)
		_, res, err := respM.ProcessPacket(nil, msg3)
		require.Error(t, err)
		require.Nil(t, res)
	})
}
