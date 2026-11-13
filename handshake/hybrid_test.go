package handshake

import (
	"crypto/mlkem"
	"net/netip"
	"testing"
	"time"

	"github.com/DefinedNet/noise"
	"github.com/slackhq/nebula/cert"
	ct "github.com/slackhq/nebula/cert_test"
	"github.com/slackhq/nebula/header"
	"github.com/slackhq/nebula/noiseutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const hybridCurve = cert.Curve_P384_MLKEM1024_MLDSA87

func skipWithoutHybrid(t *testing.T) {
	t.Helper()
	if err := cert.HybridAvailable(); err != nil {
		t.Skip(err)
	}
}

var hybridCipherSuite = noise.NewCipherSuite(noiseutil.DHP384, noise.CipherAESGCM, noise.HashSHA512)

// newHybridCertState builds a peer holding a certificate on the hybrid curve, the way the pki does.
func newHybridCertState(t *testing.T, ca cert.Certificate, caKey []byte, name string, network string) (*testCertState, []byte) {
	t.Helper()
	c, _, rawPrivKey, _ := ct.NewTestCert(
		cert.Version2, hybridCurve, ca, caKey,
		name, ca.NotBefore(), ca.NotAfter(), []netip.Prefix{netip.MustParsePrefix(network)}, nil, nil,
	)
	priv, _, _, err := cert.UnmarshalPrivateKeyFromPEM(rawPrivKey)
	require.NoError(t, err)
	return hybridCertStateFor(t, c, priv), priv
}

func hybridCertStateFor(t *testing.T, c cert.Certificate, priv []byte) *testCertState {
	t.Helper()
	hs, err := c.MarshalForHandshakes()
	require.NoError(t, err)
	return &testCertState{
		version: cert.Version2,
		creds:   map[cert.Version]*Credential{cert.Version2: NewCredential(c, hs, priv, hybridCipherSuite)},
	}
}

func newHybridMachine(t *testing.T, cs *testCertState, verifier CertVerifier, initiator bool, localIndex uint32) *Machine {
	t.Helper()
	m, err := NewMachine(
		cert.Version2, cs.getCredential,
		verifier, func() (uint32, error) { return localIndex, nil },
		initiator, header.HandshakeIXHybrid,
	)
	require.NoError(t, err)
	return m
}

type hybridPeers struct {
	pool               *cert.CAPool
	ca                 cert.Certificate
	caKey              []byte
	initCS, respCS     *testCertState
	initPriv, respPriv []byte
}

func newHybridPeers(t *testing.T) hybridPeers {
	t.Helper()
	skipWithoutHybrid(t)
	ca, _, caKey, _ := ct.NewTestCaCert(cert.Version2, hybridCurve, time.Now().Add(-time.Hour), time.Now().Add(time.Hour), nil, nil, nil)
	pool := cert.NewCAPool()
	require.NoError(t, pool.AddCA(ca))
	initCS, initPriv := newHybridCertState(t, ca, caKey, "initiator", "10.0.0.1/24")
	respCS, respPriv := newHybridCertState(t, ca, caKey, "responder", "10.0.0.2/24")
	return hybridPeers{pool: pool, ca: ca, caKey: caKey, initCS: initCS, respCS: respCS, initPriv: initPriv, respPriv: respPriv}
}

func TestHybridIX(t *testing.T) {
	p := newHybridPeers(t)
	v := testVerifier(p.pool)
	initM := newHybridMachine(t, p.initCS, v, true, 1000)
	respM := newHybridMachine(t, p.respCS, v, false, 2000)

	msg1, err := initM.Initiate(nil)
	require.NoError(t, err)

	// The responder answers msg1 but can not complete until msg3.
	msg2, respResult, err := respM.ProcessPacket(nil, msg1)
	require.NoError(t, err)
	require.Nil(t, respResult)
	require.NotEmpty(t, msg2)

	// The initiator completes by writing msg3.
	msg3, initResult, err := initM.ProcessPacket(nil, msg2)
	require.NoError(t, err)
	require.NotNil(t, initResult)
	require.NotEmpty(t, msg3)

	out, respResult, err := respM.ProcessPacket(nil, msg3)
	require.NoError(t, err)
	require.Nil(t, out)
	require.NotNil(t, respResult)

	t.Logf("msg1 %d B, msg2 %d B, msg3 %d B", len(msg1), len(msg2), len(msg3))
	for i, msg := range [][]byte{msg1, msg2, msg3} {
		h := &header.H{}
		require.NoError(t, h.Parse(msg))
		assert.Equal(t, header.HandshakeIXHybrid, h.Subtype)
		assert.Equal(t, uint64(i+1), h.MessageCounter)
	}

	assert.Equal(t, uint32(2000), initResult.RemoteIndex)
	assert.Equal(t, uint32(1000), respResult.RemoteIndex)
	assert.Equal(t, hybridCurve, initResult.RemoteCert.Certificate.Curve())
	assert.Equal(t, hybridCurve, respResult.RemoteCert.Certificate.Curve())
	assert.Equal(t, "responder", initResult.RemoteCert.Certificate.Name())
	assert.Equal(t, "initiator", respResult.RemoteCert.Certificate.Name())
	assert.Equal(t, hybridCurve, initResult.MyCert.Curve())
	assert.Equal(t, uint64(3), initResult.MessageIndex)
	assert.Equal(t, uint64(3), respResult.MessageIndex)

	// The keys pair up in both directions.
	for _, pair := range [][2]*Result{{initResult, respResult}, {respResult, initResult}} {
		ct, err := pair[0].EKey.Encrypt(nil, nil, []byte("hello"))
		require.NoError(t, err)
		pt, err := pair[1].DKey.Decrypt(nil, nil, ct)
		require.NoError(t, err)
		assert.Equal(t, []byte("hello"), pt)
	}
}

// A hybrid handshake needs a certificate on the hybrid curve, and such a certificate needs a hybrid handshake.
func TestHybridIX_Curves(t *testing.T) {
	p := newHybridPeers(t)
	v := testVerifier(p.pool)

	_, err := NewMachine(cert.Version2, p.initCS.getCredential, v, func() (uint32, error) { return 1, nil }, true, header.HandshakeIXPSK0)
	require.ErrorIs(t, err, ErrCurveMismatch)

	ca, _, caKey, _ := ct.NewTestCaCert(cert.Version2, cert.Curve_CURVE25519, time.Now().Add(-time.Hour), time.Now().Add(time.Hour), nil, nil, nil)
	classical := newTestCertState(t, ca, caKey, "classical", []netip.Prefix{netip.MustParsePrefix("10.0.0.3/24")})
	_, err = NewMachine(cert.Version2, classical.getCredential, v, func() (uint32, error) { return 1, nil }, true, header.HandshakeIXHybrid)
	require.ErrorIs(t, err, ErrCurveMismatch)
}

// A responder that does not trust the hybrid CA can not verify the initiator.
func TestHybridIX_UntrustedCA(t *testing.T) {
	p := newHybridPeers(t)
	other, _, _, _ := ct.NewTestCaCert(cert.Version2, hybridCurve, time.Now().Add(-time.Hour), time.Now().Add(time.Hour), nil, nil, nil)
	pool := cert.NewCAPool()
	require.NoError(t, pool.AddCA(other))

	initM := newHybridMachine(t, p.initCS, testVerifier(p.pool), true, 1000)
	respM := newHybridMachine(t, p.respCS, testVerifier(pool), false, 2000)
	msg1, err := initM.Initiate(nil)
	require.NoError(t, err)
	_, _, err = respM.ProcessPacket(nil, msg1)
	require.ErrorIs(t, err, cert.ErrCaNotFound)
}

// A corrupted msg3 is dropped without killing the responder, and the real one still completes.
func TestHybridIX_CorruptMsg3(t *testing.T) {
	p := newHybridPeers(t)
	v := testVerifier(p.pool)
	initM := newHybridMachine(t, p.initCS, v, true, 1000)
	respM := newHybridMachine(t, p.respCS, v, false, 2000)

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

// withKEMKey returns a peer holding c and its P-384 private key, but some other ML-KEM key: someone who broke the
// P-384 key, say with a quantum computer, and wants to be that peer.
func withKEMKey(t *testing.T, c cert.Certificate, priv []byte) *testCertState {
	t.Helper()
	dk, err := mlkem.GenerateKey1024()
	require.NoError(t, err)
	scalar, _, err := cert.SplitHybridPrivateKey(priv)
	require.NoError(t, err)
	forged := append(append([]byte(nil), scalar...), dk.Bytes()...)
	return hybridCertStateFor(t, c, forged)
}

// The P-384 private key alone does not get anyone through as the initiator: msg2 is unreadable without the
// initiator's ML-KEM key.
func TestHybridIX_ImpersonateInitiator(t *testing.T) {
	p := newHybridPeers(t)
	v := testVerifier(p.pool)
	attacker := withKEMKey(t, p.initCS.creds[cert.Version2].Cert, p.initPriv)

	initM := newHybridMachine(t, attacker, v, true, 1000)
	respM := newHybridMachine(t, p.respCS, v, false, 2000)
	msg1, err := initM.Initiate(nil)
	require.NoError(t, err)
	msg2, _, err := respM.ProcessPacket(nil, msg1)
	require.NoError(t, err)

	_, res, err := initM.ProcessPacket(nil, msg2)
	require.Error(t, err)
	require.Nil(t, res)
}

// The P-384 private key alone does not get anyone through as the responder either: the initiator completes, but msg3
// is unreadable without the responder's ML-KEM key, so no packet under the new keys can ever come back.
func TestHybridIX_ImpersonateResponder(t *testing.T) {
	p := newHybridPeers(t)
	v := testVerifier(p.pool)
	attacker := withKEMKey(t, p.respCS.creds[cert.Version2].Cert, p.respPriv)

	initM := newHybridMachine(t, p.initCS, v, true, 1000)
	respM := newHybridMachine(t, attacker, v, false, 2000)
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
}
