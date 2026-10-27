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

func hybridCipherSuite(curve cert.Curve) noise.CipherSuite {
	if curve == cert.Curve_P256 {
		return noise.NewCipherSuite(noiseutil.DHP256, noise.CipherAESGCM, noise.HashSHA256)
	}
	return noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256)
}

// newHybridCertState builds a peer holding a v3 certificate, with credentials for it and for its v2 form, the way
// the pki does.
func newHybridCertState(t *testing.T, curve cert.Curve, ca cert.Certificate, caKey []byte, name string, network string) (*testCertState, []byte) {
	t.Helper()
	c, _, rawPrivKey, _ := ct.NewTestCert(
		cert.Version3, curve, ca, caKey,
		name, ca.NotBefore(), ca.NotAfter(), []netip.Prefix{netip.MustParsePrefix(network)}, nil, nil,
	)
	priv, _, _, err := cert.UnmarshalPrivateKeyFromPEM(rawPrivKey)
	require.NoError(t, err)
	return hybridCertStateFor(t, curve, c, priv), priv
}

func hybridCertStateFor(t *testing.T, curve cert.Curve, c cert.Certificate, priv []byte) *testCertState {
	t.Helper()
	hs3, err := c.MarshalForHandshakes()
	require.NoError(t, err)
	v2 := cert.V2Form(c)
	hs2, err := v2.MarshalForHandshakes()
	require.NoError(t, err)

	ncs := hybridCipherSuite(curve)
	return &testCertState{
		version: cert.Version3,
		creds: map[cert.Version]*Credential{
			cert.Version3: NewCredential(c, hs3, priv, ncs),
			cert.Version2: NewCredential(v2, hs2, priv[:len(priv)-cert.MLKEM1024PrivateKeySize], ncs),
		},
	}
}

func newHybridMachine(t *testing.T, cs *testCertState, verifier CertVerifier, initiator bool, localIndex uint32) *Machine {
	t.Helper()
	m, err := NewMachine(
		cert.Version3, cs.getCredential,
		verifier, func() (uint32, error) { return localIndex, nil },
		initiator, header.HandshakeIXHybridMLKEM1024,
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

func newHybridPeers(t *testing.T, curve cert.Curve) hybridPeers {
	t.Helper()
	ca, _, caKey, _ := ct.NewTestCaCert(cert.Version3, curve, time.Now().Add(-time.Hour), time.Now().Add(time.Hour), nil, nil, nil)
	pool := cert.NewCAPool()
	require.NoError(t, pool.AddCA(ca))
	initCS, initPriv := newHybridCertState(t, curve, ca, caKey, "initiator", "10.0.0.1/24")
	respCS, respPriv := newHybridCertState(t, curve, ca, caKey, "responder", "10.0.0.2/24")
	return hybridPeers{pool: pool, ca: ca, caKey: caKey, initCS: initCS, respCS: respCS, initPriv: initPriv, respPriv: respPriv}
}

func TestHybridIX(t *testing.T) {
	ct.SkipWithoutPQ(t)
	for _, curve := range []cert.Curve{cert.Curve_CURVE25519, cert.Curve_P256} {
		t.Run(curve.String(), func(t *testing.T) {
			p := newHybridPeers(t, curve)
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
				assert.Equal(t, header.HandshakeIXHybridMLKEM1024, h.Subtype)
				assert.Equal(t, uint64(i+1), h.MessageCounter)
			}

			assert.Equal(t, uint32(2000), initResult.RemoteIndex)
			assert.Equal(t, uint32(1000), respResult.RemoteIndex)
			assert.Equal(t, cert.Version3, initResult.RemoteCert.Certificate.Version())
			assert.Equal(t, cert.Version3, respResult.RemoteCert.Certificate.Version())
			assert.Equal(t, "responder", initResult.RemoteCert.Certificate.Name())
			assert.Equal(t, "initiator", respResult.RemoteCert.Certificate.Name())
			assert.Equal(t, cert.Version3, initResult.MyCert.Version())
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
		})
	}
}

// A hybrid handshake needs v3 certificates, and a v3 certificate needs a hybrid handshake.
func TestHybridIX_CertVersions(t *testing.T) {
	ct.SkipWithoutPQ(t)
	p := newHybridPeers(t, cert.Curve_CURVE25519)
	v := testVerifier(p.pool)

	_, err := NewMachine(cert.Version2, p.initCS.getCredential, v, func() (uint32, error) { return 1, nil }, true, header.HandshakeIXHybridMLKEM1024)
	require.ErrorIs(t, err, ErrCertVersionMismatch)
	_, err = NewMachine(cert.Version3, p.initCS.getCredential, v, func() (uint32, error) { return 1, nil }, true, header.HandshakeIXPSK0)
	require.ErrorIs(t, err, ErrCertVersionMismatch)

	// The v2 form still does a classical handshake, here with a peer that only has v2.
	ca2 := cert.V2Form(p.ca)
	pool2 := cert.NewCAPool()
	require.NoError(t, pool2.AddCA(ca2))
	classicalCAKey := p.caKey[:len(p.caKey)-cert.MLDSA87PrivateKeySize]
	v2Peer := newTestCertState(t, ca2, classicalCAKey, "v2peer", []netip.Prefix{netip.MustParsePrefix("10.0.0.3/24")})
	p.initCS.version = cert.Version2
	initResult, respResult := doFullHandshake(t, p.initCS, v2Peer, pool2)
	assert.Equal(t, cert.Version2, initResult.RemoteCert.Certificate.Version())
	assert.Equal(t, cert.Version2, respResult.RemoteCert.Certificate.Version())
	assert.Equal(t, cert.Version2, initResult.MyCert.Version())
}

// A responder that only trusts the v2 form of the CA can not verify a v3 certificate.
func TestHybridIX_V2TrustOnly(t *testing.T) {
	ct.SkipWithoutPQ(t)
	p := newHybridPeers(t, cert.Curve_CURVE25519)
	pool2 := cert.NewCAPool()
	require.NoError(t, pool2.AddCA(cert.V2Form(p.ca)))

	initM := newHybridMachine(t, p.initCS, testVerifier(p.pool), true, 1000)
	respM := newHybridMachine(t, p.respCS, testVerifier(pool2), false, 2000)
	msg1, err := initM.Initiate(nil)
	require.NoError(t, err)
	_, _, err = respM.ProcessPacket(nil, msg1)
	require.ErrorIs(t, err, cert.ErrCaNotFound)
}

// A corrupted msg3 is dropped without killing the responder, and the real one still completes.
func TestHybridIX_CorruptMsg3(t *testing.T) {
	ct.SkipWithoutPQ(t)
	p := newHybridPeers(t, cert.Curve_CURVE25519)
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

// withKEMKey returns a peer holding c and its classical private key, but some other ML-KEM key: someone who broke
// the classical key, say with a quantum computer, and wants to be that peer.
func withKEMKey(t *testing.T, curve cert.Curve, c cert.Certificate, priv []byte) *testCertState {
	t.Helper()
	dk, err := mlkem.GenerateKey1024()
	require.NoError(t, err)
	forged := append(append([]byte(nil), priv[:len(priv)-cert.MLKEM1024PrivateKeySize]...), dk.Bytes()...)
	return hybridCertStateFor(t, curve, c, forged)
}

// The classical private key alone does not get anyone through as the initiator: msg2 is unreadable without the
// initiator's ML-KEM key.
func TestHybridIX_ImpersonateInitiator(t *testing.T) {
	ct.SkipWithoutPQ(t)
	p := newHybridPeers(t, cert.Curve_CURVE25519)
	v := testVerifier(p.pool)
	victim := p.initCS.creds[cert.Version3].Cert
	attacker := withKEMKey(t, cert.Curve_CURVE25519, victim, p.initPriv)

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

// The classical private key alone does not get anyone through as the responder either: the initiator completes,
// but msg3 is unreadable without the responder's ML-KEM key, so no packet under the new keys can ever come back.
func TestHybridIX_ImpersonateResponder(t *testing.T) {
	ct.SkipWithoutPQ(t)
	p := newHybridPeers(t, cert.Curve_CURVE25519)
	v := testVerifier(p.pool)
	victim := p.respCS.creds[cert.Version3].Cert
	attacker := withKEMKey(t, cert.Curve_CURVE25519, victim, p.respPriv)

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
