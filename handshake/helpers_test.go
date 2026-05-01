package handshake

import (
	"net/netip"
	"testing"
	"time"

	"github.com/flynn/noise"
	"github.com/slackhq/nebula/cert"
	ct "github.com/slackhq/nebula/cert_test"
	"github.com/slackhq/nebula/header"
	"github.com/stretchr/testify/require"
)

// testCertState holds cert material for a test peer.
type testCertState struct {
	version cert.Version
	creds   map[cert.Version]*Credential
}

func (s *testCertState) getCredential(v cert.Version) *Credential {
	return s.creds[v]
}

func newTestCertState(
	t *testing.T, ca cert.Certificate, caKey []byte, name string, networks []netip.Prefix,
) *testCertState {
	return newTestCertStateWithCipher(t, ca, caKey, name, networks, noise.CipherChaChaPoly)
}

func newTestCertStateWithCipher(
	t *testing.T, ca cert.Certificate, caKey []byte, name string, networks []netip.Prefix,
	cipher noise.CipherFunc,
) *testCertState {
	t.Helper()
	c, _, rawPrivKey, _ := ct.NewTestCert(
		cert.Version2, cert.Curve_CURVE25519, ca, caKey,
		name, ca.NotBefore(), ca.NotAfter(), networks, nil, nil,
	)

	priv, _, _, err := cert.UnmarshalPrivateKeyFromPEM(rawPrivKey)
	require.NoError(t, err)

	hsBytes, err := c.MarshalForHandshakes()
	require.NoError(t, err)

	ncs := noise.NewCipherSuite(noise.DH25519, cipher, noise.HashSHA256)
	return &testCertState{
		version: cert.Version2,
		creds: map[cert.Version]*Credential{
			cert.Version2: NewCredential(c, hsBytes, priv, ncs),
		},
	}
}

func testVerifier(pool *cert.CAPool) CertVerifier {
	return func(c cert.Certificate) (*cert.CachedCertificate, error) {
		return pool.VerifyCertificate(time.Now(), c)
	}
}

func newTestMachine(
	t *testing.T,
	cs *testCertState,
	verifier CertVerifier,
	initiator bool,
	localIndex uint32,
) *Machine {
	t.Helper()
	m, err := NewMachine(
		cs.version, cs.getCredential,
		verifier, func() (uint32, error) { return localIndex, nil },
		initiator, header.HandshakeIXPSK0,
	)
	require.NoError(t, err)
	return m
}

func initiateHandshake(
	t *testing.T,
	initCS *testCertState, initVerifier CertVerifier,
	respCS *testCertState, respVerifier CertVerifier,
) (initM, respM *Machine, respResult *Result, resp []byte, err error) {
	t.Helper()
	initM = newTestMachine(t, initCS, initVerifier, true, 100)
	msg1, merr := initM.Initiate(nil)
	require.NoError(t, merr)

	respM = newTestMachine(t, respCS, respVerifier, false, 200)
	resp, respResult, err = respM.ProcessPacket(nil, msg1)
	return
}

func doFullHandshake(
	t *testing.T, initCS, respCS *testCertState, caPool *cert.CAPool,
) (initResult, respResult *Result) {
	t.Helper()
	v := testVerifier(caPool)

	initM := newTestMachine(t, initCS, v, true, 1000)
	respM := newTestMachine(t, respCS, v, false, 2000)

	msg1, err := initM.Initiate(nil)
	require.NoError(t, err)

	resp, respResult, err := respM.ProcessPacket(nil, msg1)
	require.NoError(t, err)
	require.NotNil(t, respResult)
	require.NotEmpty(t, resp)

	_, initResult, err = initM.ProcessPacket(nil, resp)
	require.NoError(t, err)
	require.NotNil(t, initResult)

	return initResult, respResult
}
