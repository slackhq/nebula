package handshake

import (
	"net/netip"
	"testing"
	"time"

	"github.com/slackhq/nebula/cert"
	ct "github.com/slackhq/nebula/cert_test"
	"github.com/slackhq/nebula/header"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestLaneMachine is newTestMachine with a lane advert attached.
func newTestLaneMachine(
	t *testing.T,
	cs *testCertState,
	verifier CertVerifier,
	initiator bool,
	localIndex uint32,
	lanes *LaneDetails,
) *Machine {
	t.Helper()
	m, err := NewMachine(
		cs.version, cs.getCredential,
		verifier, func() (uint32, error) { return localIndex, nil },
		initiator, header.HandshakeIXPSK0,
		lanes,
	)
	require.NoError(t, err)
	return m
}

func doFullLaneHandshake(t *testing.T, initLanes, respLanes *LaneDetails) (initR, respR *Result) {
	t.Helper()
	ca, _, caKey, _ := ct.NewTestCaCert(
		cert.Version2, cert.Curve_CURVE25519, time.Time{}, time.Time{}, nil, nil, nil,
	)
	caPool := ct.NewTestCAPool(ca)
	v := testVerifier(caPool)

	initCS := newTestCertState(t, ca, caKey, "initiator", []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")})
	respCS := newTestCertState(t, ca, caKey, "responder", []netip.Prefix{netip.MustParsePrefix("10.0.0.2/24")})

	initM := newTestLaneMachine(t, initCS, v, true, 1000, initLanes)
	respM := newTestLaneMachine(t, respCS, v, false, 2000, respLanes)

	msg1, err := initM.Initiate(nil)
	require.NoError(t, err)

	resp, respR, err := respM.ProcessPacket(nil, msg1)
	require.NoError(t, err)
	require.NotNil(t, respR)

	_, initR, err = initM.ProcessPacket(nil, resp)
	require.NoError(t, err)
	require.NotNil(t, initR)
	return initR, respR
}

func TestMachineLaneAdvertBothSides(t *testing.T) {
	initR, respR := doFullLaneHandshake(t,
		&LaneDetails{PortCount: 8, BasePort: 4242},
		&LaneDetails{PortCount: 4, BasePort: 5353},
	)

	// Each side's Result carries the peer's advert.
	assert.Equal(t, uint32(4), initR.PeerPortCount)
	assert.Equal(t, uint32(5353), initR.PeerBasePort)
	assert.Equal(t, uint32(0), initR.PeerLaneIndex)

	assert.Equal(t, uint32(8), respR.PeerPortCount)
	assert.Equal(t, uint32(4242), respR.PeerBasePort)
	assert.Equal(t, uint32(0), respR.PeerLaneIndex)
}

func TestMachineLaneHandshakeCarriesLaneIndex(t *testing.T) {
	// A lane handshake: initiator tags its lane number; responder still
	// adverts (harmlessly).
	initR, respR := doFullLaneHandshake(t,
		&LaneDetails{PortCount: 8, BasePort: 4242, LaneIndex: 3},
		&LaneDetails{PortCount: 4, BasePort: 5353},
	)

	assert.Equal(t, uint32(3), respR.PeerLaneIndex)
	assert.Equal(t, uint32(0), initR.PeerLaneIndex)
}

func TestMachineLaneAdvertAsymmetric(t *testing.T) {
	// Vanilla initiator, multiport responder and vice versa: the nil side
	// yields all-zero peer fields on the other end.
	initR, respR := doFullLaneHandshake(t, nil, &LaneDetails{PortCount: 4, BasePort: 5353})
	assert.Equal(t, uint32(4), initR.PeerPortCount)
	assert.Equal(t, uint32(0), respR.PeerPortCount)
	assert.Equal(t, uint32(0), respR.PeerBasePort)

	initR, respR = doFullLaneHandshake(t, &LaneDetails{PortCount: 8, BasePort: 4242}, nil)
	assert.Equal(t, uint32(0), initR.PeerPortCount)
	assert.Equal(t, uint32(8), respR.PeerPortCount)
}

func TestMachineLaneAdvertOutOfRangeIgnored(t *testing.T) {
	// A BasePort that can't be a real UDP port is ignored, not fatal.
	initR, respR := doFullLaneHandshake(t,
		&LaneDetails{PortCount: 8, BasePort: 70000},
		&LaneDetails{PortCount: 4, BasePort: 5353},
	)
	assert.Equal(t, uint32(0), respR.PeerPortCount)
	assert.Equal(t, uint32(0), respR.PeerBasePort)
	// The sane side still negotiates.
	assert.Equal(t, uint32(4), initR.PeerPortCount)
}
