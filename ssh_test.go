package nebula

import (
	"bytes"
	"errors"
	"io"
	"net/netip"
	"testing"

	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/test"
	"github.com/stretchr/testify/require"
)

// dummyCert is defined in connection_manager_test.go (same package).
// We only need its zero value to seed PKI.cs so sshPrintCert's
// unconditional getCertState().GetDefaultCertificate() call (called
// even when a vpn addr is supplied) doesn't panic. The variable holding
// the default cert is immediately overwritten by the per-host lookup,
// so the dummy never has any of its methods called.

// errInjected is the sentinel returned by failingWriter once its byte budget
// is exhausted. Tests assert it with errors.Is to confirm the propagated
// error preserves the wrapped cause.
var errInjected = errors.New("injected write failure")

// failingWriter is an io.Writer that returns errInjected once its cumulative
// written total reaches afterBytes. It is used to exercise the error paths
// of json.Encoder inside ssh handlers (sshListHostMap, sshListLighthouseMap)
// without depending on a real SSH session.
type failingWriter struct {
	afterBytes int
	written    int
}

func (f *failingWriter) Write(p []byte) (int, error) {
	remaining := f.afterBytes - f.written
	if remaining <= 0 {
		return 0, errInjected
	}
	if len(p) > remaining {
		f.written += remaining
		return remaining, errInjected
	}
	f.written += len(p)
	return len(p), nil
}

// recordingStringWriter is a sshd.StringWriter that delegates every call to a
// wrapped io.Writer. Tests pass either a bytes.Buffer (capture all output)
// or a failingWriter (exercise error paths).
type recordingStringWriter struct{ w io.Writer }

func (r *recordingStringWriter) WriteLine(s string) error {
	_, err := r.w.Write([]byte(s + "\n"))
	return err
}
func (r *recordingStringWriter) Write(s string) error      { _, err := r.w.Write([]byte(s)); return err }
func (r *recordingStringWriter) WriteBytes(b []byte) error { _, err := r.w.Write(b); return err }
func (r *recordingStringWriter) GetWriter() io.Writer      { return r.w }

// newTestHostMapWithEntries returns a *HostMap pre-populated with n HostInfo
// entries spread across the 192.168.0.0/16 vpn-address space. The map's
// preferredRanges atomic is initialized so listHostMapHosts can call
// GetPreferredRanges() without panicking.
func newTestHostMapWithEntries(t *testing.T, n int) *HostMap {
	t.Helper()
	l := test.NewLogger()
	hm := newHostMap(l)
	empty := []netip.Prefix{}
	hm.preferredRanges.Store(&empty)

	iface := &Interface{}
	for i := 0; i < n; i++ {
		addr := netip.AddrFrom4([4]byte{192, 168, byte(i / 256), byte(i % 256)})
		hi := &HostInfo{
			vpnAddrs:     []netip.Addr{addr},
			localIndexId: uint32(i + 1),
		}
		hm.unlockedAddHostInfo(hi, iface)
	}
	return hm
}

// errInjectedCert is the sentinel returned by the cert.Certificate test
// doubles used in sshPrintCert tests. Kept distinct from errInjected so
// failure traces immediately show whether the error originated in the
// writer (errInjected) or in the cert marshalling layer (errInjectedCert).
var errInjectedCert = errors.New("injected cert failure")

// brokenJSONCert is a cert.Certificate whose MarshalJSON always errors.
// The embedded cert.Certificate is nil; any other interface method panics
// if called. Tests using this double MUST set sshPrintCertFlags.Json or
// .Pretty so the handler never reaches the cert.String() fallthrough at
// ssh.go's print-cert function.
type brokenJSONCert struct{ cert.Certificate }

func (brokenJSONCert) MarshalJSON() ([]byte, error) { return nil, errInjectedCert }

// newTestInterfaceWithHostCert returns a minimal *Interface with hostMap
// containing one HostInfo at vpnAddr whose ConnectionState.peerCert wraps
// the provided cert.Certificate. The pki field is wired with a CertState
// whose default cert is a dummyCert because sshPrintCert evaluates the
// default cert unconditionally before the per-host lookup overrides it.
func newTestInterfaceWithHostCert(t *testing.T, vpnAddr netip.Addr, c cert.Certificate) *Interface {
	t.Helper()
	l := test.NewLogger()
	hm := newHostMap(l)
	empty := []netip.Prefix{}
	hm.preferredRanges.Store(&empty)

	hi := &HostInfo{
		vpnAddrs:     []netip.Addr{vpnAddr},
		localIndexId: 1,
		ConnectionState: &ConnectionState{
			peerCert: &cert.CachedCertificate{Certificate: c},
		},
	}
	hm.unlockedAddHostInfo(hi, &Interface{})

	cs, err := newCertState(
		cert.Version2,
		nil,
		&dummyCert{version: cert.Version2},
		false,
		cert.Curve_CURVE25519,
		nil,
		"aes",
	)
	require.NoError(t, err)
	pki := &PKI{}
	pki.cs.Store(cs)

	return &Interface{hostMap: hm, pki: pki}
}

// newTestLighthouseWithEntries returns a *LightHouse pre-populated with n
// entries in addrMap. Reuses newTestLighthouse from connection_manager_test.go
// (same package) for the surrounding initialization, then adds RemoteList
// entries spread across 192.168.0.0/16 so the JSON output is non-trivial.
func newTestLighthouseWithEntries(t *testing.T, n int) *LightHouse {
	t.Helper()
	lh := newTestLighthouse()
	for i := 0; i < n; i++ {
		addr := netip.AddrFrom4([4]byte{192, 168, byte(i / 256), byte(i % 256)})
		lh.addrMap[addr] = NewRemoteList([]netip.Addr{addr}, nil)
	}
	return lh
}

// TestSshListHostMap_WriteFailure_PropagatesError exercises the JSON-output
// path of sshListHostMap with a writer that fails after a configurable byte
// budget. The handler today returns nil on json.Encoder.Encode failure,
// silently truncating the SSH client's output with no diagnostic for the
// operator. Each row of this table represents one writer-failure shape.
func TestSshListHostMap_WriteFailure_PropagatesError(t *testing.T) {
	tests := []struct {
		name       string
		flags      *sshListHostMapFlags
		afterBytes int
	}{
		{"json mode, immediate writer failure", &sshListHostMapFlags{Json: true}, 0},
		{"json mode, mid-stream failure", &sshListHostMapFlags{Json: true}, 16},
		{"pretty mode, immediate writer failure", &sshListHostMapFlags{Pretty: true}, 0},
		{"pretty mode, mid-stream failure", &sshListHostMapFlags{Pretty: true}, 16},
		{"pretty mode, late failure", &sshListHostMapFlags{Pretty: true}, 256},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			hm := newTestHostMapWithEntries(t, 50)
			sw := &recordingStringWriter{w: &failingWriter{afterBytes: tc.afterBytes}}

			err := sshListHostMap(hm, tc.flags, sw)

			require.Error(t, err, "writer failure must propagate; got nil")
			require.ErrorIs(t, err, errInjected,
				"propagated error must wrap errInjected so callers can errors.Is the cause")
		})
	}
}

// TestSshPrintCert_MarshalJSONFails_PropagatesError exercises the json /
// pretty output paths of sshPrintCert with a cert.Certificate whose
// MarshalJSON always returns an error. The handler today returns nil on
// MarshalJSON failure, so an operator running `print-cert <addr> -json`
// against a host with an unmarshallable cert sees an empty successful
// response — no diagnostic, no hint that the cert exists but won't
// serialize. Both -json and -pretty flag modes route through MarshalJSON
// (-pretty calls it then re-formats), so both are exercised.
func TestSshPrintCert_MarshalJSONFails_PropagatesError(t *testing.T) {
	vpnAddr := netip.MustParseAddr("10.0.0.1")
	tests := []struct {
		name  string
		flags *sshPrintCertFlags
	}{
		{"json flag", &sshPrintCertFlags{Json: true}},
		{"pretty flag", &sshPrintCertFlags{Pretty: true}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ifce := newTestInterfaceWithHostCert(t, vpnAddr, brokenJSONCert{})
			sw := &recordingStringWriter{w: &bytes.Buffer{}}

			err := sshPrintCert(ifce, tc.flags, []string{vpnAddr.String()}, sw)

			require.Error(t, err, "MarshalJSON failure must propagate; got nil")
			require.ErrorIs(t, err, errInjectedCert,
				"propagated error must wrap errInjectedCert so callers can errors.Is the cause")
		})
	}
}

// TestSshListLighthouseMap_WriteFailure_PropagatesError mirrors the
// sshListHostMap test against sshListLighthouseMap, which has the same
// json.Encoder.Encode swallow bug a few hundred lines further down in
// ssh.go. The handler shares the same set of failure shapes — both flag
// modes and both immediate / mid-stream failure points — because the
// underlying encoder behavior is identical.
func TestSshListLighthouseMap_WriteFailure_PropagatesError(t *testing.T) {
	tests := []struct {
		name       string
		flags      *sshListHostMapFlags
		afterBytes int
	}{
		{"json mode, immediate writer failure", &sshListHostMapFlags{Json: true}, 0},
		{"json mode, mid-stream failure", &sshListHostMapFlags{Json: true}, 16},
		{"pretty mode, immediate writer failure", &sshListHostMapFlags{Pretty: true}, 0},
		{"pretty mode, mid-stream failure", &sshListHostMapFlags{Pretty: true}, 16},
		{"pretty mode, late failure", &sshListHostMapFlags{Pretty: true}, 256},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			lh := newTestLighthouseWithEntries(t, 50)
			sw := &recordingStringWriter{w: &failingWriter{afterBytes: tc.afterBytes}}

			err := sshListLighthouseMap(lh, tc.flags, sw)

			require.Error(t, err, "writer failure must propagate; got nil")
			require.ErrorIs(t, err, errInjected,
				"propagated error must wrap errInjected so callers can errors.Is the cause")
		})
	}
}
