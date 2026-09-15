package nebula

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"testing"

	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/sshd"
	"github.com/stretchr/testify/assert"
)

type stubControlHostLister struct{}

func (stubControlHostLister) QueryVpnAddr(netip.Addr) *HostInfo  { return nil }
func (stubControlHostLister) ForEachIndex(controlEach)           {}
func (stubControlHostLister) ForEachVpnAddr(controlEach)         {}
func (stubControlHostLister) GetPreferredRanges() []netip.Prefix { return nil }

type alwaysFailWriter struct{}

func (alwaysFailWriter) Write([]byte) (int, error) { return 0, errors.New("injected write failure") }

type stringWriterOver struct{ w io.Writer }

func (s stringWriterOver) WriteLine(str string) error {
	_, err := s.w.Write([]byte(str + "\n"))
	return err
}
func (s stringWriterOver) Write(str string) error  { _, err := s.w.Write([]byte(str)); return err }
func (s stringWriterOver) WriteBytes(b []byte) error { _, err := s.w.Write(b); return err }
func (s stringWriterOver) GetWriter() io.Writer    { return s.w }

func TestSshListHostMap_EncodeFailure_LogsAndMeters(t *testing.T) {
	var logBuf bytes.Buffer
	l := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	// Read the package var directly; other tests call UnregisterAll().
	counterBefore := metricSshEncodeErrors.Count()

	var _ sshd.StringWriter = stringWriterOver{} // compile-time interface check
	sw := stringWriterOver{w: alwaysFailWriter{}}

	err := sshListHostMap(l, stubControlHostLister{}, &sshListHostMapFlags{Json: true}, sw)

	assert.NoError(t, err)
	assert.Equal(t, int64(1), metricSshEncodeErrors.Count()-counterBefore)
	assert.Contains(t, logBuf.String(), "ssh: failed to encode host-map output")
}

func TestSshListLighthouseMap_EncodeFailure_LogsAndMeters(t *testing.T) {
	var logBuf bytes.Buffer
	l := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	counterBefore := metricSshEncodeErrors.Count()

	sw := stringWriterOver{w: alwaysFailWriter{}}
	lh := newTestLighthouse()

	err := sshListLighthouseMap(l, lh, &sshListHostMapFlags{Json: true}, sw)

	assert.NoError(t, err)
	assert.Equal(t, int64(1), metricSshEncodeErrors.Count()-counterBefore)
	assert.Contains(t, logBuf.String(), "ssh: failed to encode lighthouse-map output")
}

type brokenJSONCert struct{ *dummyCert }

func (brokenJSONCert) MarshalJSON() ([]byte, error) { return nil, errors.New("injected MarshalJSON failure") }

type invalidJSONCert struct{ *dummyCert }

func (invalidJSONCert) MarshalJSON() ([]byte, error) { return []byte("{not valid json"), nil }

type brokenPEMCert struct{ *dummyCert }

func (brokenPEMCert) MarshalPEM() ([]byte, error) { return nil, errors.New("injected MarshalPEM failure") }

func newTestIfaceWithDefaultCert(t *testing.T, c cert.Certificate) *Interface {
	t.Helper()
	pki := &PKI{}
	pki.cs.Store(&CertState{v2Cert: c, initiatingVersion: cert.Version2})
	return &Interface{pki: pki}
}

func TestSshPrintCert_MarshalJSONFailure_LogsAndMeters(t *testing.T) {
	var logBuf bytes.Buffer
	l := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	counterBefore := metricSshEncodeErrors.Count()

	ifce := newTestIfaceWithDefaultCert(t, brokenJSONCert{&dummyCert{version: cert.Version2}})
	var buf bytes.Buffer
	sw := stringWriterOver{w: &buf}

	err := sshPrintCert(l, ifce, &sshPrintCertFlags{Json: true}, nil, sw)

	assert.NoError(t, err)
	assert.Equal(t, int64(1), metricSshEncodeErrors.Count()-counterBefore)
	assert.Contains(t, logBuf.String(), "ssh: failed to marshal print-cert json")
}

// TestSshPrintCert_IndentFailure_NoPartialWrite covers the reorder fix:
// the handler must not call w.WriteBytes when json.Indent errors.
func TestSshPrintCert_IndentFailure_NoPartialWrite(t *testing.T) {
	var logBuf bytes.Buffer
	l := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	counterBefore := metricSshEncodeErrors.Count()

	ifce := newTestIfaceWithDefaultCert(t, invalidJSONCert{&dummyCert{version: cert.Version2}})
	var written bytes.Buffer
	sw := stringWriterOver{w: &written}

	err := sshPrintCert(l, ifce, &sshPrintCertFlags{Pretty: true}, nil, sw)

	assert.NoError(t, err)
	assert.Equal(t, int64(1), metricSshEncodeErrors.Count()-counterBefore)
	assert.Contains(t, logBuf.String(), "ssh: failed to indent print-cert json")
	assert.Empty(t, written.Bytes(), "no partial buffer must be written on json.Indent failure")
}

func TestSshPrintCert_MarshalPEMFailure_LogsAndMeters(t *testing.T) {
	var logBuf bytes.Buffer
	l := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	counterBefore := metricSshEncodeErrors.Count()

	ifce := newTestIfaceWithDefaultCert(t, brokenPEMCert{&dummyCert{version: cert.Version2}})
	var buf bytes.Buffer
	sw := stringWriterOver{w: &buf}

	err := sshPrintCert(l, ifce, &sshPrintCertFlags{Raw: true}, nil, sw)

	assert.NoError(t, err)
	assert.Equal(t, int64(1), metricSshEncodeErrors.Count()-counterBefore)
	assert.Contains(t, logBuf.String(), "ssh: failed to marshal print-cert pem")
}
