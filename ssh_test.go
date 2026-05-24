package nebula

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"testing"

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

func (s stringWriterOver) WriteLine(string) error  { return nil }
func (s stringWriterOver) Write(string) error      { return nil }
func (s stringWriterOver) WriteBytes([]byte) error { return nil }
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
