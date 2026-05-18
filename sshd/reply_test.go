package sshd

import (
	"bytes"
	"errors"
	"log/slog"
	"testing"

	"github.com/rcrowley/go-metrics"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var errInjectedReply = errors.New("injected reply failure")

// fakeReplyer satisfies replyer with a configurable error return.
type fakeReplyer struct {
	err        error
	gotOK      bool
	gotPayload []byte
	calls      int
}

func (f *fakeReplyer) Reply(ok bool, payload []byte) error {
	f.calls++
	f.gotOK = ok
	f.gotPayload = payload
	return f.err
}

// TestReplyAndLog covers the four (success/failure) × (ok flag) shapes.
func TestReplyAndLog(t *testing.T) {
	tests := []struct {
		name        string
		replyErr    error
		ok          bool
		payload     []byte
		wantLog     bool   // expect a Warn line in the log buffer
		wantOKAttr  string // expected `ok` attr in the log line when wantLog
		wantMetric  int64  // expected delta on sshd.reply.errors
		wantErrIs   error  // require.ErrorIs target on the return value (nil if no error expected)
		wantNoError bool   // require.NoError on the return value
	}{
		{
			name:        "success path, ok=true: no log, no metric, returns nil",
			replyErr:    nil,
			ok:          true,
			payload:     nil,
			wantLog:     false,
			wantMetric:  0,
			wantNoError: true,
		},
		{
			name:        "success path, ok=false (rejection that succeeded): no log, no metric, returns nil",
			replyErr:    nil,
			ok:          false,
			payload:     []byte("ignored"),
			wantLog:     false,
			wantMetric:  0,
			wantNoError: true,
		},
		{
			name:       "failure path, ok=true: log, metric, returns injected error",
			replyErr:   errInjectedReply,
			ok:         true,
			payload:    []byte("payload"),
			wantLog:    true,
			wantOKAttr: "ok=true",
			wantMetric: 1,
			wantErrIs:  errInjectedReply,
		},
		{
			name:       "failure path, ok=false: log, metric, returns injected error",
			replyErr:   errInjectedReply,
			ok:         false,
			payload:    nil,
			wantLog:    true,
			wantOKAttr: "ok=false",
			wantMetric: 1,
			wantErrIs:  errInjectedReply,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var logBuf bytes.Buffer
			l := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
			// Snapshot the package-level counter so a delta comparison is
			// robust to other tests that touched the same registry.
			counterBefore := metrics.GetOrRegisterCounter("sshd.reply.errors", nil).Count()

			r := &fakeReplyer{err: tc.replyErr}
			gotErr := replyAndLog(r, tc.ok, tc.payload, l)

			assert.Equal(t, 1, r.calls, "Reply must be called exactly once")
			assert.Equal(t, tc.ok, r.gotOK, "ok flag must be forwarded to Reply")
			assert.Equal(t, tc.payload, r.gotPayload, "payload must be forwarded to Reply")

			counterAfter := metrics.GetOrRegisterCounter("sshd.reply.errors", nil).Count()
			assert.Equal(t, tc.wantMetric, counterAfter-counterBefore,
				"sshd.reply.errors must increment by %d", tc.wantMetric)

			logged := logBuf.String()
			if tc.wantLog {
				assert.Contains(t, logged, "ssh: protocol reply failed",
					"Warn line must identify the layer")
				assert.Contains(t, logged, errInjectedReply.Error(),
					"Warn line must include the underlying error so operators can correlate")
				assert.Contains(t, logged, tc.wantOKAttr,
					"Warn line must record the ok flag so operators can distinguish accept-fail from reject-fail")
			} else {
				assert.Empty(t, logged, "success path must not log")
			}

			if tc.wantNoError {
				require.NoError(t, gotErr)
			} else if tc.wantErrIs != nil {
				require.Error(t, gotErr)
				require.ErrorIs(t, gotErr, tc.wantErrIs,
					"returned error must be the underlying r.Reply error so callers can branch")
			}
		})
	}
}
