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

type fakeReplyer struct {
	err   error
	calls int
}

func (f *fakeReplyer) Reply(ok bool, payload []byte) error {
	f.calls++
	return f.err
}

func TestReplyAndLog(t *testing.T) {
	injected := errors.New("injected reply failure")
	tests := []struct {
		name        string
		replyErr    error
		wantLog     bool
		wantMetric  int64
		wantNoError bool
	}{
		{"success returns nil, no log, no metric", nil, false, 0, true},
		{"failure logs, increments metric, returns the error", injected, true, 1, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var logBuf bytes.Buffer
			l := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
			counterBefore := metrics.GetOrRegisterCounter("sshd.reply.errors", nil).Count()

			r := &fakeReplyer{err: tc.replyErr}
			gotErr := replyAndLog(r, true, nil, l)

			assert.Equal(t, 1, r.calls)
			counterAfter := metrics.GetOrRegisterCounter("sshd.reply.errors", nil).Count()
			assert.Equal(t, tc.wantMetric, counterAfter-counterBefore)

			if tc.wantNoError {
				require.NoError(t, gotErr)
			} else {
				require.ErrorIs(t, gotErr, injected)
			}
			if tc.wantLog {
				assert.Contains(t, logBuf.String(), "ssh: protocol reply failed")
			} else {
				assert.Empty(t, logBuf.String())
			}
		})
	}
}
