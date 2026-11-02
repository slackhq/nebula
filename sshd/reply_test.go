package sshd

import (
	"bytes"
	"errors"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeReplyer struct {
	err     error
	calls   int
	okArg   bool
	payload []byte
}

func (f *fakeReplyer) Reply(ok bool, payload []byte) error {
	f.calls++
	f.okArg = ok
	f.payload = payload
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
		replyOK     bool
		payload     []byte
	}{
		{"accept success", nil, false, 0, true, true, nil},
		{"reject success with empty payload", nil, false, 0, true, false, []byte{}},
		{"reply payload forwarded", nil, false, 0, true, true, []byte{0, 255}},
		{"accept failure logs and counts", injected, true, 1, false, true, nil},
		{"reject failure logs and counts", injected, true, 1, false, false, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var logBuf bytes.Buffer
			l := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
			counterBefore := metricReplyErrors.Count()

			r := &fakeReplyer{err: tc.replyErr}
			gotErr := replyAndLog(r, tc.replyOK, tc.payload, l)

			assert.Equal(t, 1, r.calls)
			assert.Equal(t, tc.replyOK, r.okArg)
			assert.Equal(t, tc.payload, r.payload)
			counterAfter := metricReplyErrors.Count()
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

type fakeRequester struct {
	ok        bool
	err       error
	calls     int
	name      string
	wantReply bool
	payload   []byte
}

func (f *fakeRequester) SendRequest(name string, wantReply bool, payload []byte) (bool, error) {
	f.calls++
	f.name, f.wantReply, f.payload = name, wantReply, payload
	return f.ok, f.err
}

func TestSendRequestAndLog(t *testing.T) {
	injected := errors.New("injected send-request failure")
	tests := []struct {
		name               string
		sendErr            error
		wantLog            bool
		wantMetric         int64
		wantNoError        bool
		replyOK, wantReply bool
		payload            []byte
	}{
		{"no reply requested returns false without error", nil, false, 0, true, false, false, nil},
		{"peer accepts request", nil, false, 0, true, true, true, []byte{0, 0, 0, 0}},
		{"peer rejects request without transport error", nil, false, 0, true, false, true, []byte{}},
		{"send failure logs and counts", injected, true, 1, false, false, false, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var logBuf bytes.Buffer
			l := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
			counterBefore := metricSendRequestErrors.Count()

			r := &fakeRequester{err: tc.sendErr, ok: tc.replyOK}
			gotOK, gotErr := sendRequestAndLog(r, "exit-status", tc.wantReply, tc.payload, l)

			assert.Equal(t, 1, r.calls)
			assert.Equal(t, tc.replyOK, gotOK)
			assert.Equal(t, "exit-status", r.name)
			assert.Equal(t, tc.wantReply, r.wantReply)
			assert.Equal(t, tc.payload, r.payload)
			counterAfter := metricSendRequestErrors.Count()
			assert.Equal(t, tc.wantMetric, counterAfter-counterBefore)

			if tc.wantNoError {
				require.NoError(t, gotErr)
			} else {
				require.ErrorIs(t, gotErr, injected)
			}
			if tc.wantLog {
				assert.Contains(t, logBuf.String(), "ssh: channel send-request failed")
			} else {
				assert.Empty(t, logBuf.String())
			}
		})
	}
}
