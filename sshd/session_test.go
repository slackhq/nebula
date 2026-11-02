package sshd

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/slackhq/nebula/commands"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

type execTestChannel struct {
	bytes.Buffer
	sendErr  error
	writeErr error
	status   []byte
	closed   bool
}

func (c *execTestChannel) Write(p []byte) (int, error) {
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	return c.Buffer.Write(p)
}
func (c *execTestChannel) WriteString(s string) (int, error) { return c.Write([]byte(s)) }

func (c *execTestChannel) Close() error          { c.closed = true; return nil }
func (*execTestChannel) CloseWrite() error       { return nil }
func (c *execTestChannel) Stderr() io.ReadWriter { return c }
func (c *execTestChannel) SendRequest(_ string, _ bool, payload []byte) (bool, error) {
	c.status = bytes.Clone(payload)
	return false, c.sendErr
}

func TestExecRequest(t *testing.T) {
	injected := errors.New("injected transport failure")
	tests := []struct {
		description       string
		payload           []byte
		commandFails      bool
		sendErr, writeErr error
		wantCalls         int
		wantStatus        []byte
		wantClosed        bool
		wantSendErrors    int64
	}{
		{description: "successful command exits zero", wantCalls: 1, wantStatus: []byte{0, 0, 0, 0}, wantClosed: true},
		{description: "failed command still exits one", commandFails: true, wantCalls: 1, wantStatus: []byte{0, 0, 0, 1}, wantClosed: true},
		{description: "output failure still exits one", writeErr: injected, wantCalls: 1, wantStatus: []byte{0, 0, 0, 1}, wantClosed: true},
		{description: "failed exit-status send is counted and channel closes", sendErr: injected, wantCalls: 1, wantStatus: []byte{0, 0, 0, 0}, wantClosed: true, wantSendErrors: 1},
		{description: "truncated payload does not dispatch", payload: []byte{0, 0, 0}},
		{description: "oversized declared command does not dispatch", payload: []byte{255, 255, 255, 255}},
	}
	for _, tt := range tests {
		t.Run(tt.description, func(t *testing.T) {
			reg := commands.New()
			calls := 0
			reg.Register(&commands.Command{Name: "test", Run: func(any, []string) (commands.Result, error) {
				calls++
				if tt.commandFails {
					return commands.Failed("refused"), nil
				}
				return commands.Did("done"), nil
			}})
			var logs bytes.Buffer
			s := session{l: slog.New(slog.NewTextHandler(&logs, nil)), commands: reg}
			ch := &execTestChannel{sendErr: tt.sendErr, writeErr: tt.writeErr}
			payload := tt.payload
			if payload == nil {
				payload = ssh.Marshal(struct{ Value string }{"test"})
			}
			requests := make(chan *ssh.Request, 1)
			// With WantReply=false, Request.Reply does not need a transport.
			requests <- &ssh.Request{Type: "exec", Payload: payload}
			close(requests)
			before := metricSendRequestErrors.Count()
			s.handleRequests(requests, ch)
			assert.Equal(t, tt.wantCalls, calls)
			assert.Equal(t, tt.wantStatus, ch.status)
			assert.Equal(t, tt.wantClosed, ch.closed)
			assert.Equal(t, tt.wantSendErrors, metricSendRequestErrors.Count()-before)
			if tt.sendErr != nil {
				require.Contains(t, logs.String(), "channel send-request failed")
			}
		})
	}
}

func BenchmarkReplyAndLog(b *testing.B) {
	l := slog.New(slog.DiscardHandler)
	r := &fakeReplyer{}
	for b.Loop() {
		if err := replyAndLog(r, true, nil, l); err != nil {
			b.Fatal(err)
		}
	}
}
