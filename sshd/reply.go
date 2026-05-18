package sshd

import "log/slog"

// replyer is the subset of *ssh.Request used for protocol-level replies.
// *ssh.Request satisfies it unchanged; tests inject a fake.
type replyer interface {
	Reply(ok bool, payload []byte) error
}

// replyAndLog calls r.Reply and, on error, increments sshd.reply.errors
// and emits a Warn so the failure is not silently dropped. The error is
// returned so callers can choose to bail out.
func replyAndLog(r replyer, ok bool, payload []byte, l *slog.Logger) error {
	if err := r.Reply(ok, payload); err != nil {
		metricReplyErrors.Inc(1)
		l.Warn("ssh: protocol reply failed", "ok", ok, "error", err)
		return err
	}
	return nil
}

// requester is the subset of ssh.Channel used for out-of-band requests.
// ssh.Channel satisfies it unchanged; tests inject a fake.
type requester interface {
	SendRequest(name string, wantReply bool, payload []byte) (bool, error)
}

// sendRequestAndLog calls r.SendRequest and, on error, increments
// sshd.send_request.errors and emits a Warn. The bool and error are
// returned so callers can branch.
func sendRequestAndLog(r requester, name string, wantReply bool, payload []byte, l *slog.Logger) (bool, error) {
	ok, err := r.SendRequest(name, wantReply, payload)
	if err != nil {
		metricSendRequestErrors.Inc(1)
		l.Warn("ssh: channel send-request failed", "name", name, "wantReply", wantReply, "error", err)
		return ok, err
	}
	return ok, nil
}
