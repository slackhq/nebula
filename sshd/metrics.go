package sshd

import "github.com/rcrowley/go-metrics"

// metricReplyErrors counts ssh.Request.Reply failures. Use replyAndLog
// rather than calling Reply directly so failures land here.
var metricReplyErrors = metrics.GetOrRegisterCounter("sshd.reply.errors", nil)

// metricSendRequestErrors counts ssh.Channel.SendRequest failures. Use
// sendRequestAndLog rather than calling SendRequest directly.
var metricSendRequestErrors = metrics.GetOrRegisterCounter("sshd.send_request.errors", nil)
