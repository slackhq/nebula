package sshd

import "github.com/rcrowley/go-metrics"

// metricReplyErrors counts ssh.Request.Reply failures. Use replyAndLog
// rather than calling Reply directly so failures land here.
var metricReplyErrors = metrics.GetOrRegisterCounter("sshd.reply.errors", nil)
