package diag

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"time"
)

// Exit statuses the client reports. They follow shell convention closely enough that a
// script can tell "you asked for something that does not exist" from "it ran and failed".
const (
	// StatusOK means the command ran. Note that commands report their own user facing
	// problems as prose and still exit 0, matching the ssh console.
	StatusOK = 0
	// StatusError means the command could not be completed.
	StatusError = 1
	// StatusUsage means the arguments were not valid for that command.
	StatusUsage = 2
	// StatusUnknownCommand means there is no such command.
	StatusUnknownCommand = 127
)

// requestTimeout bounds how long a connected client may take to send its request line. There
// is deliberately no timeout on the response: `reload` runs every reload callback inline
// before it returns, and a slow one is not a reason to hang up on the operator.
const requestTimeout = 5 * time.Second

// Server serves a Registry over a stream listener. It knows nothing about unix sockets, so
// tests can drive it over a net.Pipe.
type Server struct {
	l   *slog.Logger
	reg *Registry
}

func NewServer(l *slog.Logger, reg *Registry) *Server {
	return &Server{l: l, reg: reg}
}

// Serve accepts connections until ln is closed. Cancelling ctx closes ln, which is what ends
// the accept loop; a listener closed underneath us is a normal shutdown, not an error.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	go func() {
		<-ctx.Done()
		if err := ln.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			s.l.Warn("Failed to close the ctl listener", "error", err)
		}
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
				return nil
			}
			return err
		}

		go s.ServeConn(ctx, conn)
	}
}

// ServeConn handles one request and closes c.
func (s *Server) ServeConn(ctx context.Context, c net.Conn) {
	defer func() {
		if err := c.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			s.l.Debug("Failed to close a ctl connection", "error", err)
		}
	}()

	if err := c.SetReadDeadline(time.Now().Add(requestTimeout)); err != nil {
		s.l.Debug("Failed to set a ctl read deadline", "error", err)
	}

	req, err := readRequest(bufio.NewReaderSize(c, maxRequest))
	if err != nil {
		s.l.Debug("Rejected a ctl request", "error", err)
		// Best effort: the client may already be gone, and there is nowhere else to report it.
		_ = writeEnd(c, StatusError, err.Error())
		return
	}

	// The request is in hand, so the command owns the rest of the connection's lifetime.
	if err := c.SetReadDeadline(time.Time{}); err != nil {
		s.l.Debug("Failed to clear the ctl read deadline", "error", err)
	}

	s.l.Debug("Running a ctl command", "args", req.Args)

	buf := bufio.NewWriterSize(&frameWriter{w: c}, outputBuffer)
	dispatchErr := s.reg.DispatchArgs(req.Args, NewWriter(buf))

	if err := buf.Flush(); err != nil {
		s.l.Debug("Failed to flush ctl output", "error", err)
		return
	}

	status, msg := statusFor(dispatchErr)
	if err := writeEnd(c, status, msg); err != nil {
		s.l.Debug("Failed to write the ctl end frame", "error", err)
	}
}

// StatusFor maps a dispatch error onto an exit status, for a transport that has somewhere to
// put one.
func StatusFor(err error) int {
	status, _ := statusFor(err)
	return status
}

// statusFor maps a dispatch error onto an exit status and, when the failure is ours to
// explain rather than one the command already wrote as prose, a message to go with it.
func statusFor(err error) (int, string) {
	switch {
	case err == nil:
		return StatusOK, ""
	case errors.Is(err, ErrUnknownCommand):
		return StatusUnknownCommand, ""
	case errors.Is(err, ErrUsage):
		return StatusUsage, ""
	default:
		return StatusError, fmt.Sprintf("%s", err)
	}
}

// ErrNotSupported means this platform has no ctl transport. Windows is waiting on a named
// pipe implementation; mobile has no daemon for a CLI to attach to in the first place.
var ErrNotSupported = errors.New("nebula ctl is not supported on this platform")

// Listen creates the ctl listener at path. It is the platform boundary: everything above it
// in this package is portable.
func Listen(path string) (net.Listener, error) {
	return listenSocket(path)
}
