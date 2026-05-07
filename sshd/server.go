package sshd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"

	"github.com/armon/go-radix"
	"golang.org/x/crypto/ssh"
)

type SSHServer struct {
	config *ssh.ServerConfig
	l      *slog.Logger

	certChecker *ssh.CertChecker

	// Map of user -> authorized keys
	trustedKeys map[string]map[string]bool
	trustedCAs  []ssh.PublicKey

	// List of available commands
	helpCommand *Command
	commands    *radix.Tree
	listener    net.Listener

	// ctx parents per-Run contexts. Cancelling it (e.g. via Control.Stop) tears the server down even
	// across reloads, since each Run derives a fresh child rather than reusing this one directly.
	ctx context.Context
}

// NewSSHServer creates a new ssh server rigged with default commands and prepares to listen.
// The ssh server's context is parented off the supplied ctx so cancelling it
// (e.g. on Control.Stop) tears down active sessions and closes the listener.
func NewSSHServer(ctx context.Context, l *slog.Logger) (*SSHServer, error) {
	s := &SSHServer{
		trustedKeys: make(map[string]map[string]bool),
		l:           l,
		commands:    radix.New(),
		ctx:         ctx,
	}

	cc := ssh.CertChecker{
		IsUserAuthority: func(auth ssh.PublicKey) bool {
			for _, ca := range s.trustedCAs {
				if bytes.Equal(ca.Marshal(), auth.Marshal()) {
					return true
				}
			}

			return false
		},
		UserKeyFallback: func(c ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
			pk := string(pubKey.Marshal())
			fp := ssh.FingerprintSHA256(pubKey)

			tk, ok := s.trustedKeys[c.User()]
			if !ok {
				return nil, fmt.Errorf("unknown user %s", c.User())
			}

			_, ok = tk[pk]
			if !ok {
				return nil, fmt.Errorf("unknown public key for %s (%s)", c.User(), fp)
			}

			return &ssh.Permissions{
				// Record the public key used for authentication.
				Extensions: map[string]string{
					"fp":   fp,
					"user": c.User(),
				},
			}, nil

		},
	}

	s.config = &ssh.ServerConfig{
		PublicKeyCallback: cc.Authenticate,
		ServerVersion:     fmt.Sprintf("SSH-2.0-Nebula???"),
	}

	s.RegisterCommand(&Command{
		Name:             "help",
		ShortDescription: "prints available commands or help <command> for specific usage info",
		Callback: func(a any, args []string, w StringWriter) error {
			return helpCallback(s.commands, args, w)
		},
	})

	return s, nil
}

func (s *SSHServer) SetHostKey(hostPrivateKey []byte) error {
	private, err := ssh.ParsePrivateKey(hostPrivateKey)
	if err != nil {
		return fmt.Errorf("failed to parse private key: %s", err)
	}

	s.config.AddHostKey(private)
	return nil
}

func (s *SSHServer) ClearTrustedCAs() {
	s.trustedCAs = []ssh.PublicKey{}
}

func (s *SSHServer) ClearAuthorizedKeys() {
	s.trustedKeys = make(map[string]map[string]bool)
}

// AddTrustedCA adds a trusted CA for user certificates
func (s *SSHServer) AddTrustedCA(pubKey string) error {
	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pubKey))
	if err != nil {
		return err
	}

	s.trustedCAs = append(s.trustedCAs, pk)
	s.l.Info("Trusted CA key", "sshKey", pubKey)
	return nil
}

// AddAuthorizedKey adds an ssh public key for a user
func (s *SSHServer) AddAuthorizedKey(user, pubKey string) error {
	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pubKey))
	if err != nil {
		return err
	}

	tk, ok := s.trustedKeys[user]
	if !ok {
		tk = make(map[string]bool)
		s.trustedKeys[user] = tk
	}

	tk[string(pk.Marshal())] = true
	s.l.Info("Authorized ssh key",
		"sshKey", pubKey,
		"sshUser", user,
	)
	return nil
}

// RegisterCommand adds a command that can be run by a user, by default only `help` is available
func (s *SSHServer) RegisterCommand(c *Command) {
	s.commands.Insert(c.Name, c)
}

// Run begins listening and accepting connections. Each invocation derives a fresh per-Run context
// from the constructor-supplied ctx so a Stop+Run sequence (used by config reload) starts clean
// rather than carrying a permanently-cancelled context across runs.
func (s *SSHServer) Run(addr string) error {
	if s.ctx.Err() != nil {
		return s.ctx.Err()
	}

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	// s.listener is the public handle Stop uses to interrupt the active run; listener (the local) is what
	// this run owns. They start equal but a fast reload may overwrite s.listener with the next run's
	// listener before this run's watcher fires, so each run must close its own listener via the local
	// reference.
	s.listener = listener

	runCtx, cancel := context.WithCancel(s.ctx)
	defer cancel()

	// Close the listener when this run's context is cancelled. That can come from the parent
	// (Control.Stop), from Run returning normally (defer cancel above), or transitively when a sibling
	// run cancels through Stop closing the listener. net.Listener.Close is idempotent so a duplicate
	// close from Stop is benign.
	go func() {
		<-runCtx.Done()
		if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			s.l.Warn("Failed to close the sshd listener", "error", err)
		}
	}()

	s.l.Info("SSH server is listening", "sshListener", addr)

	// Run loops until there is an error
	s.run(runCtx, listener)

	s.l.Info("SSH server stopped listening")
	// We don't return an error because run logs for us
	return nil
}

func (s *SSHServer) run(ctx context.Context, listener net.Listener) {
	for {
		c, err := listener.Accept()
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				s.l.Warn("Error in listener, shutting down", "error", err)
			}
			return
		}
		go func(c net.Conn) {
			// NewServerConn may block while waiting for the client to complete the handshake.
			// Ensure that a bad client doesn't hurt us by checking for the parent context
			// cancellation before calling NewServerConn, and forcing the socket to close when
			// the context is cancelled.
			sessionContext, sessionCancel := context.WithCancel(ctx)
			go func() {
				<-sessionContext.Done()
				c.Close()
			}()
			conn, chans, reqs, err := ssh.NewServerConn(c, s.config)
			fp := ""
			if conn != nil {
				fp = conn.Permissions.Extensions["fp"]
			}

			if err != nil {
				l := s.l.With(
					"error", err,
					"remoteAddress", c.RemoteAddr(),
				)
				if conn != nil {
					l = l.With("sshUser", conn.User())
					conn.Close()
				}
				if fp != "" {
					l = l.With("sshFingerprint", fp)
				}
				l.Warn("failed to handshake")
				sessionCancel()
				return
			}

			l := s.l.With("sshUser", conn.User())
			l.Info("ssh user logged in",
				"remoteAddress", c.RemoteAddr(),
				"sshFingerprint", fp,
			)

			NewSession(s.commands, conn, chans, sessionCancel, l.With("subsystem", "sshd.session"))

			go ssh.DiscardRequests(reqs)

		}(c)
	}
}

func (s *SSHServer) Stop() {
	if s.listener != nil {
		if err := s.listener.Close(); err != nil {
			s.l.Warn("Failed to close the sshd listener", "error", err)
		}
	}
}
