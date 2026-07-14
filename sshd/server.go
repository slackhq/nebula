package sshd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"

	"github.com/slackhq/nebula/commands"
	"golang.org/x/crypto/ssh"
)

type SSHServer struct {
	// config is replaced whole when the host key changes, ssh.ServerConfig.AddHostKey only replaces a key of the same
	// algorithm and appends any other
	config       atomic.Pointer[ssh.ServerConfig]
	authenticate func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error)
	l            *slog.Logger

	certChecker *ssh.CertChecker

	// authLock guards trustedKeys and trustedCAs
	authLock sync.RWMutex
	// Map of user -> authorized keys
	trustedKeys map[string]map[string]bool
	trustedCAs  []ssh.PublicKey

	// Available commands.
	commands *commands.Registry
	// listeners is the public handle Stop uses to interrupt the active run
	listeners atomic.Pointer[[]net.Listener]

	// runs counts the Runs that are listening. A reload's Run can start before the one it replaced has returned
	runs atomic.Int32
	// addr is where the newest Run listens, nil when none is
	addr atomic.Pointer[net.Addr]

	// ctx parents per-Run contexts. Cancelling it (e.g. via Control.Stop) tears the server down even
	// across reloads, since each Run derives a fresh child rather than reusing this one directly.
	ctx context.Context
}

// NewSSHServer creates a new ssh server serving the supplied command registry and
// prepares to listen. The ssh server's context is parented off the supplied ctx so
// cancelling it (e.g. on Control.Stop) tears down active sessions and closes the listener.
func NewSSHServer(ctx context.Context, l *slog.Logger, reg *commands.Registry) (*SSHServer, error) {
	s := &SSHServer{
		trustedKeys: make(map[string]map[string]bool),
		l:           l,
		commands:    reg,
		ctx:         ctx,
	}

	cc := ssh.CertChecker{
		IsUserAuthority: func(auth ssh.PublicKey) bool {
			s.authLock.RLock()
			defer s.authLock.RUnlock()
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

			s.authLock.RLock()
			defer s.authLock.RUnlock()
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

	s.authenticate = cc.Authenticate
	s.config.Store(s.newConfig())

	return s, nil
}

func (s *SSHServer) SetHostKey(hostPrivateKey []byte) error {
	private, err := ssh.ParsePrivateKey(hostPrivateKey)
	if err != nil {
		return fmt.Errorf("failed to parse private key: %s", err)
	}

	config := s.newConfig()
	config.AddHostKey(private)
	s.config.Store(config)
	return nil
}

func (s *SSHServer) newConfig() *ssh.ServerConfig {
	return &ssh.ServerConfig{
		PublicKeyCallback: s.authenticate,
		ServerVersion:     fmt.Sprintf("SSH-2.0-Nebula???"),
	}
}

// Addr is the address the newest Run listens on, nil when none is.
func (s *SSHServer) Addr() net.Addr {
	if a := s.addr.Load(); a != nil {
		return *a
	}
	return nil
}

// Running is true while a Run is listening.
func (s *SSHServer) Running() bool {
	return s.runs.Load() > 0
}

func (s *SSHServer) ClearTrustedCAs() {
	s.authLock.Lock()
	s.trustedCAs = []ssh.PublicKey{}
	s.authLock.Unlock()
}

func (s *SSHServer) ClearAuthorizedKeys() {
	s.authLock.Lock()
	s.trustedKeys = make(map[string]map[string]bool)
	s.authLock.Unlock()
}

// AddTrustedCA adds a trusted CA for user certificates
func (s *SSHServer) AddTrustedCA(pubKey string) error {
	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pubKey))
	if err != nil {
		return err
	}

	s.authLock.Lock()
	s.trustedCAs = append(s.trustedCAs, pk)
	s.authLock.Unlock()
	s.l.Info("Trusted CA key", "sshKey", pubKey)
	return nil
}

// AddAuthorizedKey adds an ssh public key for a user
func (s *SSHServer) AddAuthorizedKey(user, pubKey string) error {
	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pubKey))
	if err != nil {
		return err
	}

	s.authLock.Lock()
	tk, ok := s.trustedKeys[user]
	if !ok {
		tk = make(map[string]bool)
		s.trustedKeys[user] = tk
	}

	tk[string(pk.Marshal())] = true
	s.authLock.Unlock()
	s.l.Info("Authorized ssh key",
		"sshKey", pubKey,
		"sshUser", user,
	)
	return nil
}

// Run begins listening and accepting connections on every address in addrs. Each invocation derives a
// fresh per-Run context from the constructor-supplied ctx so a Stop+Run sequence (used by config
// reload) starts clean rather than carrying a permanently-cancelled context across runs.
//
// Binding is all-or-nothing: if any address fails to bind, the already-bound listeners for this run
// are closed and the error is returned so the failure surfaces loudly.
func (s *SSHServer) Run(addrs []string) error {
	if s.ctx.Err() != nil {
		return s.ctx.Err()
	}

	listeners := make([]net.Listener, 0, len(addrs))
	for _, addr := range addrs {
		listener, err := net.Listen("tcp", addr)
		if err != nil {
			closeListeners(listeners)
			return err
		}
		listeners = append(listeners, listener)
	}
	// listeners (the local) is what this run owns. A fast reload may overwrite s.listeners with the next
	// run's listeners before this run's watcher fires, so each run must close its own via the local.
	s.listeners.Store(&listeners)
	s.runs.Add(1)
	bound := listeners[0].Addr()
	s.addr.Store(&bound)

	runCtx, cancel := context.WithCancel(s.ctx)
	defer cancel()
	// Deferred after cancel so they run first, a run on its way out no longer counts as listening
	defer s.runs.Add(-1)
	defer s.addr.CompareAndSwap(&bound, nil)

	// Close this run's listeners when its context is cancelled. That can come from the parent
	// (Control.Stop), from Run returning normally (defer cancel above), or transitively when a sibling
	// run cancels through Stop closing the listeners. net.Listener.Close is idempotent so a duplicate
	// close from Stop is benign.
	go func() {
		<-runCtx.Done()
		if err := closeListeners(listeners); err != nil {
			s.l.Warn("Failed to close the sshd listener", "error", err)
		}
	}()

	s.l.Info("SSH server is listening", "sshListeners", addrs)

	// Serve every listener until its accept loop exits, then wait for them all.
	var wg sync.WaitGroup
	for _, listener := range listeners {
		wg.Add(1)
		go func(listener net.Listener) {
			defer wg.Done()
			s.run(runCtx, listener)
		}(listener)
	}
	wg.Wait()

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
			conn, chans, reqs, err := ssh.NewServerConn(c, s.config.Load())
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
	if ls := s.listeners.Load(); ls != nil {
		if err := closeListeners(*ls); err != nil {
			s.l.Warn("Failed to close the sshd listener", "error", err)
		}
	}
}

// closeListeners closes every listener, returning the first error that is not an already closed listener.
func closeListeners(listeners []net.Listener) error {
	var first error
	for _, ln := range listeners {
		if err := ln.Close(); err != nil && !errors.Is(err, net.ErrClosed) && first == nil {
			first = err
		}
	}
	return first
}
