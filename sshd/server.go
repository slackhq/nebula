package sshd

import (
	"fmt"
	"net"

	"github.com/armon/go-radix"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
)

type SSHServer struct {
	config *ssh.ServerConfig
	l      *zap.Logger

	// Map of user -> authorized keys
	trustedKeys map[string]map[string]bool

	// List of available commands
	// helpCommand *Command
	commands *radix.Tree
	listener net.Listener
	conns    map[int]*session
	counter  int
}

// NewSSHServer creates a new ssh server rigged with default commands and prepares to listen
func NewSSHServer(l *zap.Logger) (*SSHServer, error) {
	s := &SSHServer{
		trustedKeys: make(map[string]map[string]bool),
		l:           l,
		commands:    radix.New(),
		conns:       make(map[int]*session),
	}

	s.config = &ssh.ServerConfig{
		PublicKeyCallback: s.matchPubKey,
		//TODO: AuthLogCallback: s.authAttempt,
		//TODO: version string
		ServerVersion: "SSH-2.0-Nebula???",
	}

	s.RegisterCommand(&Command{
		Name:             "help",
		ShortDescription: "prints available commands or help <command> for specific usage info",
		Callback: func(a interface{}, args []string, w StringWriter) error {
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

func (s *SSHServer) ClearAuthorizedKeys() {
	s.trustedKeys = make(map[string]map[string]bool)
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
	s.l.Info(
		"authorized ssh key",
		zap.String("sshKey", pubKey),
		zap.String("sshUser", user),
	)
	return nil
}

// RegisterCommand adds a command that can be run by a user, by default only `help` is available
func (s *SSHServer) RegisterCommand(c *Command) {
	s.commands.Insert(c.Name, c)
}

// Run begins listening and accepting connections
func (s *SSHServer) Run(addr string) error {
	var err error
	s.listener, err = net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	s.l.Info(
		"ssh server is listening",
		zap.String("sshListener", addr),
	)
	for {
		c, err := s.listener.Accept()
		if err != nil {
			s.l.Warn("Error in listener, shutting down", zap.Error(err))
			return nil
		}

		conn, chans, reqs, err := ssh.NewServerConn(c, s.config)
		fp := ""
		if conn != nil {
			fp = conn.Permissions.Extensions["fp"]
		}

		if err != nil {
			l := s.l.With(zap.Any("remoteAddress", c.RemoteAddr()))
			if conn != nil {
				l = l.With(zap.String("sshUser", conn.User()))
				conn.Close()
			}
			if fp != "" {
				l = l.With(zap.String("sshFingerprint", fp))
			}
			l.Warn("failed to handshake")
			continue
		}

		l := s.l.With(zap.String("sshUser", conn.User()))
		l.Info(
			"ssh user logged in",
			zap.Any("remoteAddress", c.RemoteAddr()),
			zap.String("sshFingerprint", fp),
		)

		session := NewSession(s.commands, conn, chans, l.With(zap.String("subsystem", "sshd.session")))
		s.counter++
		counter := s.counter
		s.conns[counter] = session

		go ssh.DiscardRequests(reqs)
		go func() {
			<-session.exitChan
			s.l.Debug(
				"closing conn",
				zap.Int("id", counter),
			)
			delete(s.conns, counter)
		}()
	}
}

func (s *SSHServer) Stop() {
	for _, c := range s.conns {
		c.Close()
	}

	if s.listener == nil {
		return
	}

	err := s.listener.Close()
	if err != nil {
		s.l.Warn("Failed to close the sshd listener", zap.Error(err))
		return
	}

	s.l.Info("SSH server stopped listening")
}

func (s *SSHServer) matchPubKey(c ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
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
}
