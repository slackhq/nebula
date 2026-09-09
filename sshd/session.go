package sshd

import (
	"log/slog"
	"sort"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"

	"github.com/slackhq/nebula/diag"
)

type session struct {
	l        *slog.Logger
	c        *ssh.ServerConn
	term     *term.Terminal
	commands *diag.Registry
	cancel   func()
}

func NewSession(commands *diag.Registry, conn *ssh.ServerConn, chans <-chan ssh.NewChannel, cancel func(), l *slog.Logger) *session {
	s := &session{
		// A copy, so the logout command this session adds for itself stays invisible to every
		// other session and to `nebula ctl`.
		commands: commands.Clone(),
		l:        l,
		c:        conn,
		cancel:   cancel,
	}

	s.commands.RegisterCommand(&diag.Command{
		Name:             "logout",
		ShortDescription: "Ends the current session",
		Callback: func(a any, args []string, w diag.StringWriter) error {
			s.Close()
			return nil
		},
	})

	go s.handleChannels(chans)
	return s
}

func (s *session) handleChannels(chans <-chan ssh.NewChannel) {
	defer s.Close()
	for newChannel := range chans {
		if newChannel.ChannelType() != "session" {
			s.l.Error("unknown channel type", "sshChannelType", newChannel.ChannelType())
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}

		channel, requests, err := newChannel.Accept()
		if err != nil {
			s.l.Warn("could not accept channel", "error", err)
			continue
		}

		go s.handleRequests(requests, channel)
	}
}

func (s *session) handleRequests(in <-chan *ssh.Request, channel ssh.Channel) {
	for req := range in {
		var err error
		switch req.Type {
		case "shell":
			if s.term == nil {
				s.term = s.createTerm(channel)
				err = req.Reply(true, nil)
			} else {
				err = req.Reply(false, nil)
			}

		case "pty-req":
			err = req.Reply(true, nil)

		case "window-change":
			err = req.Reply(true, nil)

		case "exec":
			var payload = struct{ Value string }{}
			cErr := ssh.Unmarshal(req.Payload, &payload)
			if cErr != nil {
				req.Reply(false, nil)
				return
			}

			req.Reply(true, nil)
			dErr := s.commands.Dispatch(payload.Value, diag.NewWriter(channel))

			// Report a real exit status rather than a hardcoded zero, so that
			// `ssh nebula-host list-hostmap` is scriptable the same way `nebula ctl` is.
			status := struct{ Status uint32 }{uint32(diag.StatusFor(dErr))}
			channel.SendRequest("exit-status", false, ssh.Marshal(status))
			channel.Close()
			return

		default:
			s.l.Debug("Rejected unknown request", "sshRequest", req.Type)
			err = req.Reply(false, nil)
		}

		if err != nil {
			s.l.Info("Error handling ssh session requests", "error", err)
			return
		}
	}
}

func (s *session) createTerm(channel ssh.Channel) *term.Terminal {
	term := term.NewTerminal(channel, s.c.User()+"@nebula > ")
	term.AutoCompleteCallback = func(line string, pos int, key rune) (newLine string, newPos int, ok bool) {
		// key 9 is tab
		if key == 9 {
			cmds := s.commands.Match(line)
			if len(cmds) == 1 {
				return cmds[0] + " ", len(cmds[0]) + 1, true
			}

			sort.Strings(cmds)
			term.Write([]byte(strings.Join(cmds, "\n") + "\n\n"))
		}

		return "", 0, false
	}

	go s.handleInput()
	return term
}

func (s *session) handleInput() {
	w := diag.NewWriter(s.term)
	for {
		line, err := s.term.ReadLine()
		if err != nil {
			break
		}

		// The interactive console reports problems on the terminal the user is already
		// looking at, so the error is nothing extra to say here.
		_ = s.commands.Dispatch(line, w)
	}
}

func (s *session) Close() {
	s.c.Close()
	s.cancel()
}
