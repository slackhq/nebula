package sshd

import (
	"errors"
	"log/slog"
	"sort"
	"strings"

	"github.com/slackhq/nebula/commands"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

type session struct {
	l        *slog.Logger
	c        *ssh.ServerConn
	term     *term.Terminal
	commands *commands.Registry
	cancel   func()
}

func NewSession(reg *commands.Registry, conn *ssh.ServerConn, chans <-chan ssh.NewChannel, cancel func(), l *slog.Logger) *session {
	s := &session{
		commands: reg.Clone(),
		l:        l,
		c:        conn,
		cancel:   cancel,
	}
	s.commands.DefaultFormat = DefaultFormat

	s.commands.Register(LogoutCommand(s.Close))

	go s.handleChannels(chans)
	return s
}

// LogoutCommand is the logout command a session registers on its clone of the registry,
// with end as what it does. Exported so a test can serve what a session serves.
func LogoutCommand(end func()) *commands.Command {
	return &commands.Command{
		Name:             commands.Logout,
		ShortDescription: "Ends the current session",
		Run: func(a any, args []string) (commands.Result, error) {
			end()
			return commands.Nothing(), nil
		},
	}
}

// DefaultFormat is what an ssh session renders when the operator gave neither -json nor
// -pretty: text where a command has a human form, and compact JSON for the ones that
// have none (print-tunnel, print-relays, query-lighthouse). It is ssh's policy, exported so a test
// can dispatch through the same choice, and ssh's to change.
func DefaultFormat(c *commands.Command, r commands.Result) commands.Format {
	if !c.JSONOnly {
		return commands.FormatText
	}

	// A JSON-only command's refusal ("No vpn address was provided") is a sentence for a
	// person, so an outcome renders as text here; ssh users and scripts expect it.
	if r.Value == nil {
		return commands.FormatText
	}

	return commands.FormatJSON
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
			err := s.dispatchCommand(payload.Value, commands.MergedOutput(channel))

			// A command that failed exits 1, so `ssh host cmd` callers can tell.
			status := struct{ Status uint32 }{uint32(0)}
			if err != nil {
				status.Status = 1
			}
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
	w := commands.MergedOutput(s.term)
	for {
		line, err := s.term.ReadLine()
		if err != nil {
			break
		}

		s.dispatchCommand(line, w)
	}
}

// dispatchCommand runs line and returns the command's error, which it has logged unless
// the command already told the user everything: the log line is for the operator reading
// the daemon's log, who learns nothing from a failure the user caused.
func (s *session) dispatchCommand(line string, w commands.Output) error {
	err := s.commands.Dispatch(line, w)
	if err == nil {
		return nil
	}

	var f *commands.Failure
	if !errors.As(err, &f) {
		s.l.Debug("Command returned an error", "line", line, "error", err)
	}
	return err
}

func (s *session) Close() {
	s.c.Close()
	s.cancel()
}
