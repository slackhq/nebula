package diag

import (
	"fmt"
	"sync"

	"github.com/anmitsu/go-shlex"
	"github.com/armon/go-radix"
)

// Registry is the set of commands nebula exposes for debugging and administration. It is
// transport neutral: the ssh console and the `nebula ctl` unix socket dispatch against the
// same registry, and neither knows the other exists.
//
// Registration is expected to happen once during startup, before any transport is serving,
// but the lock makes a late RegisterCommand safe rather than a data race waiting to happen.
type Registry struct {
	mu       sync.RWMutex
	commands *radix.Tree
}

// NewRegistry returns a registry containing only `help`. Everything else is attached by
// the caller, see attachCommands in the nebula package.
func NewRegistry() *Registry {
	r := &Registry{commands: radix.New()}

	r.RegisterCommand(&Command{
		Name:             "help",
		ShortDescription: "prints available commands or help <command> for specific usage info",
		Callback: func(a any, args []string, w StringWriter) error {
			return r.help(args, w)
		},
	})

	return r
}

// RegisterCommand adds a command that a user can run.
func (r *Registry) RegisterCommand(c *Command) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.commands.Insert(c.Name, c)
}

// Clone returns an independent copy sharing no tree with the original. The ssh session uses
// this so the `logout` command it adds for itself is invisible to every other session, and
// to `nebula ctl`.
func (r *Registry) Clone() *Registry {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return &Registry{commands: radix.NewFromMap(r.commands.ToMap())}
}

// Match returns every registered command name carrying the given prefix, for tab completion.
func (r *Registry) Match(prefix string) []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return matchCommand(r.commands, prefix)
}

// Dispatch splits line the way a shell would and runs the result. The ssh console uses this
// because a terminal only ever hands it a line; a transport that already has a real argv
// should call DispatchArgs instead rather than round tripping through a quoting parser.
func (r *Registry) Dispatch(line string, w StringWriter) error {
	args, err := shlex.Split(line, true)
	if err != nil {
		if wErr := w.WriteLine(fmt.Sprintf("Unable to parse command: %s", err)); wErr != nil {
			return wErr
		}
		return err
	}

	return r.DispatchArgs(args, w)
}

// DispatchArgs runs args[0] with args[1:] as its arguments, writing everything the command
// produces to w. An empty args dumps the command list, matching what an empty line does on
// the ssh console.
//
// Callbacks report user facing problems as prose on w and return nil by convention, so a
// non-nil error here means the command could not be run at all: ErrUnknownCommand, an
// ErrUsage wrapped flag failure, or an internal failure a callback chose to surface.
func (r *Registry) DispatchArgs(args []string, w StringWriter) error {
	if len(args) == 0 {
		r.mu.RLock()
		defer r.mu.RUnlock()
		dumpCommands(r.commands, w)
		return nil
	}

	r.mu.RLock()
	cmd, err := lookupCommand(r.commands, args[0])
	r.mu.RUnlock()
	if err != nil {
		if wErr := w.WriteLine(fmt.Sprintf("Command lookup failed: %s", err)); wErr != nil {
			return wErr
		}
		return err
	}

	if cmd == nil {
		if wErr := w.WriteLine(fmt.Sprintf("Did not understand: %s", args[0])); wErr != nil {
			return wErr
		}
		r.mu.RLock()
		defer r.mu.RUnlock()
		dumpCommands(r.commands, w)
		return fmt.Errorf("%w: %s", ErrUnknownCommand, args[0])
	}

	// -h and -help anywhere in the arguments mean the user wants to know how the command
	// works, not to run it.
	if checkHelpArgs(args) {
		return r.help([]string{cmd.Name}, w)
	}

	return execCommand(cmd, args[1:], w)
}

// help renders the command list, or one command's usage, onto w.
func (r *Registry) help(args []string, w StringWriter) error {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return helpCallback(r.commands, args, w)
}
