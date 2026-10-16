package commands

import (
	"cmp"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"

	"github.com/anmitsu/go-shlex"
)

// Registry holds a set of commands. New is the only way to make one.
//
// It is safe for concurrent use. Commands may be registered while a surface is serving
// from the registry: the ssh server clones it per session, and a clone may overlap a
// Register.
type Registry struct {
	mu       sync.RWMutex
	commands map[Name]*Command
}

// New returns an empty Registry with only `help` available.
func New() *Registry {
	r := &Registry{commands: map[Name]*Command{}}
	r.registerHelp()
	return r
}

func (r *Registry) registerHelp() {
	r.Register(&Command{
		Name:             Help,
		ShortDescription: "prints available commands or help <command> for specific usage info",
		Callback: func(a any, args []string, w StringWriter) error {
			return r.help(args, w)
		},
	})
}

// Register adds a command that can be run by a user. A command registered under a name
// already held replaces it.
func (r *Registry) Register(c *Command) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.commands[c.Name] = c
}

// Get returns the command registered under name, or nil if there is no such command.
func (r *Registry) Get(name Name) *Command {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.commands[name]
}

// Match returns the names of every command starting with prefix, sorted, as strings for
// a prompt to complete and print.
func (r *Registry) Match(prefix string) []string {
	cmds := make([]string, 0)
	r.mu.RLock()
	for n := range r.commands {
		if strings.HasPrefix(string(n), prefix) {
			cmds = append(cmds, string(n))
		}
	}
	r.mu.RUnlock()
	slices.Sort(cmds)
	return cmds
}

// All returns every registered command sorted by name, which is the order help lists them.
func (r *Registry) All() []*Command {
	r.mu.RLock()
	defer r.mu.RUnlock()

	cmds := slices.Collect(maps.Values(r.commands))
	slices.SortFunc(cmds, func(a, b *Command) int { return cmp.Compare(a.Name, b.Name) })
	return cmds
}

// Clone returns a copy holding the same commands.
func (r *Registry) Clone() *Registry {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return &Registry{commands: maps.Clone(r.commands)}
}

// Dispatch parses a command line and runs it, reporting problems to w. The error is the
// command's own, or the flag parse failure; both have already been reported to w, so it
// is for the caller to log, not to show.
func (r *Registry) Dispatch(line string, w StringWriter) error {
	// A line shlex cannot split, an unbalanced quote, gets no answer. sshd was silent
	// here too; this is a relocation, so it stays silent.
	args, err := shlex.Split(line, true)
	if err != nil {
		return err
	}

	return r.DispatchArgs(args, line, w)
}

// DispatchArgs runs an already tokenized command line. orig is what the user typed,
// used only for the "did not understand" message; callers that have no raw line may
// pass "" and the joined args are used instead. The error is as for Dispatch.
func (r *Registry) DispatchArgs(args []string, orig string, w StringWriter) error {
	if len(args) == 0 {
		r.dumpCommands(w)
		return nil
	}

	c := r.Get(Name(args[0]))
	if c == nil {
		if orig == "" {
			orig = strings.Join(args, " ")
		}

		if err := w.WriteLine(fmt.Sprintf("did not understand: %s", orig)); err != nil {
			return err
		}

		r.dumpCommands(w)
		return nil
	}

	if checkHelpArgs(args) {
		// Through the registered help command, so -h and `help <name>` are one path.
		return execCommand(r.Get(Help), []string{string(c.Name)}, w)
	}

	return execCommand(c, args[1:], w)
}

// dumpCommands writes the list of available commands to w.
func (r *Registry) dumpCommands(w StringWriter) {
	err := w.WriteLine("Available commands:")
	if err != nil {
		return
	}

	// In the order All gives, which is the display order.
	cmds := make([]string, 0)
	for _, l := range r.All() {
		cmds = append(cmds, fmt.Sprintf("%s - %s", l.Name, l.ShortDescription))
	}

	_ = w.Write(strings.Join(cmds, "\n") + "\n\n")
}

// help writes the command list, or usage for the single command named in a.
func (r *Registry) help(a []string, w StringWriter) error {
	// Just typed help
	if len(a) == 0 {
		r.dumpCommands(w)
		return nil
	}

	// We are printing a specific commands help text
	cmd := r.Get(Name(a[0]))
	if cmd == nil {
		return w.WriteLine("Command not available " + a[0])
	}

	if err := w.WriteLine(fmt.Sprintf("%s - %s", cmd.Name, cmd.ShortDescription)); err != nil {
		return err
	}

	if cmd.Help != "" {
		if err := w.WriteLine(fmt.Sprintf("  %s", cmd.Help)); err != nil {
			return err
		}
	}

	if cmd.Flags != nil {
		fs, _ := cmd.Flags()
		if fs != nil {
			fs.SetOutput(w.GetWriter())
			fs.PrintDefaults()
		}
	}

	return nil
}
