package commands

import (
	"errors"
	"flag"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"

	"github.com/anmitsu/go-shlex"
)

// Registry holds a set of commands.
//
// It is safe for concurrent use. Commands may be registered while surfaces are serving
// from the registry: the ssh server clones it per session and the control socket filters
// it per request, and either may overlap a Register.
type Registry struct {
	mu       sync.RWMutex
	commands map[Name]*Command

	// full is set on a filtered registry and points at the registry it was filtered
	// from, so a command that's filtered can be reported as such.
	full *Registry

	// reason explains, in the terms an operator cares about, why this registry withholds
	// a command they can name. It is supplied by whoever built the filter, because why a
	// surface declines a command is that surface's business, not the registry's.
	reason string
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
			return r.Help(args, w)
		},
	})
}

// Register adds a command that can be run by a user.
func (r *Registry) Register(c *Command) {
	r.insert(c)
}

// insert adds c under the lock.
func (r *Registry) insert(c *Command) {
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

// All returns every registered command in display order: the order of Known, which is
// the order help lists them, followed by any name Known does not place, sorted. Nebula
// registers only Known names, which TestKnownNamesAreTheRegisteredSet pins; the tail
// exists for tests.
func (r *Registry) All() []*Command {
	r.mu.RLock()
	defer r.mu.RUnlock()

	cmds := make([]*Command, 0, len(r.commands))
	for _, n := range Known {
		if c, ok := r.commands[n]; ok {
			cmds = append(cmds, c)
		}
	}

	var extra []Name
	for n := range r.commands {
		if !n.IsKnown() {
			extra = append(extra, n)
		}
	}
	slices.Sort(extra)
	for _, n := range extra {
		cmds = append(cmds, r.commands[n])
	}
	return cmds
}

// Clone returns a copy holding the same commands.
//
// help is re-registered on the copy rather than carried over, because the source's help
// is bound to the source and would list its commands, not the copy's, once a caller
// registers something on the copy.
func (r *Registry) Clone() *Registry {
	r.mu.RLock()
	out := &Registry{
		commands: maps.Clone(r.commands),
		full:     r.full,
		reason:   r.reason,
	}
	r.mu.RUnlock()

	out.registerHelp()
	return out
}

// ErrWithheld is returned when a command exists but this surface does not serve it.
var ErrWithheld = errors.New("command unavailable")

// Filter returns a copy holding the commands keep returns true for.
//
// A surface decides for itself what it will serve; the registry only applies the
// decision. Filtering here, on the side that serves requests, is what stops a client
// reaching a withheld command by naming it directly.
//
// reason says, to an operator who names a command the copy left out, why this surface
// does not serve it; "" leaves the registry to say only that it does not.
func (r *Registry) Filter(keep func(*Command) bool, reason string) *Registry {
	out := &Registry{commands: map[Name]*Command{}, full: r, reason: reason}

	for _, cmd := range r.All() {
		if keep(cmd) {
			out.insert(cmd)
		}
	}

	// Bind help to the filtered set so it only advertises what this surface serves.
	out.registerHelp()
	return out
}

// Dispatch parses a command line and runs it, reporting problems to w.
func (r *Registry) Dispatch(line string, w StringWriter) {
	args, err := shlex.Split(line, true)
	if err != nil {
		_, _ = fmt.Fprintf(w.Err(), "could not parse command line: %v\n", err)
		return
	}

	if len(args) == 0 {
		r.DumpCommands(w)
		return
	}

	_ = r.DispatchArgs(args, line, w)
}

// DispatchArgs runs an already tokenized command line. orig is what the user typed,
// used only for the "did not understand" message; callers that have no raw line may
// pass "" and the joined args are used instead.
func (r *Registry) DispatchArgs(args []string, orig string, w StringWriter) error {
	if len(args) == 0 {
		r.DumpCommands(w)
		return nil
	}

	c := r.Get(Name(args[0]))
	if c == nil {
		if withheld := r.withheld(Name(args[0])); withheld != nil {
			// Saying why, rather than "did not understand", keeps the rule legible and
			// points at a surface that will actually run the command.
			_, _ = fmt.Fprintf(w.Err(), "%s is not available on this surface: %s\n", withheld.Name, r.withheldReason(withheld))
			return ErrWithheld
		}

		if orig == "" {
			orig = strings.Join(args, " ")
		}

		if err := w.WriteLine(fmt.Sprintf("did not understand: %s", orig)); err != nil {
			return err
		}

		r.DumpCommands(w)
		return nil
	}

	if IsHelpRequest(args) {
		return r.Help([]string{string(c.Name)}, w)
	}

	return execCommand(c, args[1:], w)
}

// DumpCommands writes the list of available commands to w.
func (r *Registry) DumpCommands(w StringWriter) {
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

// Help writes the command list, or usage for the single command named in a.
func (r *Registry) Help(a []string, w StringWriter) (err error) {
	// Just typed help
	if len(a) == 0 {
		r.DumpCommands(w)
		return nil
	}

	// We are printing a specific commands help text
	if cmd := r.Get(Name(a[0])); cmd != nil {
		err = w.WriteLine(fmt.Sprintf("%s - %s", cmd.Name, cmd.ShortDescription))
		if err != nil {
			return err
		}

		if cmd.Help != "" {
			err = w.WriteLine(fmt.Sprintf("  %s", cmd.Help))
			if err != nil {
				return err
			}
		}

		if cmd.Flags != nil {
			fs, _ := cmd.Flags()
			if fs != nil {
				fs.SetOutput(w.Err())
				fs.PrintDefaults()
			}
		}

		return nil
	}

	if withheld := r.withheld(Name(a[0])); withheld != nil {
		_, _ = fmt.Fprintf(w.Err(), "%s is not available on this surface: %s\n", withheld.Name, r.withheldReason(withheld))
		return nil
	}

	err = w.WriteLine("Command not available " + a[0])
	if err != nil {
		return err
	}

	return nil
}

// Resolve returns the command registered under name, or says why there is none. A
// command this surface withholds is reported with the filter's reason, and one that
// does not exist at all as unknown, so a client that misspells and one that asks for a
// real command it cannot have here are told different things. It is the edge where a
// name from the wire becomes a Command for a Request.
func (r *Registry) Resolve(name Name) (*Command, error) {
	if c := r.Get(name); c != nil {
		return c, nil
	}

	if withheld := r.withheld(name); withheld != nil {
		return nil, fmt.Errorf("%s is not available on this surface: %s", withheld.Name, r.withheldReason(withheld))
	}

	return nil, fmt.Errorf("unknown command %q", name)
}

// Schema describes every command in the registry, so a client can offer them without
// having been built against this daemon.
func (r *Registry) Schema() []CommandSchema {
	// In the order All gives, which is the display order.
	out := make([]CommandSchema, 0, len(r.All()))

	for _, c := range r.All() {
		cs := CommandSchema{Name: c.Name, Short: c.ShortDescription, Help: c.Help}

		if c.Flags != nil {
			if fl, _ := c.Flags(); fl != nil {
				fl.VisitAll(func(f *flag.Flag) {
					cs.Flags = append(cs.Flags, FlagSchema{
						Name:    f.Name,
						Bool:    isBoolFlag(f),
						Default: f.DefValue,
						Usage:   f.Usage,
					})
				})
			}
		}

		out = append(out, cs)
	}

	return out
}

// CommandSchema describes one command well enough for a client to offer it.
type CommandSchema struct {
	Name  Name         `json:"name"`
	Short string       `json:"short,omitempty"`
	Help  string       `json:"help,omitempty"`
	Flags []FlagSchema `json:"flags,omitempty"`
}

// FlagSchema describes one of a command's named parameters.
type FlagSchema struct {
	Name string `json:"name"`

	// Bool reports a parameter that takes no value, which is what tells a command line
	// client whether `-pretty` swallows the word after it.
	Bool bool `json:"bool,omitempty"`

	Default string `json:"default,omitempty"`
	Usage   string `json:"usage,omitempty"`
}

// isBoolFlag reports whether f is satisfied by its presence alone. The flag package marks
// these with an unexported interface, which is the only way to tell.
func isBoolFlag(f *flag.Flag) bool {
	bf, ok := f.Value.(interface{ IsBoolFlag() bool })
	return ok && bf.IsBoolFlag()
}

// withheld returns the command named name if it exists in the unfiltered registry but
// not in this one.
func (r *Registry) withheld(name Name) *Command {
	if r.full == nil {
		return nil
	}

	return r.full.Get(name)
}

// withheldReason renders the explanation supplied to Filter, falling back to something
// true but unhelpful when no explanation was given.
func (r *Registry) withheldReason(c *Command) string {
	if r.reason == "" {
		return "this surface does not serve it"
	}

	return r.reason
}
