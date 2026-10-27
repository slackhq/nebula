package commands

import (
	"cmp"
	"flag"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"
	"sync"
)

// Registry holds a set of commands.
//
// It is safe for concurrent use. Commands may be registered while a surface is serving
// from the registry.
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
		Run: func(a any, args []string) (Result, error) {
			if len(args) == 0 {
				return Value(r.Schema()), nil
			}

			if c := r.Get(Name(args[0])); c != nil {
				return Value(r.schemaFor(c)), nil
			}

			if err := r.unavailable(Name(args[0])); err != nil {
				return Failed("%s", err), nil
			}

			return Failed("Command not available %s", args[0]), nil
		},
		Text: renderHelp,
	})
}

// renderHelp is help's human rendering: the command list, or one command's usage.
func renderHelp(v any, w io.Writer) error {
	switch h := v.(type) {
	case []CommandSchema:
		return writeCommandList(h, w)
	case CommandSchema:
		return WriteCommandHelp(h, w)
	default:
		return fmt.Errorf("expected a command schema, got %T", v)
	}
}

func writeCommandList(cmds []CommandSchema, w io.Writer) error {
	if _, err := io.WriteString(w, "Available commands:\n"); err != nil {
		return err
	}

	// In the order the schema came, which is the display order; see Registry.All.
	lines := make([]string, 0, len(cmds))
	for _, c := range cmds {
		lines = append(lines, fmt.Sprintf("%s - %s", c.Name, c.Short))
	}

	_, err := io.WriteString(w, strings.Join(lines, "\n")+"\n\n")
	return err
}

// WriteCommandHelp renders one command's usage. It is the single rendering of a
// CommandSchema for a person: the daemon uses it for `help <command>`, and a client that
// already holds the schema uses it for `-h`, so the two cannot drift.
func WriteCommandHelp(c CommandSchema, w io.Writer) error {
	if _, err := fmt.Fprintf(w, "%s - %s\n", c.Name, c.Short); err != nil {
		return err
	}

	if c.Help != "" {
		if _, err := fmt.Fprintf(w, "  %s\n", c.Help); err != nil {
			return err
		}
	}

	// Same layout as flag.PrintDefaults, including its habit of leaving out a default
	// that is the zero value.
	for _, f := range c.Flags {
		kind := ""
		if !f.Bool {
			kind = " string"
		}
		def := ""
		if f.Default != "" && f.Default != "false" {
			def = fmt.Sprintf(" (default %s)", f.Default)
		}
		if _, err := fmt.Fprintf(w, "  -%s%s\n    \t%s%s\n", f.Name, kind, f.Usage, def); err != nil {
			return err
		}
	}

	return nil
}

// Register adds a command that can be run by a user.
//
// It panics if the command declares a reserved flag. That is a programming error, and
// surfacing it here, at startup, is better than at the moment an operator first types
// the command.
func (r *Registry) Register(c *Command) {
	if c.Run == nil {
		panic(fmt.Sprintf("commands: %s has no Run", c.Name))
	}

	if c.Flags != nil {
		if fl, _ := c.Flags(); fl != nil {
			for _, name := range reservedFlags {
				if fl.Lookup(name) != nil {
					panic(fmt.Sprintf("commands: %s declares reserved flag -%s", c.Name, name))
				}
			}
		}
	}

	r.insert(c)
}

// insert adds c without the reserved flag check, for commands that have already passed
// it on another registry.
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

// All returns every registered command sorted by name, which is the order help lists
// them and the schema describes them.
func (r *Registry) All() []*Command {
	r.mu.RLock()
	defer r.mu.RUnlock()

	cmds := slices.Collect(maps.Values(r.commands))
	slices.SortFunc(cmds, func(a, b *Command) int { return cmp.Compare(a.Name, b.Name) })
	return cmds
}

// Filter returns a filtered copy of the registry.
//
// Keep should return true for commands that should be included in the copy.
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

// unavailable explains why name cannot be run here when this registry was filtered from
// one that holds it: the command exists, and this surface withholds it, for the reason
// whoever built the filter gave. It is nil when name is simply unknown, so the two cases
// read differently to an operator.
func (r *Registry) unavailable(name Name) error {
	if r.full == nil {
		return nil
	}

	c := r.full.Get(name)
	if c == nil {
		return nil
	}

	reason := r.reason
	if reason == "" {
		reason = "this surface does not serve it"
	}

	return fmt.Errorf("%s is not available on this surface: %s", c.Name, reason)
}

// Resolve returns the command registered under name, or says why there is none: the
// filter's reason for one this surface withholds, or unknown for a name that does not
// exist.
func (r *Registry) Resolve(name Name) (*Command, error) {
	if c := r.Get(name); c != nil {
		return c, nil
	}

	if err := r.unavailable(name); err != nil {
		return nil, err
	}

	return nil, fmt.Errorf("unknown command %q", name)
}

// setParams sets each named parameter on fl, in the order of names, and stops at the
// first that is unknown or does not parse. own says whether the command declared flags
// of its own, which decides between "takes no parameters" and "has no parameter".
//
// The presentation flags are on fl, since commandFlags put them there, but they are not
// parameters: a request has one place to choose its rendering, the envelope's format
// field, and a client that sends them here is told where that is rather than having a
// second, weaker way to say the same thing.
func setParams(fl *flag.FlagSet, name string, names []string, params map[string]string, own bool) error {
	for _, k := range names {
		if isPresentationFlag(k) {
			return fmt.Errorf("%s is a command line flag, not a parameter; choose the rendering with the request's format field", k)
		}

		f := fl.Lookup(k)
		if f == nil {
			if !own {
				return fmt.Errorf("%s takes no parameters", name)
			}
			return fmt.Errorf("%s has no parameter %q", name, k)
		}

		v := params[k]
		if err := fl.Set(k, v); err != nil {
			if IsBoolFlag(f) {
				// The flag package's own words for this are "parse error".
				return fmt.Errorf("%s: expected a boolean, got %q", k, v)
			}
			return fmt.Errorf("%s: %w", k, err)
		}
	}

	return nil
}

// Schema describes every command in the registry, so a client can offer them without
// having been built against this daemon.
func (r *Registry) Schema() []CommandSchema {
	all := r.All()
	out := make([]CommandSchema, 0, len(all))
	for _, c := range all {
		out = append(out, r.schemaFor(c))
	}
	return out
}

// schemaFor describes one command. It is the one derivation, for the whole schema and
// for `help <command>` alike.
func (r *Registry) schemaFor(c *Command) CommandSchema {
	fl, _, _ := commandFlags(c)
	return schemaOf(c, fl)
}

// schemaOf describes c as driven through fl, the FlagSet commandFlags built for it. The
// presentation flags are included because a command line client parses its line
// against this and help renders from it; they are listed after the command's own,
// which is where readers expect them. Invoke refuses them as parameters.
func schemaOf(c *Command, fl *flag.FlagSet) CommandSchema {
	cs := CommandSchema{Name: c.Name, Short: c.ShortDescription, Help: c.Help}

	var own, shared []FlagSchema
	fl.VisitAll(func(f *flag.Flag) {
		fs := FlagSchema{
			Name:    f.Name,
			Bool:    IsBoolFlag(f),
			Default: f.DefValue,
			Usage:   f.Usage,
		}
		if isPresentationFlag(f.Name) {
			shared = append(shared, fs)
			return
		}
		own = append(own, fs)
	})
	cs.Flags = append(own, shared...)

	return cs
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
