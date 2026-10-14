package commands

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
)

// CommandFlags is called before help or command execution to parse command line flags.
// It should return a flag.FlagSet instance and a pointer to the struct that will contain parsed flags
//
// Every call must build a fresh FlagSet and a fresh struct. Nothing may be shared between
// calls: a command runs on more than one surface and on more than one goroutine.
type CommandFlags func() (*flag.FlagSet, any)

// RunFunc computes a command's Result.
//
// fs is the pointer returned by Command.Flags, if there was one; -h, -help, -json and
// -pretty are reserved and handled before Run is called. a is the operands: whatever
// was not consumed as a flag. The Result is rendered by whichever surface asked: Value
// for a command that reports, Did or Failed for one that acts, Nothing for one with
// nothing to say. An error is for a failure of the command itself; a bad argument is
// Failed, so the caller hears why in its own format.
type RunFunc func(fs any, a []string) (Result, error)

// TextFunc renders a Result's Value for a person. See Typed for declaring one against
// the type the command actually returns.
type TextFunc func(v any, w io.Writer) error

type Command struct {
	Name             Name
	ShortDescription string
	Help             string

	// Identity indicates this command should be made available via the info socket.
	Identity bool

	Flags CommandFlags

	// Run produces the command's Result, leaving presentation to Render.
	Run RunFunc

	// Text renders a Result's Value for a person. Both surfaces call it, so a command
	// reads the same over ssh as it does through the control socket. It never sees an
	// outcome: Render prints those itself, the same way for every command. Leaving it
	// nil declares that no human rendering of the Value exists yet, which JSONOnly says
	// up front; Render then refuses text rather than inventing an interim form for
	// people to script against.
	Text TextFunc

	// JSONOnly declares that the command's Value has no human rendering yet, so a surface
	// whose default is text asks for JSON instead, and the schema says so to a client. It
	// is a statement that no such form exists, not a fallback. A refusal is still
	// rendered as a sentence, since that always has a human form.
	JSONOnly bool

	// Then, when set, is the second half of a command that acts: Run says what is about
	// to happen and Then does it and says how it went, with its Result rendered after
	// Run's and deciding the outcome. A Run that refused is the outcome, and Then does
	// not run. It exists for a command whose action can cut off
	// its own reply: reload restarts the ssh server when the sshd keys changed, which
	// ends the session that asked, so Run's line has to be on the wire before the reload
	// begins. A surface that answers in one piece, the control socket, runs Then before
	// it answers and carries both.
	Then func() Result
}

// Failure is the error a surface gets for a refusal the person has already been shown:
// a Run that returned Failed, a command that is not there, a line that would not parse.
// The message it rendered is the whole story, so the surface reports the failure, exit
// status 1 over ssh, and does not log it.
type Failure struct {
	Msg string
}

func (f *Failure) Error() string {
	return f.Msg
}

// commandFlags returns the FlagSet a command is driven through, on any surface: the
// command's own flags, if it declares any, with the two presentation flags added. own
// reports whether the command declared any of its own, which is what tells a caller
// whether to say a parameter is unknown or that the command takes none at all.
//
// The presentation flags are defined here rather than by each command, because how a
// result is displayed is not a property of the command that produced it. This is also
// the one definition of them: the ssh line parses into it, nebula ctl parses its line
// against the schema derived from it, and help renders from that schema. They are
// command line flags only: a socket request chooses its rendering with the envelope's
// format field, and Invoke refuses them as parameters.
func commandFlags(c *Command) (fl *flag.FlagSet, fs any, own bool) {
	if c.Flags != nil {
		fl, fs = c.Flags()
	}
	own = fl != nil
	if fl == nil {
		fl = flag.NewFlagSet(string(c.Name), flag.ContinueOnError)
	}

	addPresentationFlags(fl)

	// What Parse prints after a bad flag, and for -h: the command's usage as help renders
	// it, so a line that went wrong is answered with the same text as `help <command>`.
	fl.Usage = func() { _ = WriteCommandHelp(schemaOf(c, fl), fl.Output()) }

	return fl, fs, own
}

// addPresentationFlags defines the two presentation flags on fl.
func addPresentationFlags(fl *flag.FlagSet) {
	fl.Bool(FlagJSON, false, "outputs as json")
	fl.Bool(FlagPretty, false, "pretty prints json, assumes -json")
}

// Flagged fills in c's Flags and Run as a pair: define declares the flags on a fresh F,
// and run is handed that F. The struct the flags fill is the struct Run reads by
// construction, so no Run has to assert the type it was given or decide what to do
// when the assertion fails.
func Flagged[F any](c *Command, define func(*flag.FlagSet, *F), run func(*F, []string) (Result, error)) *Command {
	c.Flags = func() (*flag.FlagSet, any) {
		fl := flag.NewFlagSet("", flag.ContinueOnError)
		s := new(F)
		define(fl, s)
		return fl, s
	}
	c.Run = func(fs any, a []string) (Result, error) {
		s, ok := fs.(*F)
		if !ok {
			return Result{}, fmt.Errorf("%s was handed %T for its flags, not %T", c.Name, fs, s)
		}
		return run(s, a)
	}
	return c
}

// isPresentationFlag reports whether name is one of the two flags commandFlags adds.
func isPresentationFlag(name string) bool {
	return name == FlagJSON || name == FlagPretty
}

// execLine runs an ssh command line against c, reporting problems to w. The line is
// parsed into the command's own FlagSet and Run reads it directly, so a flag.Value whose
// String does not re-parse, flag.Func above all, arrives as the line said. Invoke fills
// the same FlagSet through Set.
func (r *Registry) execLine(c *Command, args []string, w Output) error {
	fl, fs, _ := commandFlags(c)

	// Parse reports a bad flag to this writer, with the command's usage after it. -h,
	// -help and --help take the same path with nothing wrong: the usage is the whole
	// answer, and Parse says so with ErrHelp. A -h that is a flag's value or follows --
	// is read as the operand it is, since ParseArgs is the one reading of the line.
	fl.SetOutput(w.Err)
	operands, err := ParseArgs(fl, args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}

	format := presentationFormat(fl)

	// An error from Run is something the command could not do rather than a refusal it
	// chose, but the person at the prompt still hears it; the surface logs it too.
	res, err := c.Run(fs, operands)
	if err != nil {
		_, _ = fmt.Fprintln(w.Err, err.Error())
		return err
	}

	// Run's reply goes out first, and then the action, if the command has one and Run
	// did not refuse, whose Result is the outcome. In JSON only the outcome travels:
	// the promise is for a person to read, and a program expects one document.
	if c.Then == nil || !res.OK || r.formatFor(c, res, format) == FormatText {
		if err := r.renderLine(c, res, format, w); err != nil {
			return err
		}
	}
	if c.Then != nil && res.OK {
		res = c.Then()
		if err := r.renderLine(c, res, format, w); err != nil {
			return err
		}
	}

	if !res.OK {
		return &Failure{Msg: res.Reason}
	}
	return nil
}

// formatFor is the format a Result is rendered in. The line wins when it asked for one;
// otherwise the surface that owns the registry decides, from the command and its
// Result, so each surface can keep its own default.
func (r *Registry) formatFor(c *Command, res Result, format Format) Format {
	if format == FormatUnset {
		return r.defaultFormatFor(c, res)
	}
	return format
}

// renderLine writes one Result of a command line to w; see formatFor. An empty Result
// writes nothing.
func (r *Registry) renderLine(c *Command, res Result, format Format, w Output) error {
	if res.Empty() {
		return nil
	}

	if err := Render(c, res, r.formatFor(c, res, format), w.Out); err != nil {
		if errors.Is(err, ErrNoTextRendering) {
			_, _ = fmt.Fprintln(w.Err, err.Error())
		}
		return err
	}
	return nil
}

// ParseArgs parses args with fl and returns the operands.
//
// It differs from fl.Parse in two ways, and both surfaces parse through here so a line
// means the same typed at an ssh prompt or to nebula ctl.
//
// Flags and operands may come in any order, which is the one way it differs from
// fl.Parse. Parse stops at the first operand, so `print-tunnel 10.0.0.1 -json` would
// reach the command with "-json" as a second operand and the flag silently dropped. Here
// an operand ends nothing: parsing resumes after it, and only "--" ends the flags, with
// everything after it an operand. What counts as a flag is Parse's rule: every argument
// that starts with "-", a negative number included, so one that is meant as an operand
// goes after "--".
func ParseArgs(fl *flag.FlagSet, args []string) ([]string, error) {
	operands := make([]string, 0, len(args))

	for len(args) > 0 {
		// Walk the flags the way Parse will, to the first argument it would not read as a
		// flag: an operand or the terminator. Everything before it is Parse's.
		end := len(args)
		for i := 0; i < len(args); {
			a := args[i]
			if a == "--" {
				if err := fl.Parse(args[:i]); err != nil {
					return nil, err
				}
				return append(operands, args[i+1:]...), nil
			}

			if len(a) < 2 || a[0] != '-' {
				end = i
				break
			}

			f, hasValue := LookupArg(fl, a)
			if f == nil {
				// An undefined flag: leave it for Parse to report.
				i++
				continue
			}

			if hasValue || IsBoolFlag(f) {
				i++
			} else {
				// The flag's value is the next argument, whatever it looks like.
				i += 2
			}
		}

		if err := fl.Parse(args[:end]); err != nil {
			return nil, err
		}

		if end == len(args) {
			break
		}

		operands = append(operands, args[end])
		args = args[end+1:]
	}

	return operands, nil
}

// LookupArg reads arg the way Parse does: one or two leading dashes, the flag's name, and
// an optional "=value". f is the flag of fl by that name, nil when fl has none, and
// hasValue reports that the value came with the argument rather than in the one after it.
// It is the one reading of an argument's shape: ParseArgs walks a line with it, and
// nebula ctl lifts its own flags out of a line with it, so the two cannot disagree about
// which word is a flag's value.
func LookupArg(fl *flag.FlagSet, arg string) (f *flag.Flag, hasValue bool) {
	name := strings.TrimPrefix(strings.TrimPrefix(arg, "-"), "-")
	if eq := strings.IndexByte(name, '='); eq >= 0 {
		name, hasValue = name[:eq], true
	}
	return fl.Lookup(name), hasValue
}

// IsBoolFlag reports whether f is satisfied by its presence alone and never reads the
// argument after it as its value. The flag package marks these with an unexported
// interface, which is the only way to tell.
func IsBoolFlag(f *flag.Flag) bool {
	bf, ok := f.Value.(interface{ IsBoolFlag() bool })
	return ok && bf.IsBoolFlag()
}
