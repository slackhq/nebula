package commands

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// ErrNoTextRendering is returned by Render when a command's Value has no human rendering
// and text was asked for anyway. A command declares this by leaving Text nil and saying
// so with JSONOnly; it is not a fallback situation but a statement that no such form
// exists yet, so nobody builds a script around an interim one. Each surface's default
// policy avoids ever asking.
var ErrNoTextRendering = errors.New("no human readable output yet; pass -json or -pretty")

// Format is how a result should be presented.
type Format int

const (
	// FormatUnset is a request that expressed no preference. A surface resolves it with
	// its own default before rendering; Render itself treats it as FormatText.
	FormatUnset Format = iota

	// FormatText renders for a person. It is what an operator gets by default on every
	// surface with a human at the other end.
	FormatText

	// FormatJSON renders the result as compact JSON.
	FormatJSON

	// FormatPrettyJSON renders the result as indented JSON.
	FormatPrettyJSON
)

// Flag names for the two presentation flags. They are offered on every command rather
// than declared by each one, because how a result is displayed is not a property of the
// command that produced it.
const (
	FlagJSON   = "json"
	FlagPretty = "pretty"
)

// Flag names nebula ctl takes for itself, anywhere on its line, to say which daemon to
// talk to; see reservedFlags.
const (
	FlagConfig = "config"
	FlagSocket = "socket"
)

// reservedFlags are handled before a command's Run is called, so a command may not
// declare them itself. -h and -help are intercepted as a request for usage; -json and
// -pretty are added to every command's FlagSet by commandFlags, on every surface, so a
// command that defined either would make that definition panic with "flag redefined"
// on whichever goroutine ran the command; and -config and -socket are nebula ctl's own,
// taken off the line before the client knows which command it names, so a command
// that declared either would never receive it there.
var reservedFlags = []string{"h", "help", FlagJSON, FlagPretty, FlagConfig, FlagSocket}

// Render writes r in the requested format. Every surface calls it, so a hostmap looks
// the same over ssh as it does through the control socket, and a change to either
// rendering happens once.
func Render(c *Command, r Result, f Format, w io.Writer) error {
	switch f {
	case FormatJSON:
		return renderJSON(r.Payload(), w, false)

	case FormatPrettyJSON:
		return renderJSON(r.Payload(), w, true)

	default:
		// An outcome reads the same for every command: its reason, as a sentence. Only a
		// Value needs the command's own rendering, so Text never sees anything else.
		if r.Value == nil {
			_, err := io.WriteString(w, r.Reason+"\n")
			return err
		}

		if c != nil && c.Text != nil {
			return c.Text(r.Value, w)
		}

		name := "this command"
		if c != nil {
			name = string(c.Name)
		}
		return fmt.Errorf("%s has %w", name, ErrNoTextRendering)
	}
}

func renderJSON(v any, w io.Writer, indent bool) error {
	enc := json.NewEncoder(w)
	if indent {
		enc.SetIndent("", "    ")
	}

	return enc.Encode(v)
}

// Result is what every Run returns: whether the command worked, a sentence saying so,
// and, for a command that reports rather than acts, the value it produced.
//
// Value and Reason are alternatives. A command that reports returns Value(v), and the
// surfaces render v, as JSON or through the command's Text. A command that acts, or any
// command refusing its arguments, returns Did or Failed, and the surfaces render the
// Outcome: its Reason is the sentence these commands have always printed. Nothing is for
// a command with nothing to say.
//
// The envelope itself never reaches a caller. Payload is what JSON carries, and Render
// hands Text only the Value, so a command's renderer sees the one type it returns on
// success and is never asked to recognise an Outcome.
type Result struct {
	Outcome
	Value any

	// NotFound marks a refusal that is about the thing asked for rather than the asking:
	// a vpn address with no tunnel behind it, as opposed to one that would not parse. It
	// renders exactly as any other refusal, and never reaches the wire; the distinction
	// is for a surface whose protocol has a word for it, so an HTTP client is told 404
	// rather than 400 and never has to parse the sentence.
	NotFound bool
}

// Outcome is the part of a Result that says whether the command worked and, in words a
// caller can show someone, why. It is what a program receives from a command that acts
// rather than reports: closing a tunnel, changing a remote, reloading config.
//
// One shape serves all of them. Designing a payload per outcome would be work without a
// reader. Reason is set either way, so a success says what it did rather than leaving
// the caller to infer it from a bare true.
type Outcome struct {
	OK     bool   `json:"ok"`
	Reason string `json:"reason"`
}

// Value is the Result of a command that reports: v is what it has to show, and it must
// marshal to JSON.
func Value(v any) Result {
	return Result{Outcome: Outcome{OK: true}, Value: v}
}

// Failed is a convenience for the common "it did not work, here is why" case.
func Failed(format string, args ...any) Result {
	return Result{Outcome: Outcome{Reason: fmt.Sprintf(format, args...)}}
}

// NotFound is Failed for a command asked about something that does not exist. See
// Result.NotFound.
func NotFound(format string, args ...any) Result {
	r := Failed(format, args...)
	r.NotFound = true
	return r
}

// Did is a convenience for the common "it worked, here is what happened" case.
func Did(format string, args ...any) Result {
	return Result{Outcome: Outcome{OK: true, Reason: fmt.Sprintf(format, args...)}}
}

// Nothing is the Result of a command with nothing to say: it did its work, and the
// surface sends an empty, successful reply without rendering anything.
func Nothing() Result {
	return Result{Outcome: Outcome{OK: true}}
}

// Empty reports a Result with nothing to render: no Value and no Reason. The zero Result
// counts, so a Run that returns Result{} says nothing rather than failing silently.
func (r Result) Empty() bool {
	return r.Value == nil && r.Reason == ""
}

// Payload is what a program receives: the Value when there is one, otherwise the
// Outcome. No surface sends the envelope itself, so print-tunnel -json emits the tunnel
// and close-tunnel -json emits {ok, reason}.
func (r Result) Payload() any {
	if r.Value != nil {
		return r.Value
	}
	return r.Outcome
}

// Typed adapts a renderer for one result type to the TextFunc a Command declares. The
// value Render passes is the command's own, see Result, so all that is left is to name
// its type once here instead of asserting it at the top of every renderer. A renderer
// paired with a command that returns something else fails here, saying what arrived.
func Typed[T any](render func(T, io.Writer) error) TextFunc {
	return func(v any, w io.Writer) error {
		t, ok := v.(T)
		if !ok {
			return fmt.Errorf("expected %T, got %T", t, v)
		}
		return render(t, w)
	}
}
