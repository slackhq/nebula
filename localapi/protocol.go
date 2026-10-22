// Package localapi serves the nebula command registry over local IPC endpoints: the
// control socket, so the user who ran nebula can inspect and control it from a CLI on
// the same machine, and the info API, so other programs on the machine can ask who is
// behind a vpn address.
//
// The control socket's access is the socket's own: without a group it is 0600 to the
// user who ran nebula, and the server checks the peer's credentials on every connection
// besides; with a group configured it is 0660 to that group, and the kernel's check on
// connect is the whole of it, so a member has the same control of the daemon as its
// user. It serves every command in the registry. The info API is opt in, HTTP, and as
// open as the operator makes its socket; it serves the identity commands alone, decided
// here, on the serving side; see InfoServer for what that is and why it is safe.
//
// # Protocol
//
// One JSON object in, one JSON object out, both newline terminated. It is an API, not a
// command line: a request names a command and passes its options as named parameters,
// rather than shipping an argv the daemon has to parse. A client that is itself a CLI
// asks for the schema first (Request.Describe) and turns the user's flags into those
// parameters; a client that is not need never think in flags at all.
package localapi

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// ProtocolVersion is the version of the request and response envelopes. A client sending
// a version this server does not know gets a sentence back rather than a parse error,
// which matters because the daemon and the CLI are upgraded independently.
const ProtocolVersion = 1

// MaxRequestBytes bounds the request. A request names a command and its parameters, so it
// has no business being large, and an unbounded read is a way for a local process to
// consume memory the packet path needs.
const MaxRequestBytes = 64 * 1024

// Request is the single JSON object a client sends.
type Request struct {
	Version int `json:"version"`

	// Describe asks for the schema of every command this surface serves, in place of
	// running one. Command, Params and Args are ignored.
	Describe bool `json:"describe,omitempty"`

	// Command names the command to run.
	Command string `json:"command,omitempty"`

	// Params carries the command's options by name, with JSON's own types, true rather
	// than "true", 3 rather than "3", or as the strings a command line parsed them from,
	// which is what nebula ctl sends. Unknown names are an error, so a typo is reported
	// instead of ignored. The schema lists json and pretty on every command because the
	// command lines take them; here they are refused, since Format is how a request
	// chooses its rendering.
	Params map[string]any `json:"params,omitempty"`

	// Args carries the command's operands, the values that are not options: the vpn
	// address `print-tunnel` prints, for instance. They stay positional because the
	// commands do not name them.
	Args []string `json:"args,omitempty"`

	// Format asks for a rendering other than the default. "" and "json" return the
	// command's result as a JSON value, which is what a program wants. "text" asks the
	// daemon to run the command's own human rendering and return it as a string, which is
	// how `nebula ctl` shows an operator the same output the ssh server would.
	Format string `json:"format,omitempty"`
}

// Response is the single JSON object a server sends back.
type Response struct {
	Version int `json:"version"`

	// Result is what a request for JSON produced: the command's value, or the schema
	// when the request was a Describe, as a JSON value, so a caller reads it directly
	// instead of parsing a string that happens to contain JSON.
	//
	// Whitespace inside a JSON result is not preserved: an envelope normalises it, and
	// in an API it carries no meaning anyway. Formatting a result for a human to read is
	// the client's job.
	Result json.RawMessage `json:"result,omitempty"`

	// Text is what a request for text produced: the command's own human rendering, the
	// bytes it wrote and nothing else. They travel as bytes, base64 in the envelope,
	// rather than as a JSON string, because a string is UTF-8 and the rendering need
	// not be: a name from a certificate is whatever the certificate holds, and the ssh
	// server passes it through, so this does too.
	Text []byte `json:"text,omitempty"`

	// Error explains a failure in a sentence, and is absent on success. It is the only
	// signal a caller needs: there is no separate status field, because a command that
	// failed always says why and one that succeeded never does. A command line client
	// turns its presence into a non-zero exit.
	//
	// A command that ran and refused sets Error too, alongside its Result when the
	// caller asked for JSON. That is how a refusal and a request that never ran are
	// told apart: the first has both, the second has Error alone.
	Error string `json:"error,omitempty"`
}

// frameError is a frame that arrived and was not one: oversized, or not the JSON object
// the protocol defines. It is told from a failed read so the client can say the daemon
// answered with something it could not read, rather than that it could not be reached.
type frameError struct{ err error }

func (e *frameError) Error() string { return e.err.Error() }
func (e *frameError) Unwrap() error { return e.err }

// readFrame reads one frame, a newline terminated JSON object, from r into v. With
// writeFrame it is where the framing rule lives, for both directions: a frame is a
// single line, a line over max bytes is refused rather than buffered, and a final line
// with no newline before EOF still counts. what names the frame in errors ("request", "response"); a
// read failure is returned wrapped, so a caller can still see io.EOF or a timeout in it.
// strict refuses a field v does not declare, which is the daemon's reading of a request:
// a client that misspells one deserves to hear about it, as it does for a parameter.
// The client reads a response leniently, so a field a newer daemon adds is passed over
// rather than fatal.
func readFrame(r io.Reader, max int, what string, v any, strict bool) error {
	br := bufio.NewReader(io.LimitReader(r, int64(max)+1))

	line, err := br.ReadBytes('\n')
	if err != nil && (len(line) == 0 || !errors.Is(err, io.EOF)) {
		// EOF after a partial line is the unterminated final line the rule allows, and
		// an oversized line looks the same once the LimitReader cuts it off, so both go
		// on to be judged by their length. Anything else is a failed read, whatever was
		// buffered first: a deadline that lands mid frame is a timeout, not a parse
		// error in half a document.
		return fmt.Errorf("could not read %s: %w", what, err)
	}

	// The limit is on the body, not the frame, so the terminator does not count
	// against it. A body that exceeds max is cut off by the LimitReader before its
	// newline, so a missing terminator is also what an oversized line looks like.
	body := bytes.TrimSuffix(line, []byte{'\n'})
	if len(body) > max {
		return &frameError{fmt.Errorf("%s exceeded %d bytes", what, max)}
	}

	dec := json.NewDecoder(bytes.NewReader(body))
	if strict {
		dec.DisallowUnknownFields()
	}
	if err := dec.Decode(v); err != nil {
		return &frameError{fmt.Errorf("could not parse %s: %w", what, err)}
	}

	// Strict is one object and nothing after it: a second object, or stray bytes, on
	// the line would be read as part of a request that happened to decode, and is
	// refused the way an unknown field is.
	if strict {
		if _, err := dec.Token(); err != io.EOF {
			return fmt.Errorf("could not parse %s: unexpected data after the object", what)
		}
	}

	return nil
}

// writeFrame writes v to w as one frame: the JSON object and the newline that ends it.
func writeFrame(w io.Writer, v any) error {
	body, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("could not encode frame: %w", err)
	}

	_, err = w.Write(append(body, '\n'))
	return err
}
