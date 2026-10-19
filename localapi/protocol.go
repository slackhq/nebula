// Package localapi serves the nebula command registry over a local IPC endpoint so the
// user who ran nebula can inspect and control it from a CLI on the same machine.
//
// Access is restricted by the filesystem (a 0600 socket) and by a peer credential check
// on every connection. Which commands are served is decided by the caller that builds
// the Server, and the filtering happens here, on the serving side, rather than in the
// client.
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
	// instead of ignored.
	Params map[string]any `json:"params,omitempty"`

	// Args carries the command's operands, the values that are not options: the vpn
	// address `print-tunnel` prints, for instance. They stay positional because the
	// commands do not name them.
	Args []string `json:"args,omitempty"`
}

// Response is the single JSON object a server sends back.
type Response struct {
	Version int `json:"version"`

	// Result is what the request produced: the command's output, or the schema when the
	// request was a Describe. It is a JSON value when the command emitted JSON, so a
	// caller reads it directly instead of parsing a string that happens to contain JSON,
	// and a JSON string otherwise.
	//
	// Whitespace inside a JSON result is not preserved: an envelope normalises it, and
	// in an API it carries no meaning anyway. Formatting a result for a human to read is
	// the client's job, which is what Pretty is for.
	Result json.RawMessage `json:"result,omitempty"`

	// Error explains a failure in a sentence, and is absent on success. It is the only
	// signal a caller needs: there is no separate status field, because a command that
	// failed always says why and one that succeeded never does. A command line client
	// turns its presence into a non-zero exit.
	Error string `json:"error,omitempty"`
}

// jsonOrString renders b as a JSON value when it is one, and as a JSON string when it is
// not. A command writes bytes; when those bytes are JSON a caller reads them directly
// rather than parsing a string that happens to contain JSON.
func jsonOrString(b []byte) json.RawMessage {
	if len(b) == 0 {
		return nil
	}

	if json.Valid(b) {
		return json.RawMessage(b)
	}

	quoted, err := json.Marshal(string(b))
	if err != nil {
		return nil
	}

	return quoted
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
func readFrame(r io.Reader, max int, what string, v any) error {
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

	if err := json.Unmarshal(body, v); err != nil {
		return &frameError{fmt.Errorf("could not parse %s: %w", what, err)}
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
