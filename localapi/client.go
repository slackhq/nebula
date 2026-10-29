package localapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/slackhq/nebula/commands"
)

// DialTimeout bounds the connect to a socket that exists but is not being served.
const DialTimeout = 5 * time.Second

// ResponseTimeout bounds the exchange once connected: sending the request and waiting
// for the daemon's answer. The daemon drops a client that is slow to send in 10s and one
// that is slow to read in 30s, so this is the other side of the same bargain, with room
// for the slowest command (a hostmap dump on a large network) before a stalled daemon is
// given up on. Client.Timeout overrides it.
const ResponseTimeout = 60 * time.Second

// MaxResponseBytes bounds what a client will read back. A response carries one command's
// output, and a hostmap dump on a large network is the realistic worst case.
const MaxResponseBytes = 64 << 20

// Client talks to a nebula listening at Path.
type Client struct {
	Path string

	// Timeout bounds the request and response once connected. Zero means
	// ResponseTimeout.
	Timeout time.Duration
}

// ReplyError is an answer the client could not read: the daemon was reached and wrote
// something back, but not a response this client understands. The daemon is not
// nebula, or not a version this client speaks to.
type ReplyError struct {
	Err error
}

func (e *ReplyError) Error() string { return "the daemon's reply could not be read: " + e.Err.Error() }
func (e *ReplyError) Unwrap() error { return e.Err }

// DaemonError is a refusal the daemon answered with: the connection worked, the request
// was read, and the daemon said no. It is told apart from a failure to reach the daemon
// so that a client does not send its user after a socket path, or a sudo, when the daemon
// was right there and answered. A protocol version the daemon does not speak, a socket at
// its connection limit and a peer the daemon will not serve all arrive as one of these.
type DaemonError struct {
	Msg string
}

func (e *DaemonError) Error() string { return e.Msg }

// Describe asks the daemon which commands it serves and what parameters they take, so a
// client can offer them without having been built against this daemon.
func (c *Client) Describe() ([]commands.CommandSchema, error) {
	res, err := c.do(&Request{Version: ProtocolVersion, Describe: true})
	if err != nil {
		return nil, err
	}

	if res.Error != "" {
		return nil, &DaemonError{Msg: res.Error}
	}

	schema := []commands.CommandSchema{}
	if err := json.Unmarshal(res.Result, &schema); err != nil {
		return nil, &ReplyError{Err: fmt.Errorf("could not parse the command schema: %w", err)}
	}

	return schema, nil
}

// Invoke runs one command and returns what the daemon said. params are the command's
// options by name, as the strings a command line parsed them from; a program speaking
// the protocol directly may send JSON's own types instead, see Request.Params. An empty
// format asks for JSON, which is the API's default; "text" asks the daemon to apply the
// command's own human rendering.
func (c *Client) Invoke(command string, params map[string]string, args []string, format string) (*Response, error) {
	var wire map[string]any
	if len(params) > 0 {
		wire = make(map[string]any, len(params))
		for k, v := range params {
			wire[k] = v
		}
	}

	return c.do(&Request{
		Version: ProtocolVersion,
		Command: command,
		Params:  wire,
		Args:    args,
		Format:  format,
	})
}

// do sends one request and reads the one response.
//
// Nothing is checked about the socket before the connect: its mode is the kernel's to
// enforce, and a socket that is not ours to connect to is refused there with a
// permission error, which the caller turns into advice.
func (c *Client) do(req *Request) (*Response, error) {
	conn, err := dial(c.Path, DialTimeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// Without this a daemon that accepts and then stalls, blocked inside a command or
	// stopped with SIGSTOP, hangs the client for good, and a script wrapping it never
	// completes. One deadline covers the write and the read: the answer is due within
	// the budget, however the time is spent.
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = ResponseTimeout
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))

	// If we get a write error, save that fact but then look for a response from the server.
	// Some error conditions manifest as the server accepting our connection, writing an
	// error, and then closing the connection. Our write races against that close.
	writeErr := error(nil)
	if err := writeFrame(conn, req); err != nil {
		writeErr = fmt.Errorf("could not send request: %w", err)
	}

	res, err := readResponse(conn)
	if err != nil {
		// Something answered and it was not a response: the daemon was reached, and
		// that is the message even when it hung up before the request was written,
		// which a daemon that is not nebula is likely to do.
		var fe *frameError
		if errors.As(err, &fe) {
			return nil, &ReplyError{Err: err}
		}
		if writeErr != nil {
			return nil, writeErr
		}
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			return nil, fmt.Errorf("the daemon did not answer within %s", timeout)
		}
		return nil, err
	}

	return res, nil
}

func readResponse(conn net.Conn) (*Response, error) {
	res := &Response{}
	if err := readFrame(conn, MaxResponseBytes, "response", res, false); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("the daemon closed the connection without answering")
		}
		return nil, err
	}

	return res, nil
}
