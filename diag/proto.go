package diag

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// The ctl protocol is one request, one response, one connection.
//
// The request is a single JSON line. argv travels as a list rather than a joined string so
// that a path with a space in it survives the trip; the client already has a real argv from
// the operating system and re-splitting it would only ever lose information.
//
// The response is a stream of frames rather than raw bytes followed by a status line,
// because there is no sentinel that is safe to look for: `print-cert -raw` emits arbitrary
// PEM and `list-hostmap -json` emits arbitrary JSON, either of which could contain whatever
// terminator we picked.
const (
	// ProtoVersion is the only request version this build understands. An unknown version
	// gets a legible error rather than a hang, which is the whole point of sending it.
	ProtoVersion = 1

	// frameOutput carries raw command output, destined for the client's stdout.
	frameOutput = 0x01
	// frameEnd carries a JSON endPayload and is the last frame on a connection.
	frameEnd = 0x02
	// frameStderr is reserved. Commands write to a single writer today, so there is nothing
	// to put in it, but holding the number means adding one later needs no version bump.
	frameStderr = 0x03

	// maxFrame bounds a single frame's payload. Larger writes are split across frames.
	maxFrame = 64 * 1024
	// maxRequest bounds the request line, so a client that never sends a newline cannot make
	// nebula buffer without limit.
	maxRequest = 64 * 1024
	// outputBuffer is what keeps json.NewEncoder(w.GetWriter()) from emitting a frame per
	// token; output accumulates here and flushes in useful sized chunks.
	outputBuffer = 32 * 1024
)

// ErrTruncated means the connection ended before the end frame arrived, which is how a
// client notices that nebula died or was torn down partway through a command.
var ErrTruncated = errors.New("connection closed before the command finished")

// request is the JSON line a client sends.
type request struct {
	Version int      `json:"version"`
	Args    []string `json:"args"`
}

// endPayload is the JSON body of the end frame. Error is set only when Status is non-zero
// and describes a failure to run the command, not a failure the command itself reported.
type endPayload struct {
	Status int    `json:"status"`
	Error  string `json:"error,omitempty"`
}

// writeRequest sends the request line.
func writeRequest(w io.Writer, args []string) error {
	b, err := json.Marshal(request{Version: ProtoVersion, Args: args})
	if err != nil {
		return err
	}

	if len(b)+1 > maxRequest {
		return fmt.Errorf("command line is too long: %d bytes", len(b))
	}

	_, err = w.Write(append(b, '\n'))
	return err
}

// readRequest reads and validates one request line.
func readRequest(r *bufio.Reader) (request, error) {
	var req request

	line, err := readLimitedLine(r, maxRequest)
	if err != nil {
		return req, err
	}

	if err := json.Unmarshal(line, &req); err != nil {
		return req, fmt.Errorf("malformed request: %w", err)
	}

	if req.Version != ProtoVersion {
		return req, fmt.Errorf("unsupported protocol version %d, this nebula speaks version %d", req.Version, ProtoVersion)
	}

	return req, nil
}

// readLimitedLine reads through the next newline, refusing a line longer than limit rather
// than buffering whatever an unfriendly client decides to send.
func readLimitedLine(r *bufio.Reader, limit int) ([]byte, error) {
	line := make([]byte, 0, 256)
	for {
		b, err := r.ReadByte()
		if err != nil {
			return nil, err
		}

		if b == '\n' {
			return line, nil
		}

		if len(line) >= limit {
			return nil, fmt.Errorf("request exceeded %d bytes without a newline", limit)
		}

		line = append(line, b)
	}
}

// frameWriter turns writes into output frames. It is handed to commands wrapped in a
// bufio.Writer, so a command that makes many small writes does not make many small frames.
type frameWriter struct {
	w io.Writer
}

func (f *frameWriter) Write(b []byte) (int, error) {
	written := 0
	for {
		chunk := b[written:]
		if len(chunk) > maxFrame {
			chunk = chunk[:maxFrame]
		}

		if err := writeFrame(f.w, frameOutput, chunk); err != nil {
			return written, err
		}

		written += len(chunk)
		if written == len(b) {
			return written, nil
		}
	}
}

// writeFrame emits one frame: a type byte, a big endian length, then the payload.
func writeFrame(w io.Writer, kind byte, payload []byte) error {
	var hdr [5]byte
	hdr[0] = kind
	binary.BigEndian.PutUint32(hdr[1:], uint32(len(payload)))

	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}

	if len(payload) == 0 {
		return nil
	}

	_, err := w.Write(payload)
	return err
}

// writeEnd emits the final frame. A transport error here is unreportable by definition, the
// connection is the only channel we have.
func writeEnd(w io.Writer, status int, msg string) error {
	b, err := json.Marshal(endPayload{Status: status, Error: msg})
	if err != nil {
		return err
	}

	return writeFrame(w, frameEnd, b)
}

// readResponse consumes frames until the end frame, copying output to out. It returns the
// command's exit status. A non-nil error means the exchange failed and the status is
// meaningless.
func readResponse(r io.Reader, out io.Writer) (int, error) {
	var hdr [5]byte

	for {
		if _, err := io.ReadFull(r, hdr[:]); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return 0, ErrTruncated
			}
			return 0, err
		}

		length := binary.BigEndian.Uint32(hdr[1:])
		if length > maxFrame {
			return 0, fmt.Errorf("frame of %d bytes exceeds the %d byte maximum", length, maxFrame)
		}

		payload := make([]byte, length)
		if _, err := io.ReadFull(r, payload); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return 0, ErrTruncated
			}
			return 0, err
		}

		switch hdr[0] {
		case frameOutput:
			if _, err := out.Write(payload); err != nil {
				return 0, err
			}

		case frameEnd:
			var end endPayload
			if err := json.Unmarshal(payload, &end); err != nil {
				return 0, fmt.Errorf("malformed end frame: %w", err)
			}

			if end.Error != "" {
				return end.Status, errors.New(end.Error)
			}

			return end.Status, nil

		case frameStderr:
			// Reserved and unused by this build. Skipping rather than failing means an older
			// client stays usable against a newer nebula that starts sending them.

		default:
			return 0, fmt.Errorf("unknown frame type 0x%02x", hdr[0])
		}
	}
}
