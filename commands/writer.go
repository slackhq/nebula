package commands

import "io"

// StringWriter is how a command talks back to whoever invoked it.
//
// Out and Err are distinct so a command's primary output stays machine readable on
// surfaces that separate the two (the local control socket maps them to different
// frames). The ssh surface points both at the same channel, which is why it sees a
// single merged stream exactly as it always has.
type StringWriter interface {
	WriteLine(string) error
	Write(string) error
	WriteBytes([]byte) error
	GetWriter() io.Writer
	Err() io.Writer
}

type stringWriter struct {
	w io.Writer
	e io.Writer
}

// NewStringWriter returns a StringWriter that merges output and errors onto w.
func NewStringWriter(w io.Writer) StringWriter {
	return &stringWriter{w: w, e: w}
}

// NewSplitStringWriter returns a StringWriter that sends command output to out and
// usage/error text to err.
func NewSplitStringWriter(out, err io.Writer) StringWriter {
	return &stringWriter{w: out, e: err}
}

func (w *stringWriter) WriteLine(s string) error {
	return w.Write(s + "\n")
}

func (w *stringWriter) Write(s string) error {
	_, err := w.w.Write([]byte(s))
	return err
}

func (w *stringWriter) WriteBytes(b []byte) error {
	_, err := w.w.Write(b)
	return err
}

func (w *stringWriter) GetWriter() io.Writer {
	return w.w
}

func (w *stringWriter) Err() io.Writer {
	return w.e
}
