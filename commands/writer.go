package commands

import "io"

// StringWriter is how a command talks back to whoever invoked it: one stream, which the
// ssh surface points at its channel.
type StringWriter interface {
	WriteLine(string) error
	Write(string) error
	WriteBytes([]byte) error
	GetWriter() io.Writer
}

type stringWriter struct {
	w io.Writer
}

// NewStringWriter returns a StringWriter that writes to w.
func NewStringWriter(w io.Writer) StringWriter {
	return &stringWriter{w: w}
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
