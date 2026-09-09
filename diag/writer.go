package diag

import "io"

type StringWriter interface {
	WriteLine(string) error
	Write(string) error
	WriteBytes([]byte) error
	GetWriter() io.Writer
}

type stringWriter struct {
	w io.Writer
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

// NewWriter adapts an io.Writer to the StringWriter commands are handed. Transports
// implement their own framing behind w; the commands never know the difference.
func NewWriter(w io.Writer) StringWriter {
	return &stringWriter{w: w}
}
