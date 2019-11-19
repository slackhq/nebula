package sshd

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
