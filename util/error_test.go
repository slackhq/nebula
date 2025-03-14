package util

import (
	"errors"
	"fmt"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

type m = map[string]any

type TestLogWriter struct {
	Logs []string
}

func NewTestLogWriter() *TestLogWriter {
	return &TestLogWriter{Logs: make([]string, 0)}
}

func (tl *TestLogWriter) Write(p []byte) (n int, err error) {
	tl.Logs = append(tl.Logs, string(p))
	return len(p), nil
}

func (tl *TestLogWriter) Reset() {
	tl.Logs = tl.Logs[:0]
}

func TestContextualError_Log(t *testing.T) {
	l := logrus.New()
	l.Formatter = &logrus.TextFormatter{
		DisableTimestamp: true,
		DisableColors:    true,
	}

	tl := NewTestLogWriter()
	l.Out = tl

	// Test a full context line
	tl.Reset()
	e := NewContextualError("test message", m{"field": "1"}, errors.New("error"))
	e.Log(l)
	assert.Equal(t, []string{"level=error msg=\"test message\" error=error field=1\n"}, tl.Logs)

	// Test a line with an error and msg but no fields
	tl.Reset()
	e = NewContextualError("test message", nil, errors.New("error"))
	e.Log(l)
	assert.Equal(t, []string{"level=error msg=\"test message\" error=error\n"}, tl.Logs)

	// Test just a context and fields
	tl.Reset()
	e = NewContextualError("test message", m{"field": "1"}, nil)
	e.Log(l)
	assert.Equal(t, []string{"level=error msg=\"test message\" field=1\n"}, tl.Logs)

	// Test just a context
	tl.Reset()
	e = NewContextualError("test message", nil, nil)
	e.Log(l)
	assert.Equal(t, []string{"level=error msg=\"test message\"\n"}, tl.Logs)

	// Test just an error
	tl.Reset()
	e = NewContextualError("", nil, errors.New("error"))
	e.Log(l)
	assert.Equal(t, []string{"level=error error=error\n"}, tl.Logs)
}

func TestLogWithContextIfNeeded(t *testing.T) {
	l := logrus.New()
	l.Formatter = &logrus.TextFormatter{
		DisableTimestamp: true,
		DisableColors:    true,
	}

	tl := NewTestLogWriter()
	l.Out = tl

	// Test ignoring fallback context
	tl.Reset()
	e := NewContextualError("test message", m{"field": "1"}, errors.New("error"))
	LogWithContextIfNeeded("This should get thrown away", e, l)
	assert.Equal(t, []string{"level=error msg=\"test message\" error=error field=1\n"}, tl.Logs)

	// Test using fallback context
	tl.Reset()
	err := fmt.Errorf("this is a normal error")
	LogWithContextIfNeeded("Fallback context woo", err, l)
	assert.Equal(t, []string{"level=error msg=\"Fallback context woo\" error=\"this is a normal error\"\n"}, tl.Logs)
}

func TestContextualizeIfNeeded(t *testing.T) {
	// Test ignoring fallback context
	e := NewContextualError("test message", m{"field": "1"}, errors.New("error"))
	assert.Same(t, e, ContextualizeIfNeeded("should be ignored", e))

	// Test using fallback context
	err := fmt.Errorf("this is a normal error")
	cErr := ContextualizeIfNeeded("Fallback context woo", err)

	switch v := cErr.(type) {
	case *ContextualError:
		assert.Equal(t, err, v.RealError)
	default:
		t.Error("Error was not wrapped")
		t.Fail()
	}
}
