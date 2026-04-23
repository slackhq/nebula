package util

import (
	"bytes"
	"errors"
	"fmt"
	"testing"

	"github.com/slackhq/nebula/test"
	"github.com/stretchr/testify/assert"
)

type m = map[string]any

func TestContextualError_Log(t *testing.T) {
	buf := &bytes.Buffer{}
	l := test.NewLoggerWithOutput(buf)

	// Test a full context line
	buf.Reset()
	e := NewContextualError("test message", m{"field": "1"}, errors.New("error"))
	e.Log(l)
	assert.Equal(t, "level=ERROR msg=\"test message\" field=1 error=error\n", buf.String())

	// Test a line with an error and msg but no fields
	buf.Reset()
	e = NewContextualError("test message", nil, errors.New("error"))
	e.Log(l)
	assert.Equal(t, "level=ERROR msg=\"test message\" error=error\n", buf.String())

	// Test just a context and fields
	buf.Reset()
	e = NewContextualError("test message", m{"field": "1"}, nil)
	e.Log(l)
	assert.Equal(t, "level=ERROR msg=\"test message\" field=1\n", buf.String())

	// Test just a context
	buf.Reset()
	e = NewContextualError("test message", nil, nil)
	e.Log(l)
	assert.Equal(t, "level=ERROR msg=\"test message\"\n", buf.String())

	// Test just an error
	buf.Reset()
	e = NewContextualError("", nil, errors.New("error"))
	e.Log(l)
	assert.Equal(t, "level=ERROR msg=\"\" error=error\n", buf.String())
}

func TestLogWithContextIfNeeded(t *testing.T) {
	buf := &bytes.Buffer{}
	l := test.NewLoggerWithOutput(buf)

	// Test ignoring fallback context
	buf.Reset()
	e := NewContextualError("test message", m{"field": "1"}, errors.New("error"))
	LogWithContextIfNeeded("This should get thrown away", e, l)
	assert.Equal(t, "level=ERROR msg=\"test message\" field=1 error=error\n", buf.String())

	// Test using fallback context
	buf.Reset()
	err := fmt.Errorf("this is a normal error")
	LogWithContextIfNeeded("Fallback context woo", err, l)
	assert.Equal(t, "level=ERROR msg=\"Fallback context woo\" error=\"this is a normal error\"\n", buf.String())
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
