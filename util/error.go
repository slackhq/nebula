package util

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
)

type ContextualError struct {
	RealError error
	Fields    map[string]any
	Context   string
}

func NewContextualError(msg string, fields map[string]any, realError error) *ContextualError {
	return &ContextualError{Context: msg, Fields: fields, RealError: realError}
}

// ContextualizeIfNeeded is a helper function to turn an error into a ContextualError if it is not already one
func ContextualizeIfNeeded(msg string, err error) error {
	switch err.(type) {
	case *ContextualError:
		return err
	default:
		return NewContextualError(msg, nil, err)
	}
}

// LogWithContextIfNeeded is a helper function to log an error line for an error or ContextualError
func LogWithContextIfNeeded(msg string, err error, l *slog.Logger) {
	switch v := err.(type) {
	case *ContextualError:
		v.Log(l)
	default:
		l.Error(msg, "error", err)
	}
}

func (ce *ContextualError) Error() string {
	if ce.RealError == nil {
		return ce.Context
	}
	return fmt.Errorf("%s (%v): %w", ce.Context, ce.Fields, ce.RealError).Error()
}

func (ce *ContextualError) Unwrap() error {
	if ce.RealError == nil {
		return errors.New(ce.Context)
	}
	return ce.RealError
}

// Log emits ce as a single error-level log line with Fields and RealError
// promoted to top-level attributes, producing a flat shape callers can grep
// or parse without walking into a nested object.
func (ce *ContextualError) Log(l *slog.Logger) {
	attrs := make([]slog.Attr, 0, len(ce.Fields)+1)
	for k, v := range ce.Fields {
		attrs = append(attrs, slog.Any(k, v))
	}
	if ce.RealError != nil {
		attrs = append(attrs, slog.Any("error", ce.RealError))
	}
	// LogAttrs is intentional: attrs is built from a map[string]any so it has
	// no pair-form equivalent.
	//nolint:sloglint
	l.LogAttrs(context.Background(), slog.LevelError, ce.Context, attrs...)
}
