package util

import (
	"errors"
	"fmt"

	"github.com/sirupsen/logrus"
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
func LogWithContextIfNeeded(msg string, err error, l *logrus.Logger) {
	switch v := err.(type) {
	case *ContextualError:
		v.Log(l)
	default:
		l.WithError(err).Error(msg)
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

func (ce *ContextualError) Log(lr *logrus.Logger) {
	if ce.RealError != nil {
		lr.WithFields(ce.Fields).WithError(ce.RealError).Error(ce.Context)
	} else {
		lr.WithFields(ce.Fields).Error(ce.Context)
	}
}
