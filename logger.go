package nebula

import (
	"errors"

	"github.com/sirupsen/logrus"
)

type ContextualError struct {
	RealError error
	Fields    map[string]interface{}
	Context   string
}

func NewContextualError(msg string, fields map[string]interface{}, realError error) ContextualError {
	return ContextualError{Context: msg, Fields: fields, RealError: realError}
}

func (ce ContextualError) Error() string {
	if ce.RealError == nil {
		return ce.Context
	}
	return ce.RealError.Error()
}

func (ce ContextualError) Unwrap() error {
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
