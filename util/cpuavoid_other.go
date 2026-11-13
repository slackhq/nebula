//go:build !linux || android || e2e_testing

package util

import "errors"

// AvoidCPUs is unsupported outside Linux: there is no thread affinity API to restrict.
func AvoidCPUs(_ []int, _ bool) error { return errors.ErrUnsupported }
