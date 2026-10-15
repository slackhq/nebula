//go:build !linux || android || e2e_testing

package cpupick

import "errors"

// Avoid is unsupported outside Linux: there is no thread affinity API to restrict.
func Avoid(_ []int, _ bool) error { return errors.ErrUnsupported }
