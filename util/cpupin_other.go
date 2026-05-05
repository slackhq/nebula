//go:build !linux || android || e2e_testing

package util

// PinThreadToCPU is a no-op outside Linux: only Linux exposes a stable
// per-thread CPU affinity API and only Linux has XPS-driven TX ring
// selection in the first place. On every other platform there's nothing
// to fix here.
func PinThreadToCPU(_ int) error {
	return nil
}
