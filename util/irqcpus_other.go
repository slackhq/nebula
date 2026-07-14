//go:build !linux || android || e2e_testing

package util

// NICIRQCPUs reports no IRQ information on platforms without the linux
// sysfs interface; callers fall back to their non-IRQ-aware defaults.
func NICIRQCPUs() (map[int]bool, error) {
	return nil, nil
}
