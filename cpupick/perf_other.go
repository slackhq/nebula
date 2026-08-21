//go:build !linux

package cpupick

// perfCPUs is Linux-only sysfs walking; elsewhere report "no distinction".
// Default already returns nil off-Linux (util.AllowedCPUs has no answer
// there), so this exists to keep the package compiling everywhere.
func perfCPUs(allowed []int) ([]int, string) {
	return allowed, ""
}
