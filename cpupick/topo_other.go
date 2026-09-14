//go:build !linux

package cpupick

// readTopology has no sysfs to consult off Linux; the flat stand-in makes
// arrange's NUMA and SMT rules no-ops. Default is already nil off Linux
// (util.AllowedCPUs has no answer there) — this keeps the package compiling.
func readTopology(cpus []int) topology {
	return flatTopology(cpus)
}
