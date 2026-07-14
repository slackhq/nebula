//go:build linux && !android && !e2e_testing

package util

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// NICIRQCPUs returns the set of CPUs that service interrupts for the ACTIVE
// RX/TX queues of physical network interfaces that are up. Read-only: it
// matches /proc/interrupts action names against each NIC's PCI address and
// interface name, drops vectors whose queue index is beyond the device's
// active queue count (drivers like mlx5 keep handlers registered for
// deactivated queues, so /proc/interrupts alone over-reports), and unions
// /proc/irq/<n>/effective_affinity_list for the survivors.
//
// Callers use this to keep busy pinned threads OFF those CPUs: a thread
// pinned onto a core that also runs NAPI for a NIC RX queue competes with
// softirq processing for the core and measurably collapses throughput for
// flows hashed to that queue.
func NICIRQCPUs() (map[int]bool, error) {
	return nicIRQCPUs("/sys/class/net", "/proc/irq", "/proc/interrupts")
}

// irqAction is one row of /proc/interrupts: the IRQ number and the action
// (handler) name in its final column, e.g. "mlx5_comp3@pci:0000:82:00.0".
type irqAction struct {
	irq    string
	action string
}

func nicIRQCPUs(netDir, irqDir, interruptsPath string) (map[int]bool, error) {
	actions, err := parseInterrupts(interruptsPath)
	if err != nil {
		return nil, err
	}
	devs, err := os.ReadDir(netDir)
	if err != nil {
		return nil, err
	}

	cpus := make(map[int]bool)
	for _, dev := range devs {
		devPath := filepath.Join(netDir, dev.Name())
		pciDev, err := filepath.EvalSymlinks(filepath.Join(devPath, "device"))
		if err != nil {
			continue // virtual device (lo, tun, bridge, vlan, ...)
		}
		pciAddr := filepath.Base(pciDev)
		state, err := os.ReadFile(filepath.Join(devPath, "operstate"))
		if err != nil || strings.TrimSpace(string(state)) != "up" {
			continue // a down NIC's queue IRQs don't fire
		}
		nq := countQueues(filepath.Join(devPath, "queues"))

		for _, ia := range actions {
			if !strings.Contains(ia.action, pciAddr) && !containsWord(ia.action, dev.Name()) {
				continue
			}
			// Vector naming puts the queue index at the end of the handler
			// name (mlx5_comp3@pci:..., ice-eth0-TxRx-3, virtio0-input.3).
			// An index at or beyond the active queue count is a handler for
			// a deactivated queue: registered, but it will not fire.
			name, _, _ := strings.Cut(ia.action, "@")
			if idx, ok := trailingInt(name); ok && idx >= nq {
				continue
			}
			for _, cpu := range irqAffinity(irqDir, ia.irq) {
				cpus[cpu] = true
			}
		}
	}
	return cpus, nil
}

// parseInterrupts extracts (irq, action) pairs from /proc/interrupts,
// skipping the header and the non-numeric summary rows (NMI, LOC, ...).
func parseInterrupts(path string) ([]irqAction, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []irqAction
	for line := range strings.SplitSeq(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		irq, ok := strings.CutSuffix(fields[0], ":")
		if !ok {
			continue
		}
		if _, err := strconv.Atoi(irq); err != nil {
			continue
		}
		out = append(out, irqAction{irq: irq, action: fields[len(fields)-1]})
	}
	return out, nil
}

// irqAffinity returns the CPUs IRQ n actually targets.
// effective_affinity_list is the vector's real target; smp_affinity_list
// (the fallback for kernels without effective affinity reporting) is the
// admin-allowed mask and may be wider.
func irqAffinity(irqDir, irq string) []int {
	irqPath := filepath.Join(irqDir, irq)
	list, err := os.ReadFile(filepath.Join(irqPath, "effective_affinity_list"))
	if err != nil || len(strings.TrimSpace(string(list))) == 0 {
		list, err = os.ReadFile(filepath.Join(irqPath, "smp_affinity_list"))
		if err != nil {
			return nil
		}
	}
	return parseCPUList(strings.TrimSpace(string(list)))
}

// countQueues counts the rx-* entries of a netdev's queues directory — the
// device's ACTIVE RX queues (sysfs removes the directories when a queue is
// deactivated, e.g. by ethtool -L).
func countQueues(queuesDir string) int {
	entries, err := os.ReadDir(queuesDir)
	if err != nil {
		return 0
	}
	n := 0
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "rx-") {
			n++
		}
	}
	return n
}

// containsWord reports whether s contains word bounded by non-alphanumeric
// characters (or string edges), so ifname "eth0" doesn't match "eth01".
func containsWord(s, word string) bool {
	for start := 0; ; {
		i := strings.Index(s[start:], word)
		if i < 0 {
			return false
		}
		i += start
		before := i == 0 || !isAlnum(s[i-1])
		afterIdx := i + len(word)
		after := afterIdx == len(s) || !isAlnum(s[afterIdx])
		if before && after {
			return true
		}
		start = i + 1
	}
}

func isAlnum(b byte) bool {
	return b >= '0' && b <= '9' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z'
}

// trailingInt parses the decimal digits at the end of s.
func trailingInt(s string) (int, bool) {
	i := len(s)
	for i > 0 && s[i-1] >= '0' && s[i-1] <= '9' {
		i--
	}
	if i == len(s) {
		return 0, false
	}
	n, err := strconv.Atoi(s[i:])
	return n, err == nil
}

// parseCPUList parses the kernel's cpulist format: comma-separated CPU ids
// or inclusive ranges, e.g. "0-3,8,10-12". Malformed elements are skipped —
// this parses trusted kernel output, not user input.
func parseCPUList(s string) []int {
	if s == "" {
		return nil
	}
	var cpus []int
	for part := range strings.SplitSeq(s, ",") {
		lo, hi, ok := strings.Cut(part, "-")
		start, err := strconv.Atoi(strings.TrimSpace(lo))
		if err != nil {
			continue
		}
		end := start
		if ok {
			if end, err = strconv.Atoi(strings.TrimSpace(hi)); err != nil {
				continue
			}
		}
		for cpu := start; cpu <= end; cpu++ {
			cpus = append(cpus, cpu)
		}
	}
	return cpus
}
