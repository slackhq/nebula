//go:build linux && !android && !e2e_testing

package util

import (
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"
)

func TestParseCPUList(t *testing.T) {
	cases := []struct {
		in   string
		want []int
	}{
		{"", nil},
		{"3", []int{3}},
		{"0-3", []int{0, 1, 2, 3}},
		{"0-2,8,10-11", []int{0, 1, 2, 8, 10, 11}},
		{"garbage", nil},
		{"1,garbage,4", []int{1, 4}},
	}
	for _, c := range cases {
		if got := parseCPUList(c.in); !reflect.DeepEqual(got, c.want) {
			t.Errorf("parseCPUList(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestTrailingInt(t *testing.T) {
	cases := []struct {
		in   string
		want int
		ok   bool
	}{
		{"mlx5_comp12", 12, true},
		{"ice-eth0-TxRx-3", 3, true},
		{"virtio0-input.7", 7, true},
		{"mlx5_async0", 0, true},
		{"no-digits", 0, false},
		{"", 0, false},
	}
	for _, c := range cases {
		got, ok := trailingInt(c.in)
		if got != c.want || ok != c.ok {
			t.Errorf("trailingInt(%q) = (%d, %v), want (%d, %v)", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestContainsWord(t *testing.T) {
	if !containsWord("ice-eth0-TxRx-3", "eth0") {
		t.Error("eth0 should match with boundaries")
	}
	if containsWord("ice-eth01-TxRx-3", "eth0") {
		t.Error("eth0 must not match inside eth01")
	}
	if !containsWord("eth0", "eth0") {
		t.Error("exact match should work")
	}
}

// fakeNIC builds /sys/class/net/<name> with operstate, a device symlink to a
// PCI-address-named dir (physical NICs only), and nq rx queue directories.
func fakeNIC(t *testing.T, netDir, name, operstate, pciAddr string, nq int) {
	t.Helper()
	devPath := filepath.Join(netDir, name)
	if err := os.MkdirAll(devPath, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(devPath, "operstate"), []byte(operstate+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if pciAddr == "" {
		return
	}
	pciDir := filepath.Join(netDir, "..", "devices", pciAddr)
	if err := os.MkdirAll(pciDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(pciDir, filepath.Join(devPath, "device")); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < nq; i++ {
		if err := os.MkdirAll(filepath.Join(devPath, "queues", "rx-"+strconv.Itoa(i)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
}

func writeIRQ(t *testing.T, irqDir, irq, affinity string) {
	t.Helper()
	p := filepath.Join(irqDir, irq)
	if err := os.MkdirAll(p, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(p, "effective_affinity_list"), []byte(affinity+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestNICIRQCPUs(t *testing.T) {
	root := t.TempDir()
	netDir := filepath.Join(root, "class", "net")
	irqDir := filepath.Join(root, "irq")
	if err := os.MkdirAll(netDir, 0o755); err != nil {
		t.Fatal(err)
	}

	// eth0: up, 2 active queues at 0000:82:00.0. comp0/comp1 active,
	// comp2 is a deactivated queue's leftover handler, async0 always fires.
	fakeNIC(t, netDir, "eth0", "up", "0000:82:00.0", 2)
	// eth1: physical but down; its vectors must not count.
	fakeNIC(t, netDir, "eth1", "down", "0000:83:00.0", 2)
	// eth9: up, matched by ifname (intel-style action names), 1 queue.
	fakeNIC(t, netDir, "eth9", "up", "0000:84:00.0", 1)
	// nebula1: virtual, no device dir.
	fakeNIC(t, netDir, "nebula1", "up", "", 0)

	interrupts := filepath.Join(root, "interrupts")
	content := `           CPU0       CPU1
 100:   1 2   IR-PCI-MSIX  1-edge  mlx5_comp0@pci:0000:82:00.0
 101:   1 2   IR-PCI-MSIX  2-edge  mlx5_comp1@pci:0000:82:00.0
 102:   1 2   IR-PCI-MSIX  3-edge  mlx5_comp2@pci:0000:82:00.0
 103:   1 2   IR-PCI-MSIX  4-edge  mlx5_async0@pci:0000:82:00.0
 200:   1 2   IR-PCI-MSIX  5-edge  mlx5_comp0@pci:0000:83:00.0
 300:   1 2   IR-PCI-MSIX  6-edge  ice-eth9-TxRx-0
 301:   1 2   IR-PCI-MSIX  7-edge  ice-eth9-TxRx-1
 NMI:   0 0   Non-maskable interrupts
`
	if err := os.WriteFile(interrupts, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	writeIRQ(t, irqDir, "100", "0-1") // eth0 comp0: counted
	writeIRQ(t, irqDir, "101", "2")   // eth0 comp1: counted
	writeIRQ(t, irqDir, "102", "5")   // eth0 comp2: beyond 2 queues, skipped
	writeIRQ(t, irqDir, "103", "7")   // eth0 async0: counted
	writeIRQ(t, irqDir, "200", "9")   // eth1 down: skipped
	writeIRQ(t, irqDir, "300", "11")  // eth9 TxRx-0: counted
	writeIRQ(t, irqDir, "301", "12")  // eth9 TxRx-1: beyond 1 queue, skipped

	got, err := nicIRQCPUs(netDir, irqDir, interrupts)
	if err != nil {
		t.Fatalf("nicIRQCPUs: %v", err)
	}
	want := map[int]bool{0: true, 1: true, 2: true, 7: true, 11: true}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("nicIRQCPUs = %v, want %v", got, want)
	}
}
