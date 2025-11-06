// SPDX-License-Identifier: MIT
//
// Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.

package conn

import (
	"fmt"
	"net"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

// UDP socket read/write buffer size (7MB). The value of 7MB is chosen as it is
// the max supported by a default configuration of macOS. Some platforms will
// silently clamp the value to other maximums, such as linux clamping to
// net.core.{r,w}mem_max (see _linux.go for additional implementation that works
// around this limitation)
const socketBufferSize = 7 << 20

// controlFn is the callback function signature from net.ListenConfig.Control.
// It is used to apply platform specific configuration to the socket prior to
// bind.
type controlFn func(network, address string, c syscall.RawConn) error

// controlFns is a list of functions that are called from the listen config
// that can apply socket options.
var controlFns = []controlFn{}

const SO_ATTACH_REUSEPORT_EBPF = 52

//Create eBPF program that returns a hash to distribute packets

func createReuseportProgram() (*ebpf.Program, error) {
	// This program uses the packet's hash and returns it modulo number of sockets
	// Simple version: just return a counter-based distribution
	//instructions := asm.Instructions{
	//	// Load the skb->hash value (already computed by kernel)
	//	asm.LoadMem(asm.R0, asm.R1, int16(unsafe.Offsetof(unix.XDPMd{}.RxQueueIndex)), asm.Word),
	//	asm.Return(),
	//}
	//
	//// Alternative: simpler round-robin approach
	//// This returns the CPU number, effectively round-robin
	//instructions := asm.Instructions{
	//	asm.Mov.Reg(asm.R0, asm.R1),              // Move ctx to R0
	//	asm.LoadMem(asm.R0, asm.R1, 0, asm.Word), // Load some field
	//	asm.Return(),
	//}

	// Better: Use BPF helper to get random/hash value
	//instructions := asm.Instructions{
	//	// Call get_prandom_u32() to get random value for distribution
	//	asm.Mov.Imm(asm.R0, 0),
	//	asm.Call.Label("get_prandom_u32"),
	//	asm.Return(),
	//}
	//
	//prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
	//	Type:         ebpf.SocketFilter,
	//	Instructions: instructions,
	//	License:      "GPL",
	//})

	//instructions := asm.Instructions{
	//	// R1 contains pointer to skb
	//	// Load skb->hash at offset 0x20 (may vary by kernel, but 0x20 is common)
	//	asm.LoadMem(asm.R0, asm.R1, 0x20, asm.Word),
	//
	//	// If hash is 0, use rxhash instead (fallback)
	//	asm.JEq.Imm(asm.R0, 0, "use_rxhash"),
	//	asm.Return().Sym("return"),
	//
	//	// Fallback: load rxhash
	//	asm.LoadMem(asm.R0, asm.R1, 0x24, asm.Word).Sym("use_rxhash"),
	//	asm.Return(),
	//}
	//
	//prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
	//	Type:         ebpf.SkReuseport,
	//	Instructions: instructions,
	//	License:      "GPL",
	//})

	//instructions := asm.Instructions{
	//	// R1 = ctx (sk_reuseport_md)
	//	// R2 = sk_reuseport map (we'll use NULL/0 for default behavior)
	//	// R3 = key (select socket index)
	//	// R4 = flags
	//
	//	// Simple approach: use the hash field from sk_reuseport_md
	//	// struct sk_reuseport_md { ... __u32 hash; ... } at offset 24
	//	asm.Mov.Reg(asm.R6, asm.R1), // Save ctx
	//
	//	// Load the hash value at offset 24
	//	asm.LoadMem(asm.R2, asm.R6, 24, asm.Word),
	//
	//	// Call bpf_sk_select_reuseport(ctx, map, key, flags)
	//	asm.Mov.Reg(asm.R1, asm.R6), // ctx
	//	asm.Mov.Imm(asm.R2, 0),      // map (NULL = use default)
	//	asm.Mov.Reg(asm.R3, asm.R2), // key = hash we loaded (in R2)
	//	asm.Mov.Imm(asm.R4, 0),      // flags
	//	asm.Call.Label("sk_select_reuseport"),
	//
	//	// Return 0
	//	asm.Mov.Imm(asm.R0, 0),
	//	asm.Return(),
	//}
	//
	//prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
	//	Type:         ebpf.SkReuseport,
	//	Instructions: instructions,
	//	License:      "GPL",
	//})

	instructions := asm.Instructions{
		// R1 = ctx (sk_reuseport_md pointer)
		// Load hash from sk_reuseport_md at offset 24
		//asm.LoadMem(asm.R0, asm.R1, 20, asm.Word),

		// R1 = ctx (save it)
		asm.Mov.Reg(asm.R6, asm.R1),

		// Prepare string on stack: "BPF called!\n"
		// We need to build the format string on the stack
		asm.Mov.Reg(asm.R1, asm.R10), // R1 = frame pointer
		asm.Add.Imm(asm.R1, -16),     // R1 = stack location for string

		// Write "BPF called!\n" to stack (we'll use a simpler version)
		// Store immediate 64-bit values
		asm.StoreImm(asm.R1, 0, 0x2066706220, asm.DWord), // "bpf "
		asm.StoreImm(asm.R1, 8, 0x0a21, asm.DWord),       // "!\n"

		// Call bpf_trace_printk(fmt, fmt_size)
		// R1 already points to format string
		asm.Mov.Imm(asm.R2, 16), // R2 = format size
		asm.Call.Label("bpf_printk"),

		// Return 0 (send to socket 0 for testing)
		asm.Mov.Imm(asm.R0, 0),
		asm.Return(),

		//asm.Mov.Imm(asm.R0, 0),
		//// Just return the hash directly
		//// The kernel will automatically modulo by number of sockets
		//asm.Return(),
	}

	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type:         ebpf.SkReuseport,
		Instructions: instructions,
		License:      "GPL",
	})

	return prog, err
}

//func createReuseportProgram() (*ebpf.Program, error) {
//	// Try offset 20 (common in newer kernels)
//	instructions := asm.Instructions{
//		asm.LoadMem(asm.R0, asm.R1, 20, asm.Word),
//		asm.Return(),
//	}
//
//	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
//		Type:         ebpf.SkReuseport,
//		Instructions: instructions,
//		License:      "GPL",
//	})
//
//	return prog, err
//}

func reusePortHax(fd uintptr) error {
	prog, err := createReuseportProgram()
	if err != nil {
		return fmt.Errorf("failed to create eBPF program: %w", err)
	}
	//defer prog.Close()
	sockErr := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, SO_ATTACH_REUSEPORT_EBPF, prog.FD())
	if sockErr != nil {
		return sockErr
	}
	return nil
}

var EvilFdZero uintptr

// listenConfig returns a net.ListenConfig that applies the controlFns to the
// socket prior to bind. This is used to apply socket buffer sizing and packet
// information OOB configuration for sticky sockets.
func listenConfig(q int) *net.ListenConfig {
	return &net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			for _, fn := range controlFns {
				if err := fn(network, address, c); err != nil {
					return err
				}
			}

			if q == 0 {
				c.Control(func(fd uintptr) {
					EvilFdZero = fd
				})
				//	var e error
				//	err := c.Control(func(fd uintptr) {
				//		e = reusePortHax(fd)
				//	})
				//	if err != nil {
				//		return err
				//	}
				//	if e != nil {
				//		return e
				//	}
			}

			return nil
		},
	}
}
