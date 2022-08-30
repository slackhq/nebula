//go:build windows
// +build windows

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2021 WireGuard LLC. All Rights Reserved.
 */

//NOTE: this file was forked from https://git.zx2c4.com/wireguard-go/tree/tun/tun.go?id=851efb1bb65555e0f765a3361c8eb5ac47435b19

package wintun

import (
	"os"
)

type Device interface {
	File() *os.File                 // returns the file descriptor of the device
	Read([]byte, int) (int, error)  // read a packet from the device (without any additional headers)
	Write([]byte, int) (int, error) // writes a packet to the device (without any additional headers)
	Flush() error                   // flush all previous writes to the device
	Name() (string, error)          // fetches and returns the current name
	Close() error                   // stops the device and closes the event channel
}
