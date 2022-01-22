//go:build !e2e_testing
// +build !e2e_testing

package overlay

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"syscall"

	"github.com/sirupsen/logrus"
)

func newTunFromFd(_ *logrus.Logger, _ int, _ *net.IPNet, _ int, _ []Route, _ int) (Device, error) {
	return nil, fmt.Errorf("newTunFromFd not supported in Windows")
}

func newTun(l *logrus.Logger, deviceName string, cidr *net.IPNet, defaultMTU int, routes []Route, _ int, _ bool) (Device, error) {
	if len(routes) > 0 {
		return nil, fmt.Errorf("route MTU not supported in Windows")
	}

	useWintun := true
	if err := checkWinTunExists(); err != nil {
		l.WithError(err).Warn("Check Wintun driver failed, fallback to wintap driver")
		useWintun = false
	}

	if useWintun {
		device, err := newWinTun(l, deviceName, cidr, defaultMTU, routes)
		if err != nil {
			return nil, fmt.Errorf("create Wintun interface failed, %w", err)
		}
		return device, nil
	}

	device, err := newWaterTun(l, cidr, defaultMTU, routes)
	if err != nil {
		return nil, fmt.Errorf("create wintap driver failed, %w", err)
	}
	return device, nil
}

func checkWinTunExists() error {
	myPath, err := os.Executable()
	if err != nil {
		return err
	}

	arch := runtime.GOARCH
	switch arch {
	case "386":
		//NOTE: wintun bundles 386 as x86
		arch = "x86"
	}

	_, err = syscall.LoadDLL(filepath.Join(filepath.Dir(myPath), "dist", "windows", "wintun", "bin", arch, "wintun.dll"))
	return err
}
