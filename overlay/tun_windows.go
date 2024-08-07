//go:build !e2e_testing
// +build !e2e_testing

package overlay

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"syscall"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/config"
)

func newTunFromFd(_ *config.C, _ *logrus.Logger, _ int, _ netip.Prefix) (Device, error) {
	return nil, fmt.Errorf("newTunFromFd not supported in Windows")
}

func newTun(c *config.C, l *logrus.Logger, cidr netip.Prefix, multiqueue bool) (Device, error) {
	useWintun := true
	if err := checkWinTunExists(); err != nil {
		l.WithError(err).Warn("Check Wintun driver failed, fallback to wintap driver")
		useWintun = false
	}

	if useWintun {
		device, err := newWinTun(c, l, cidr, multiqueue)
		if err != nil {
			return nil, fmt.Errorf("create Wintun interface failed, %w", err)
		}
		return device, nil
	}

	device, err := newWaterTun(c, l, cidr, multiqueue)
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
