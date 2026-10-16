//go:build (openbsd || netbsd) && !e2e_testing

package overlay

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"runtime"

	"golang.org/x/sys/unix"
)

var deviceNameRE = regexp.MustCompile(`^tun[0-9]+$`)

// tunDevNeedsRestart is true when tun.dev asks for a particular tun that isn't the running one. Anything else takes the
// first free one, and the one we have will do
func tunDevNeedsRestart(name, running string) bool {
	return deviceNameRE.MatchString(name) && name != running
}

// openTun opens /dev/name, or the first /dev/tunN nothing else has open when name is empty or not tunN
func openTun(l *slog.Logger, name string) (int, string, error) {
	if name != "" && !deviceNameRE.MatchString(name) {
		// The name doesn't mean anything here, so like darwin a bad one isn't worth refusing to start over
		l.Warn("interface name must be tun[0-9]+ on "+runtime.GOOS+", ignoring", "name", name)
		name = ""
	}
	if name != "" {
		fd, err := unix.Open("/dev/"+name, os.O_RDWR, 0)
		return fd, name, err
	}
	for i := 0; ; i++ {
		name = fmt.Sprintf("tun%d", i)
		fd, err := unix.Open("/dev/"+name, os.O_RDWR, 0)
		if err == nil {
			return fd, name, nil
		}
		if !errors.Is(err, unix.EBUSY) {
			return -1, "", fmt.Errorf("no free tun device, %s: %w", name, err)
		}
	}
}
