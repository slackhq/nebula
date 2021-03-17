package nebula

// Windows support is primarily implemented in udp_generic, besides NewListenConfig

import (
	"fmt"
	"net"
	"syscall"
)

func NewListenConfig(multi bool) net.ListenConfig {
	return net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var controlErr error
			err := c.Control(func(fd uintptr) {
				if err := syscall.SetsockoptInt(syscall.Handle(fd), syscall.SOL_SOCKET, syscall.SO_SNDBUF, 999999); err != nil {
					controlErr = fmt.Errorf("SO_SNDBUF failed: %v", err)
					return
				}
			})
			if err != nil {
				return err
			}
			if controlErr != nil {
				return controlErr
			}
			err = c.Control(func(fd uintptr) {
				if err := syscall.SetsockoptInt(syscall.Handle(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, 999999); err != nil {
					controlErr = fmt.Errorf("SO_RCVBUF failed: %v", err)
					return
				}
			})
			if err != nil {
				return err
			}
			if controlErr != nil {
				return controlErr
			}

			if multi {
				// There is no way to support multiple listeners safely on Windows:
				// https://docs.microsoft.com/en-us/windows/desktop/winsock/using-so-reuseaddr-and-so-exclusiveaddruse
				return fmt.Errorf("multiple udp listeners not supported on windows")
			}
			return nil
		},
	}
}

func (u *udpConn) Rebind() error {
	return nil
}
