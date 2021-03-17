package nebula

// Darwin support is primarily implemented in udp_generic, besides NewListenConfig

import (
	"fmt"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

func NewListenConfig(multi bool) net.ListenConfig {
	return net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var controlErr error
			err := c.Control(func(fd uintptr) {
				if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_SNDBUF, 999999); err != nil {
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
				if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, 999999); err != nil {
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
				var controlErr error
				err := c.Control(func(fd uintptr) {
					if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, unix.SO_REUSEPORT, 1); err != nil {
						controlErr = fmt.Errorf("SO_REUSEPORT failed: %v", err)
						return
					}
				})
				if err != nil {
					return err
				}
				if controlErr != nil {
					return controlErr
				}
			}
			return nil
		},
	}
}

func (u *udpConn) Rebind() error {
	file, err := u.File()
	if err != nil {
		return err
	}

	return syscall.SetsockoptInt(int(file.Fd()), unix.IPPROTO_IP, unix.IP_BOUND_IF, 0)
}
