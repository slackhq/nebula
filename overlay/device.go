package overlay

import (
	"io"
	"net"
)

type Device interface {
	io.ReadWriteCloser
	Activate() error
	CidrNet() *net.IPNet
	DeviceName() string
	WriteRaw([]byte) error
	NewMultiQueueReader() (io.ReadWriteCloser, error)
}
