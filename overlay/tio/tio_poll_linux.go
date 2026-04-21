package tio

import (
	"fmt"
	"os"
	"sync/atomic"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Maximum size we accept for a single read from a TUN with IFF_VNET_HDR. A
// TSO superpacket can be up to 64KiB of payload plus a single L2/L3/L4 header
// prefix plus the virtio header.
const tunReadBufSize = 65535

type Poll struct {
	fd int

	readPoll  [2]unix.PollFd
	writePoll [2]unix.PollFd
	closed    atomic.Bool

	readBuf  []byte
	batchRet [1][]byte
}

func newPoll(fd int, shutdownFd int) (*Poll, error) {
	if err := unix.SetNonblock(fd, true); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("failed to set Poll device as nonblocking: %w", err)
	}

	out := &Poll{
		fd:      fd,
		readBuf: make([]byte, tunReadBufSize),
		readPoll: [2]unix.PollFd{
			{Fd: int32(fd), Events: unix.POLLIN},
			{Fd: int32(shutdownFd), Events: unix.POLLIN},
		},
		writePoll: [2]unix.PollFd{
			{Fd: int32(fd), Events: unix.POLLOUT},
			{Fd: int32(shutdownFd), Events: unix.POLLIN},
		},
	}
	return out, nil
}

// blockOnRead waits until the Poll fd is readable or shutdown has been signaled.
// Returns os.ErrClosed if Close was called.
func (t *Poll) blockOnRead() error {
	const problemFlags = unix.POLLHUP | unix.POLLNVAL | unix.POLLERR
	var err error
	for {
		_, err = unix.Poll(t.readPoll[:], -1)
		if err != unix.EINTR {
			break
		}
	}
	tunEvents := t.readPoll[0].Revents
	shutdownEvents := t.readPoll[1].Revents
	t.readPoll[0].Revents = 0
	t.readPoll[1].Revents = 0
	if err != nil {
		return err
	}
	if shutdownEvents&(unix.POLLIN|problemFlags) != 0 {
		return os.ErrClosed
	}
	if tunEvents&problemFlags != 0 {
		return os.ErrClosed
	}
	return nil
}

func (t *Poll) blockOnWrite() error {
	const problemFlags = unix.POLLHUP | unix.POLLNVAL | unix.POLLERR
	var err error
	for {
		_, err = unix.Poll(t.writePoll[:], -1)
		if err != unix.EINTR {
			break
		}
	}
	tunEvents := t.writePoll[0].Revents
	shutdownEvents := t.writePoll[1].Revents
	t.writePoll[0].Revents = 0
	t.writePoll[1].Revents = 0
	if err != nil {
		return err
	}
	if shutdownEvents&(unix.POLLIN|problemFlags) != 0 {
		return os.ErrClosed
	}
	if tunEvents&problemFlags != 0 {
		return os.ErrClosed
	}
	return nil
}

func (t *Poll) Read() ([][]byte, error) {
	if t.readBuf == nil {
		t.readBuf = make([]byte, defaultBatchBufSize)
	}
	n, err := t.readOne(t.readBuf)
	if err != nil {
		return nil, err
	}
	t.batchRet[0] = t.readBuf[:n]
	return t.batchRet[:], nil
}

func (t *Poll) readOne(to []byte) (int, error) {
	// first 4 bytes is protocol family, in network byte order
	var head [4]byte
	iovecs := [2]syscall.Iovec{ //todo plat-specific
		{&head[0], 4},
		{&to[0], uint64(len(to))},
	}
	for {
		n, _, errno := syscall.Syscall(syscall.SYS_READV, uintptr(t.fd), uintptr(unsafe.Pointer(&iovecs[0])), 2)
		if errno == 0 {
			bytesRead := int(n)
			if bytesRead < 4 {
				return 0, nil
			}
			return bytesRead - 4, nil
		}
		switch errno {
		case unix.EAGAIN:
			if err := t.blockOnRead(); err != nil {
				return 0, err
			}
		case unix.EINTR:
			// retry
		case unix.EBADF:
			return 0, os.ErrClosed
		default:
			return 0, errno
		}
	}
}

// Write is only valid for single threaded use
func (t *Poll) Write(from []byte) (int, error) {
	if len(from) <= 1 {
		return 0, syscall.EIO
	}

	ipVer := from[0] >> 4
	var head [4]byte
	// first 4 bytes is protocol family, in network byte order
	switch ipVer {
	case 4:
		head[3] = syscall.AF_INET
	case 6:
		head[3] = syscall.AF_INET6
	default:
		return 0, fmt.Errorf("unable to determine IP version from packet")
	}

	iovecs := [2]syscall.Iovec{ //todo plat specific
		{&head[0], 4},
		{&from[0], uint64(len(from))},
	}
	for {
		n, _, errno := syscall.Syscall(syscall.SYS_WRITEV, uintptr(t.fd), uintptr(unsafe.Pointer(&iovecs[0])), 2)
		if errno == 0 {
			return int(n) - 4, nil
		}
		switch errno {
		case unix.EAGAIN:
			if err := t.blockOnWrite(); err != nil {
				return 0, err
			}
		case unix.EINTR:
			// retry
		case unix.EBADF:
			return 0, os.ErrClosed
		default:
			return 0, errno
		}
	}
}

func (t *Poll) Close() error {
	if t.closed.Swap(true) {
		return nil
	}

	//shutdownFd is owned by the container, so we should not close it

	var err error
	if t.fd >= 0 {
		err = unix.Close(t.fd)
		t.fd = -1
	}

	return err
}

func (t *Poll) WriteReject(p []byte) (int, error) {
	return t.Write(p)
}
