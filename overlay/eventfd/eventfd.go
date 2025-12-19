package eventfd

import (
	"encoding/binary"
	"syscall"

	"golang.org/x/sys/unix"
)

type EventFD struct {
	fd  int
	buf [8]byte
}

func New() (EventFD, error) {
	fd, err := unix.Eventfd(0, unix.EFD_NONBLOCK)
	if err != nil {
		return EventFD{}, err
	}
	return EventFD{
		fd:  fd,
		buf: [8]byte{},
	}, nil
}

func (e *EventFD) Kick() error {
	binary.LittleEndian.PutUint64(e.buf[:], 1) //is this right???
	_, err := syscall.Write(int(e.fd), e.buf[:])
	return err
}

func (e *EventFD) Close() error {
	if e.fd != 0 {
		return unix.Close(e.fd)
	}
	return nil
}

func (e *EventFD) FD() int {
	return e.fd
}

type Epoll struct {
	fd     int
	buf    [8]byte
	events []syscall.EpollEvent
}

func NewEpoll() (Epoll, error) {
	fd, err := unix.EpollCreate1(0)
	if err != nil {
		return Epoll{}, err
	}
	return Epoll{
		fd:     fd,
		buf:    [8]byte{},
		events: make([]syscall.EpollEvent, 1),
	}, nil
}

func (ep *Epoll) AddEvent(fdToAdd int) error {
	event := syscall.EpollEvent{
		Events: syscall.EPOLLIN,
		Fd:     int32(fdToAdd),
	}
	return syscall.EpollCtl(ep.fd, syscall.EPOLL_CTL_ADD, fdToAdd, &event)
}

func (ep *Epoll) Block() (int, error) {
	n, err := syscall.EpollWait(ep.fd, ep.events, -1)
	if err != nil {
		//goland:noinspection GoDirectComparisonOfErrors
		if err == syscall.EINTR {
			return 0, nil //??
		}
		return -1, err
	}
	return n, nil
}

func (ep *Epoll) Clear() error {
	_, err := syscall.Read(int(ep.events[0].Fd), ep.buf[:])
	return err
}

func (ep *Epoll) Close() error {
	if ep.fd != 0 {
		return unix.Close(ep.fd)
	}
	return nil
}
