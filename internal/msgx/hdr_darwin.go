package msgx

import "golang.org/x/sys/unix"

// Hdr mirrors xnu's struct msghdr_x (bsd/sys/socket_private.h), which the SDK doesn't ship.
// recvmsg_x reports each message's length in Datalen rather than in its return value.
type Hdr struct {
	Name       *byte
	Namelen    uint32
	Iov        *unix.Iovec
	Iovlen     int32
	Control    *byte
	Controllen uint32
	Flags      int32
	Datalen    uint64
}
