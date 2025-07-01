package udp

import "errors"

var ErrInvalidIPv6RemoteForSocket = errors.New("listener is IPv4, but writing to IPv6 remote")
