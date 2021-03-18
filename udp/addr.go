package udp

import (
	"encoding/json"
	"fmt"
	"net"
	"strconv"
)

type m map[string]interface{}

type Addr struct {
	IP   net.IP
	Port uint16
}

func NewAddr(ip net.IP, port uint16) *Addr {
	addr := Addr{IP: make([]byte, len(ip)), Port: port}
	copy(addr.IP, ip)
	return &addr
}

func NewAddrFromString(s string) *Addr {
	ip, port, err := parseIPAndPort(s)
	//TODO: handle err
	_ = err
	return &Addr{IP: ip, Port: port}
}

func (ua *Addr) Equals(t *Addr) bool {
	if t == nil || ua == nil {
		return t == nil && ua == nil
	}
	return ua.IP.Equal(t.IP) && ua.Port == t.Port
}

func (ua *Addr) String() string {
	return net.JoinHostPort(ua.IP.String(), fmt.Sprintf("%v", ua.Port))
}

func (ua *Addr) MarshalJSON() ([]byte, error) {
	return json.Marshal(m{"ip": ua.IP, "port": ua.Port})
}

func (ua *Addr) Copy() *Addr {
	nu := Addr{
		Port: ua.Port,
		IP:   make(net.IP, len(ua.IP)),
	}

	copy(nu.IP, ua.IP)
	return &nu
}

func parseIPAndPort(s string) (net.IP, uint16, error) {
	rIp, sPort, err := net.SplitHostPort(s)
	if err != nil {
		return nil, 0, err
	}

	iPort, err := strconv.Atoi(sPort)
	ip := net.ParseIP(rIp)
	return ip, uint16(iPort), nil
}
