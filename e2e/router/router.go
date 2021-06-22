// +build e2e_testing

package router

import (
	"fmt"
	"net"
	"reflect"
	"strconv"
	"sync"

	"github.com/slackhq/nebula"
)

type R struct {
	// Simple map of the ip:port registered on a control to the control
	// Basically a router, right?
	controls map[string]*nebula.Control

	// A map for inbound packets for a control that doesn't know about this address
	inNat map[string]*nebula.Control

	// A last used map, if an inbound packet hit the inNat map then
	// all return packets should use the same last used inbound address for the outbound sender
	// map[from address + ":" + to address] => ip:port to rewrite in the udp packet to receiver
	outNat map[string]net.UDPAddr

	// All interactions are locked to help serialize behavior
	sync.Mutex
}

type ExitType int

const (
	// Keeps routing, the function will get called again on the next packet
	KeepRouting ExitType = 0
	// Does not route this packet and exits immediately
	ExitNow ExitType = 1
	// Routes this packet and exits immediately afterwards
	RouteAndExit ExitType = 2
)

type ExitFunc func(packet *nebula.UdpPacket, receiver *nebula.Control) ExitType

func NewR(controls ...*nebula.Control) *R {
	r := &R{
		controls: make(map[string]*nebula.Control),
		inNat:    make(map[string]*nebula.Control),
		outNat:   make(map[string]net.UDPAddr),
	}

	for _, c := range controls {
		addr := c.GetUDPAddr()
		if _, ok := r.controls[addr]; ok {
			panic("Duplicate listen address: " + addr)
		}
		r.controls[addr] = c
	}

	return r
}

// AddRoute will place the nebula controller at the ip and port specified.
// It does not look at the addr attached to the instance.
// If a route is used, this will behave like a NAT for the return path.
// Rewriting the source ip:port to what was last sent to from the origin
func (r *R) AddRoute(ip net.IP, port uint16, c *nebula.Control) {
	r.Lock()
	defer r.Unlock()

	inAddr := net.JoinHostPort(ip.String(), fmt.Sprintf("%v", port))
	if _, ok := r.inNat[inAddr]; ok {
		panic("Duplicate listen address inNat: " + inAddr)
	}
	r.inNat[inAddr] = c
}

// OnceFrom will route a single packet from sender then return
// If the router doesn't have the nebula controller for that address, we panic
func (r *R) OnceFrom(sender *nebula.Control) {
	r.RouteExitFunc(sender, func(*nebula.UdpPacket, *nebula.Control) ExitType {
		return RouteAndExit
	})
}

// RouteUntilTxTun will route for sender and return when a packet is seen on receivers tun
// If the router doesn't have the nebula controller for that address, we panic
func (r *R) RouteUntilTxTun(sender *nebula.Control, receiver *nebula.Control) []byte {
	tunTx := receiver.GetTunTxChan()
	udpTx := sender.GetUDPTxChan()

	for {
		select {
		// Maybe we already have something on the tun for us
		case b := <-tunTx:
			return b

		// Nope, lets push the sender along
		case p := <-udpTx:
			outAddr := sender.GetUDPAddr()
			r.Lock()
			inAddr := net.JoinHostPort(p.ToIp.String(), fmt.Sprintf("%v", p.ToPort))
			c := r.getControl(outAddr, inAddr, p)
			if c == nil {
				r.Unlock()
				panic("No control for udp tx")
			}

			c.InjectUDPPacket(p)
			r.Unlock()
		}
	}
}

// RouteExitFunc will call the whatDo func with each udp packet from sender.
// whatDo can return:
//   - exitNow: the packet will not be routed and this call will return immediately
//   - routeAndExit: this call will return immediately after routing the last packet from sender
//   - keepRouting: the packet will be routed and whatDo will be called again on the next packet from sender
func (r *R) RouteExitFunc(sender *nebula.Control, whatDo ExitFunc) {
	h := &nebula.Header{}
	for {
		p := sender.GetFromUDP(true)
		r.Lock()
		if err := h.Parse(p.Data); err != nil {
			panic(err)
		}

		outAddr := sender.GetUDPAddr()
		inAddr := net.JoinHostPort(p.ToIp.String(), fmt.Sprintf("%v", p.ToPort))
		receiver := r.getControl(outAddr, inAddr, p)
		if receiver == nil {
			r.Unlock()
			panic("Can't route for host: " + inAddr)
		}

		e := whatDo(p, receiver)
		switch e {
		case ExitNow:
			r.Unlock()
			return

		case RouteAndExit:
			receiver.InjectUDPPacket(p)
			r.Unlock()
			return

		case KeepRouting:
			receiver.InjectUDPPacket(p)

		default:
			panic(fmt.Sprintf("Unknown exitFunc return: %v", e))
		}

		r.Unlock()
	}
}

// RouteUntilAfterMsgType will route for sender until a message type is seen and sent from sender
// If the router doesn't have the nebula controller for that address, we panic
func (r *R) RouteUntilAfterMsgType(sender *nebula.Control, msgType nebula.NebulaMessageType, subType nebula.NebulaMessageSubType) {
	h := &nebula.Header{}
	r.RouteExitFunc(sender, func(p *nebula.UdpPacket, r *nebula.Control) ExitType {
		if err := h.Parse(p.Data); err != nil {
			panic(err)
		}
		if h.Type == msgType && h.Subtype == subType {
			return RouteAndExit
		}

		return KeepRouting
	})
}

// RouteForUntilAfterToAddr will route for sender and return only after it sees and sends a packet destined for toAddr
// finish can be any of the exitType values except `keepRouting`, the default value is `routeAndExit`
// If the router doesn't have the nebula controller for that address, we panic
func (r *R) RouteForUntilAfterToAddr(sender *nebula.Control, toAddr *net.UDPAddr, finish ExitType) {
	if finish == KeepRouting {
		finish = RouteAndExit
	}

	r.RouteExitFunc(sender, func(p *nebula.UdpPacket, r *nebula.Control) ExitType {
		if p.ToIp.Equal(toAddr.IP) && p.ToPort == uint16(toAddr.Port) {
			return finish
		}

		return KeepRouting
	})
}

// RouteForAllExitFunc will route for every registered controller and calls the whatDo func with each udp packet from
// whatDo can return:
//   - exitNow: the packet will not be routed and this call will return immediately
//   - routeAndExit: this call will return immediately after routing the last packet from sender
//   - keepRouting: the packet will be routed and whatDo will be called again on the next packet from sender
func (r *R) RouteForAllExitFunc(whatDo ExitFunc) {
	sc := make([]reflect.SelectCase, len(r.controls))
	cm := make([]*nebula.Control, len(r.controls))

	i := 0
	for _, c := range r.controls {
		sc[i] = reflect.SelectCase{
			Dir:  reflect.SelectRecv,
			Chan: reflect.ValueOf(c.GetUDPTxChan()),
			Send: reflect.Value{},
		}

		cm[i] = c
		i++
	}

	for {
		x, rx, _ := reflect.Select(sc)
		r.Lock()

		p := rx.Interface().(*nebula.UdpPacket)

		outAddr := cm[x].GetUDPAddr()
		inAddr := net.JoinHostPort(p.ToIp.String(), fmt.Sprintf("%v", p.ToPort))
		receiver := r.getControl(outAddr, inAddr, p)
		if receiver == nil {
			r.Unlock()
			panic("Can't route for host: " + inAddr)
		}

		e := whatDo(p, receiver)
		switch e {
		case ExitNow:
			r.Unlock()
			return

		case RouteAndExit:
			receiver.InjectUDPPacket(p)
			r.Unlock()
			return

		case KeepRouting:
			receiver.InjectUDPPacket(p)

		default:
			panic(fmt.Sprintf("Unknown exitFunc return: %v", e))
		}
		r.Unlock()
	}
}

// FlushAll will route for every registered controller, exiting once there are no packets left to route
func (r *R) FlushAll() {
	sc := make([]reflect.SelectCase, len(r.controls))
	cm := make([]*nebula.Control, len(r.controls))

	i := 0
	for _, c := range r.controls {
		sc[i] = reflect.SelectCase{
			Dir:  reflect.SelectRecv,
			Chan: reflect.ValueOf(c.GetUDPTxChan()),
			Send: reflect.Value{},
		}

		cm[i] = c
		i++
	}

	// Add a default case to exit when nothing is left to send
	sc = append(sc, reflect.SelectCase{
		Dir:  reflect.SelectDefault,
		Chan: reflect.Value{},
		Send: reflect.Value{},
	})

	for {
		x, rx, ok := reflect.Select(sc)
		if !ok {
			return
		}
		r.Lock()

		p := rx.Interface().(*nebula.UdpPacket)

		outAddr := cm[x].GetUDPAddr()
		inAddr := net.JoinHostPort(p.ToIp.String(), fmt.Sprintf("%v", p.ToPort))
		receiver := r.getControl(outAddr, inAddr, p)
		if receiver == nil {
			r.Unlock()
			panic("Can't route for host: " + inAddr)
		}
		r.Unlock()
	}
}

// getControl performs or seeds NAT translation and returns the control for toAddr, p from fields may change
// This is an internal router function, the caller must hold the lock
func (r *R) getControl(fromAddr, toAddr string, p *nebula.UdpPacket) *nebula.Control {
	if newAddr, ok := r.outNat[fromAddr+":"+toAddr]; ok {
		p.FromIp = newAddr.IP
		p.FromPort = uint16(newAddr.Port)
	}

	c, ok := r.inNat[toAddr]
	if ok {
		sHost, sPort, err := net.SplitHostPort(toAddr)
		if err != nil {
			panic(err)
		}

		port, err := strconv.Atoi(sPort)
		if err != nil {
			panic(err)
		}

		r.outNat[c.GetUDPAddr()+":"+fromAddr] = net.UDPAddr{
			IP:   net.ParseIP(sHost),
			Port: port,
		}
		return c
	}

	return r.controls[toAddr]
}
