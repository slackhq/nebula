//go:build e2e_testing
// +build e2e_testing

package router

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/slackhq/nebula"
	"github.com/slackhq/nebula/header"
	"github.com/slackhq/nebula/udp"
	"golang.org/x/exp/maps"
)

type R struct {
	// Simple map of the ip:port registered on a control to the control
	// Basically a router, right?
	controls map[netip.AddrPort]*nebula.Control

	// A map for inbound packets for a control that doesn't know about this address
	inNat map[netip.AddrPort]*nebula.Control

	// A last used map, if an inbound packet hit the inNat map then
	// all return packets should use the same last used inbound address for the outbound sender
	// map[from address + ":" + to address] => ip:port to rewrite in the udp packet to receiver
	outNat map[string]netip.AddrPort

	// A map of vpn ip to the nebula control it belongs to
	vpnControls map[netip.Addr]*nebula.Control

	ignoreFlows []ignoreFlow
	flow        []flowEntry

	// A set of additional mermaid graphs to draw in the flow log markdown file
	// Currently consisting only of hostmap renders
	additionalGraphs []mermaidGraph

	// All interactions are locked to help serialize behavior
	sync.Mutex

	fn           string
	cancelRender context.CancelFunc
	t            testing.TB
}

type ignoreFlow struct {
	tun         NullBool
	messageType header.MessageType
	subType     header.MessageSubType
	//from
	//to
}

type mermaidGraph struct {
	title   string
	content string
}

type NullBool struct {
	HasValue bool
	IsTrue   bool
}

type flowEntry struct {
	note   string
	packet *packet
}

type packet struct {
	from   *nebula.Control
	to     *nebula.Control
	packet *udp.Packet
	tun    bool // a packet pulled off a tun device
	rx     bool // the packet was received by a udp device
}

func (p *packet) WasReceived() {
	if p != nil {
		p.rx = true
	}
}

type ExitType int

const (
	// KeepRouting the function will get called again on the next packet
	KeepRouting ExitType = 0
	// ExitNow does not route this packet and exits immediately
	ExitNow ExitType = 1
	// RouteAndExit routes this packet and exits immediately afterwards
	RouteAndExit ExitType = 2
)

type ExitFunc func(packet *udp.Packet, receiver *nebula.Control) ExitType

// NewR creates a new router to pass packets in a controlled fashion between the provided controllers.
// The packet flow will be recorded in a file within the mermaid directory under the same name as the test.
// Renders will occur automatically, roughly every 100ms, until a call to RenderFlow() is made
func NewR(t testing.TB, controls ...*nebula.Control) *R {
	ctx, cancel := context.WithCancel(context.Background())

	if err := os.MkdirAll("mermaid", 0755); err != nil {
		panic(err)
	}

	r := &R{
		controls:     make(map[netip.AddrPort]*nebula.Control),
		vpnControls:  make(map[netip.Addr]*nebula.Control),
		inNat:        make(map[netip.AddrPort]*nebula.Control),
		outNat:       make(map[string]netip.AddrPort),
		flow:         []flowEntry{},
		ignoreFlows:  []ignoreFlow{},
		fn:           filepath.Join("mermaid", fmt.Sprintf("%s.md", t.Name())),
		t:            t,
		cancelRender: cancel,
	}

	// Try to remove our render file
	os.Remove(r.fn)

	for _, c := range controls {
		addr := c.GetUDPAddr()
		if _, ok := r.controls[addr]; ok {
			panic("Duplicate listen address: " + addr.String())
		}

		for _, vpnAddr := range c.GetVpnAddrs() {
			r.vpnControls[vpnAddr] = c
		}

		r.controls[addr] = c
	}

	// Spin the renderer in case we go nuts and the test never completes
	go func() {
		clockSource := time.NewTicker(time.Millisecond * 100)
		defer clockSource.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-clockSource.C:
				r.renderHostmaps("clock tick")
				r.renderFlow()
			}
		}
	}()

	return r
}

// AddRoute will place the nebula controller at the ip and port specified.
// It does not look at the addr attached to the instance.
// If a route is used, this will behave like a NAT for the return path.
// Rewriting the source ip:port to what was last sent to from the origin
func (r *R) AddRoute(ip netip.Addr, port uint16, c *nebula.Control) {
	r.Lock()
	defer r.Unlock()

	inAddr := netip.AddrPortFrom(ip, port)
	if _, ok := r.inNat[inAddr]; ok {
		panic("Duplicate listen address inNat: " + inAddr.String())
	}
	r.inNat[inAddr] = c
}

// RenderFlow renders the packet flow seen up until now and stops further automatic renders from happening.
func (r *R) RenderFlow() {
	r.cancelRender()
	r.renderFlow()
}

// CancelFlowLogs stops flow logs from being tracked and destroys any logs already collected
func (r *R) CancelFlowLogs() {
	r.cancelRender()
	r.flow = nil
}

func (r *R) renderFlow() {
	if r.flow == nil {
		return
	}

	f, err := os.OpenFile(r.fn, os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0644)
	if err != nil {
		panic(err)
	}

	var participants = map[netip.AddrPort]struct{}{}
	var participantsVals []string

	fmt.Fprintln(f, "```mermaid")
	fmt.Fprintln(f, "sequenceDiagram")

	// Assemble participants
	for _, e := range r.flow {
		if e.packet == nil {
			continue
		}

		addr := e.packet.from.GetUDPAddr()
		if _, ok := participants[addr]; ok {
			continue
		}
		participants[addr] = struct{}{}
		sanAddr := normalizeName(addr.String())
		participantsVals = append(participantsVals, sanAddr)
		fmt.Fprintf(
			f, "    participant %s as Nebula: %s<br/>UDP: %s\n",
			sanAddr, e.packet.from.GetVpnAddrs(), sanAddr,
		)
	}

	if len(participantsVals) > 2 {
		// Get the first and last participantVals for notes
		participantsVals = []string{participantsVals[0], participantsVals[len(participantsVals)-1]}
	}

	// Print packets
	h := &header.H{}
	for _, e := range r.flow {
		if e.packet == nil {
			//fmt.Fprintf(f, "    note over %s: %s\n", strings.Join(participantsVals, ", "), e.note)
			continue
		}

		p := e.packet
		if p.tun {
			fmt.Fprintln(f, r.formatUdpPacket(p))

		} else {
			if err := h.Parse(p.packet.Data); err != nil {
				panic(err)
			}

			line := "--x"
			if p.rx {
				line = "->>"
			}

			fmt.Fprintf(f,
				"    %s%s%s: %s(%s), index %v, counter: %v\n",
				normalizeName(p.from.GetUDPAddr().String()),
				line,
				normalizeName(p.to.GetUDPAddr().String()),
				h.TypeName(), h.SubTypeName(), h.RemoteIndex, h.MessageCounter,
			)
		}
	}
	fmt.Fprintln(f, "```")

	for _, g := range r.additionalGraphs {
		fmt.Fprintf(f, "## %s\n", g.title)
		fmt.Fprintln(f, "```mermaid")
		fmt.Fprintln(f, g.content)
		fmt.Fprintln(f, "```")
	}
}

func normalizeName(s string) string {
	rx := regexp.MustCompile("[\\[\\]\\:]")
	return rx.ReplaceAllLiteralString(s, "_")
}

// IgnoreFlow tells the router to stop recording future flows that matches the provided criteria.
// messageType and subType will target nebula underlay packets while tun will target nebula overlay packets
// NOTE: This is a very broad system, if you set tun to true then no more tun traffic will be rendered
func (r *R) IgnoreFlow(messageType header.MessageType, subType header.MessageSubType, tun NullBool) {
	r.Lock()
	defer r.Unlock()
	r.ignoreFlows = append(r.ignoreFlows, ignoreFlow{
		tun,
		messageType,
		subType,
	})
}

func (r *R) RenderHostmaps(title string, controls ...*nebula.Control) {
	r.Lock()
	defer r.Unlock()

	s := renderHostmaps(controls...)
	if len(r.additionalGraphs) > 0 {
		lastGraph := r.additionalGraphs[len(r.additionalGraphs)-1]
		if lastGraph.content == s && lastGraph.title == title {
			// Ignore this rendering if it matches the last rendering added
			// This is useful if you want to track rendering changes
			return
		}
	}

	r.additionalGraphs = append(r.additionalGraphs, mermaidGraph{
		title:   title,
		content: s,
	})
}

func (r *R) renderHostmaps(title string) {
	c := maps.Values(r.controls)
	sort.SliceStable(c, func(i, j int) bool {
		return c[i].GetVpnAddrs()[0].Compare(c[j].GetVpnAddrs()[0]) > 0
	})

	s := renderHostmaps(c...)
	if len(r.additionalGraphs) > 0 {
		lastGraph := r.additionalGraphs[len(r.additionalGraphs)-1]
		if lastGraph.content == s {
			// Ignore this rendering if it matches the last rendering added
			// This is useful if you want to track rendering changes
			return
		}
	}

	r.additionalGraphs = append(r.additionalGraphs, mermaidGraph{
		title:   title,
		content: s,
	})
}

// InjectFlow can be used to record packet flow if the test is handling the routing on its own.
// The packet is assumed to have been received
func (r *R) InjectFlow(from, to *nebula.Control, p *udp.Packet) {
	r.Lock()
	defer r.Unlock()
	r.unlockedInjectFlow(from, to, p, false)
}

func (r *R) Log(arg ...any) {
	if r.flow == nil {
		return
	}

	r.Lock()
	r.flow = append(r.flow, flowEntry{note: fmt.Sprint(arg...)})
	r.t.Log(arg...)
	r.Unlock()
}

func (r *R) Logf(format string, arg ...any) {
	if r.flow == nil {
		return
	}

	r.Lock()
	r.flow = append(r.flow, flowEntry{note: fmt.Sprintf(format, arg...)})
	r.t.Logf(format, arg...)
	r.Unlock()
}

// unlockedInjectFlow is used by the router to record a packet has been transmitted, the packet is returned and
// should be marked as received AFTER it has been placed on the receivers channel.
// If flow logs have been disabled this function will return nil
func (r *R) unlockedInjectFlow(from, to *nebula.Control, p *udp.Packet, tun bool) *packet {
	if r.flow == nil {
		return nil
	}

	r.renderHostmaps(fmt.Sprintf("Packet %v", len(r.flow)))

	if len(r.ignoreFlows) > 0 {
		var h header.H
		err := h.Parse(p.Data)
		if err != nil {
			panic(err)
		}

		for _, i := range r.ignoreFlows {
			if !tun {
				if i.messageType == h.Type && i.subType == h.Subtype {
					return nil
				}
			} else if i.tun.HasValue && i.tun.IsTrue {
				return nil
			}
		}
	}

	fp := &packet{
		from:   from,
		to:     to,
		packet: p.Copy(),
		tun:    tun,
	}

	r.flow = append(r.flow, flowEntry{packet: fp})
	return fp
}

// OnceFrom will route a single packet from sender then return
// If the router doesn't have the nebula controller for that address, we panic
func (r *R) OnceFrom(sender *nebula.Control) {
	r.RouteExitFunc(sender, func(*udp.Packet, *nebula.Control) ExitType {
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
			r.Lock()
			np := udp.Packet{Data: make([]byte, len(b))}
			copy(np.Data, b)
			r.unlockedInjectFlow(receiver, receiver, &np, true)
			r.Unlock()
			return b

		// Nope, lets push the sender along
		case p := <-udpTx:
			r.Lock()
			a := sender.GetUDPAddr()
			c := r.getControl(a, p.To, p)
			if c == nil {
				r.Unlock()
				panic("No control for udp tx " + a.String())
			}
			fp := r.unlockedInjectFlow(sender, c, p, false)
			c.InjectUDPPacket(p)
			fp.WasReceived()
			r.Unlock()
		}
	}
}

// RouteForAllUntilTxTun will route for everyone and return when a packet is seen on receivers tun
// If the router doesn't have the nebula controller for that address, we panic
func (r *R) RouteForAllUntilTxTun(receiver *nebula.Control) []byte {
	sc := make([]reflect.SelectCase, len(r.controls)+1)
	cm := make([]*nebula.Control, len(r.controls)+1)

	i := 0
	sc[i] = reflect.SelectCase{
		Dir:  reflect.SelectRecv,
		Chan: reflect.ValueOf(receiver.GetTunTxChan()),
		Send: reflect.Value{},
	}
	cm[i] = receiver

	i++
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

		if x == 0 {
			// we are the tun tx, we can exit
			p := rx.Interface().([]byte)
			np := udp.Packet{Data: make([]byte, len(p))}
			copy(np.Data, p)

			r.unlockedInjectFlow(cm[x], cm[x], &np, true)
			r.Unlock()
			return p

		} else {
			// we are a udp tx, route and continue
			p := rx.Interface().(*udp.Packet)
			a := cm[x].GetUDPAddr()
			c := r.getControl(a, p.To, p)
			if c == nil {
				r.Unlock()
				panic(fmt.Sprintf("No control for udp tx %s", p.To))
			}
			fp := r.unlockedInjectFlow(cm[x], c, p, false)
			c.InjectUDPPacket(p)
			fp.WasReceived()
		}
		r.Unlock()
	}
}

// RouteExitFunc will call the whatDo func with each udp packet from sender.
// whatDo can return:
//   - exitNow: the packet will not be routed and this call will return immediately
//   - routeAndExit: this call will return immediately after routing the last packet from sender
//   - keepRouting: the packet will be routed and whatDo will be called again on the next packet from sender
func (r *R) RouteExitFunc(sender *nebula.Control, whatDo ExitFunc) {
	h := &header.H{}
	for {
		p := sender.GetFromUDP(true)
		r.Lock()
		if err := h.Parse(p.Data); err != nil {
			panic(err)
		}

		receiver := r.getControl(sender.GetUDPAddr(), p.To, p)
		if receiver == nil {
			r.Unlock()
			panic("Can't RouteExitFunc for host: " + p.To.String())
		}

		e := whatDo(p, receiver)
		switch e {
		case ExitNow:
			r.Unlock()
			return

		case RouteAndExit:
			fp := r.unlockedInjectFlow(sender, receiver, p, false)
			receiver.InjectUDPPacket(p)
			fp.WasReceived()
			r.Unlock()
			return

		case KeepRouting:
			fp := r.unlockedInjectFlow(sender, receiver, p, false)
			receiver.InjectUDPPacket(p)
			fp.WasReceived()

		default:
			panic(fmt.Sprintf("Unknown exitFunc return: %v", e))
		}

		r.Unlock()
	}
}

// RouteUntilAfterMsgType will route for sender until a message type is seen and sent from sender
// If the router doesn't have the nebula controller for that address, we panic
func (r *R) RouteUntilAfterMsgType(sender *nebula.Control, msgType header.MessageType, subType header.MessageSubType) {
	h := &header.H{}
	r.RouteExitFunc(sender, func(p *udp.Packet, r *nebula.Control) ExitType {
		if err := h.Parse(p.Data); err != nil {
			panic(err)
		}
		if h.Type == msgType && h.Subtype == subType {
			return RouteAndExit
		}

		return KeepRouting
	})
}

func (r *R) RouteForAllUntilAfterMsgTypeTo(receiver *nebula.Control, msgType header.MessageType, subType header.MessageSubType) {
	h := &header.H{}
	r.RouteForAllExitFunc(func(p *udp.Packet, r *nebula.Control) ExitType {
		if r != receiver {
			return KeepRouting
		}

		if err := h.Parse(p.Data); err != nil {
			panic(err)
		}

		if h.Type == msgType && h.Subtype == subType {
			return RouteAndExit
		}

		return KeepRouting
	})
}

func (r *R) InjectUDPPacket(sender, receiver *nebula.Control, packet *udp.Packet) {
	r.Lock()
	defer r.Unlock()

	fp := r.unlockedInjectFlow(sender, receiver, packet, false)
	receiver.InjectUDPPacket(packet)
	fp.WasReceived()
}

// RouteForUntilAfterToAddr will route for sender and return only after it sees and sends a packet destined for toAddr
// finish can be any of the exitType values except `keepRouting`, the default value is `routeAndExit`
// If the router doesn't have the nebula controller for that address, we panic
func (r *R) RouteForUntilAfterToAddr(sender *nebula.Control, toAddr netip.AddrPort, finish ExitType) {
	if finish == KeepRouting {
		finish = RouteAndExit
	}

	r.RouteExitFunc(sender, func(p *udp.Packet, r *nebula.Control) ExitType {
		if p.To == toAddr {
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

		p := rx.Interface().(*udp.Packet)
		receiver := r.getControl(cm[x].GetUDPAddr(), p.To, p)
		if receiver == nil {
			r.Unlock()
			panic("Can't RouteForAllExitFunc for host: " + p.To.String())
		}

		e := whatDo(p, receiver)
		switch e {
		case ExitNow:
			r.Unlock()
			return

		case RouteAndExit:
			fp := r.unlockedInjectFlow(cm[x], receiver, p, false)
			receiver.InjectUDPPacket(p)
			fp.WasReceived()
			r.Unlock()
			return

		case KeepRouting:
			fp := r.unlockedInjectFlow(cm[x], receiver, p, false)
			receiver.InjectUDPPacket(p)
			fp.WasReceived()

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

		p := rx.Interface().(*udp.Packet)

		receiver := r.getControl(cm[x].GetUDPAddr(), p.To, p)
		if receiver == nil {
			r.Unlock()
			panic("Can't FlushAll for host: " + p.To.String())
		}
		r.Unlock()
	}
}

// getControl performs or seeds NAT translation and returns the control for toAddr, p from fields may change
// This is an internal router function, the caller must hold the lock
func (r *R) getControl(fromAddr, toAddr netip.AddrPort, p *udp.Packet) *nebula.Control {
	if newAddr, ok := r.outNat[fromAddr.String()+":"+toAddr.String()]; ok {
		p.From = newAddr
	}

	c, ok := r.inNat[toAddr]
	if ok {
		r.outNat[c.GetUDPAddr().String()+":"+fromAddr.String()] = toAddr
		return c
	}

	return r.controls[toAddr]
}

func (r *R) formatUdpPacket(p *packet) string {
	var packet gopacket.Packet
	var srcAddr netip.Addr

	packet = gopacket.NewPacket(p.packet.Data, layers.LayerTypeIPv6, gopacket.Lazy)
	if packet.ErrorLayer() == nil {
		v6 := packet.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
		if v6 == nil {
			panic("not an ipv6 packet")
		}
		srcAddr, _ = netip.AddrFromSlice(v6.SrcIP)
	} else {
		packet = gopacket.NewPacket(p.packet.Data, layers.LayerTypeIPv4, gopacket.Lazy)
		v6 := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		if v6 == nil {
			panic("not an ipv6 packet")
		}
		srcAddr, _ = netip.AddrFromSlice(v6.SrcIP)
	}

	from := "unknown"
	if c, ok := r.vpnControls[srcAddr]; ok {
		from = c.GetUDPAddr().String()
	}

	udpLayer := packet.Layer(layers.LayerTypeUDP).(*layers.UDP)
	if udpLayer == nil {
		panic("not a udp packet")
	}

	data := packet.ApplicationLayer()
	return fmt.Sprintf(
		"    %s-->>%s: src port: %v<br/>dest port: %v<br/>data: \"%v\"\n",
		normalizeName(from),
		normalizeName(p.to.GetUDPAddr().String()),
		udpLayer.SrcPort,
		udpLayer.DstPort,
		string(data.Payload()),
	)
}
