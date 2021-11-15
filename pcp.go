package nebula

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/jackpal/gateway"
	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/udp"
	"math/rand"
	"net"
	"strings"
	"sync"
	"time"
)

const pcpDefaultPort uint16 = 5351
const pcpDefaultLifetime uint32 = 120

type pcp struct {
	sync.RWMutex

	local *udp.Addr
	gw    *udp.Addr

	c                     *net.UDPConn
	reqCloseCh            chan bool
	latestMappingResponse time.Time
	mappingActiveUntil    time.Time
	nonce                 []byte
	retryAfter            time.Time
	retryBackoff          uint16
	lifetime              uint32
	isClosing             bool
	lh                    *LightHouse
	l                     *logrus.Logger
}

type pcpBaseResponse struct {
	OpCode     uint8
	ResultCode uint8
	Lifetime   uint32
	Epoch      uint32
}

type pcpMapResponse struct {
	pcpBaseResponse
	protocol     uint8
	internalPort uint16
	externalPort uint16
	externalIP   net.IP
}

// TODO Support port-mapping for both ipv4 and ipv6 at same time

func NewPCP(config *config.C, lh *LightHouse, l *logrus.Logger) (*pcp, error) {

	if config.IsSet("punchy.port_mappings.pcp.gateway") || config.IsSet("punchy.port_mappings.pcp.local") {
		if !config.IsSet("punchy.port_mappings.pcp.gateway") || !config.IsSet("punchy.port_mappings.pcp.local") {
			return nil, fmt.Errorf("both `punchy.port_mappings.pcp.gateway` and `punchy.port_mappings.pcp.local` is required")
		}
	}

	var gwIp net.IP

	if config.IsSet("punchy.port_mappings.pcp.gateway") {
		gwString := config.GetString("punchy.port_mappings.pcp.gateway", "")
		ip := net.ParseIP(gwString)
		if ip == nil {
			return nil, fmt.Errorf("failed to parse gateway ip: %s", gwString)
		}
		gwIp = ip
	} else {
		gi, err := gateway.DiscoverGateway()
		if err != nil {
			return nil, fmt.Errorf("unable to discover gateway")
		}
		gwIp = gi
	}
	gw := &udp.Addr{
		IP:   gwIp,
		Port: pcpDefaultPort,
	}

	var localIp net.IP
	if config.IsSet("punchy.port_mappings.pcp.local") {
		localString := config.GetString("punchy.port_mappings.pcp.local", "")
		ip := net.ParseIP(localString)
		if ip == nil {
			return nil, fmt.Errorf("failed to parse local ip: %s", localString)
		}
		localIp = ip
	} else {
		li, err := gateway.DiscoverInterface()
		if err != nil {
			return nil, fmt.Errorf("unable to discover ip used for gateway(%s)", gwIp.String())
		}
		localIp = li
	}

	local := &udp.Addr{
		IP:   localIp,
		Port: uint16(lh.nebulaPort),
	}

	nonce := make([]byte, 12)
	rand.Read(nonce)

	return &pcp{
		local:              local,
		gw:                 gw,
		mappingActiveUntil: time.UnixMilli(0),
		retryBackoff:       1,
		nonce:              nonce,
		lh:                 lh,
		l:                  l,
	}, nil
}

func (p *pcp) Start() error {
	if p.local == nil {
		return fmt.Errorf("missing local")
	}
	p.Lock()
	defer p.Unlock()
	if p.c != nil {
		return fmt.Errorf("pcp is already started")
	}
	p.isClosing = false
	s, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("%s:%d", p.gw.IP, p.gw.Port))
	if err != nil {
		return err
	}
	c, err := net.DialUDP("udp4", nil, s)
	if err != nil {
		return fmt.Errorf("failed to dial gw: %s", err)
	}
	p.c = c

	p.l.Debugf("PCP server: %s", c.RemoteAddr())

	go p.startReadResponses(c)
	p.reqCloseCh = p.startRequester()

	p.sendMappingRequest()

	return nil
}

func (p *pcp) Stop() {
	p.Lock()
	defer p.Unlock()
	p.l.Debug("Stopping pcp")

	if p.reqCloseCh != nil {
		p.reqCloseCh <- true
		p.reqCloseCh = nil
	}

	if p.c != nil {
		p.l.Debugf("PCP Sending map request to %s to remove mapping", p.gw)
		p.isClosing = true
		pkt := p.pcpMapRequestPkt(p.local, &udp.Addr{IP: nil, Port: 0}, 0)
		_, err := p.c.Write(pkt)
		if err != nil {
			p.l.WithError(err).Printf("error sending pcp remove mapping request")
		}

		err = p.c.Close()
		if err != nil {
			p.l.Error("error when closing pcp udp connection", err)
		}
		p.c = nil
	}
}

func (p *pcp) startRequester() chan bool {
	ticker := time.NewTicker(2 * time.Second)
	quit := make(chan bool)
	go func() {
		for {
			select {
			case <-ticker.C:
				p.sendMappingRequest()
			case <-quit:
				ticker.Stop()
				return
			}
		}
	}()
	return quit
}

func (p *pcp) sendMappingRequest() {
	if time.Now().Before(p.mappingActiveUntil.Add(-time.Duration(p.lifetime/2) * time.Second)) {
		return
	}

	if time.Now().Before(p.retryAfter) {
		p.l.Tracef("skip sending request waiting for retry time: %s", p.retryAfter.Format("15:04:05"))
		return
	}
	if p.latestMappingResponse.IsZero() {
		p.l.Debugf("PCP No responses received yet\n")
		p.incrementRetry()
	}

	pkt := p.pcpMapRequestPkt(p.local, &udp.Addr{IP: nil, Port: 0}, pcpDefaultLifetime)
	p.l.Debugf("PCP Sending map request to %s", p.gw)
	_, err := p.c.Write(pkt)
	if err != nil {
		p.l.WithError(err).Printf("error sending pcp mapping request")
	}
}

func (p *pcp) pcpMapRequestPkt(local, external *udp.Addr, lifetime uint32) []byte {
	pkt := make([]byte, 24+36)

	pkt[0] = 2                                     // PCP Version
	pkt[1] = 1                                     // Request MAP OPCODE
	binary.BigEndian.PutUint32(pkt[4:8], lifetime) // lifetimeSec

	// Client IP as
	copy(pkt[8:24], local.IP.To16())

	mapOp := pkt[24:]

	copy(mapOp[:12], p.nonce) // MAP Nonce

	mapOp[12] = 17

	// 24 bits / 3 bytes reserved

	binary.BigEndian.PutUint16(mapOp[16:18], local.Port)    // local port
	binary.BigEndian.PutUint16(mapOp[18:20], external.Port) // local port
	copy(mapOp[20:], external.IP.To16())

	return pkt
}

func (p *pcp) parsePCPResponse(b []byte) (*pcpBaseResponse, error) {
	if len(b) < 24 {
		return nil, fmt.Errorf("not enough bytes")
	}
	if b[0] != 2 {
		return nil, fmt.Errorf("pcp version is not supported: %d only supported is (2)", b[0])
	}
	if b[1]&0b10000000 == 0 {
		return nil, fmt.Errorf("PCP received request expecting response")
	}
	res := &pcpBaseResponse{
		OpCode:     b[1] & 0b01111111,
		ResultCode: b[3],
		Lifetime:   binary.BigEndian.Uint32(b[4:]),
		Epoch:      binary.BigEndian.Uint32(b[8:]),
	}
	return res, nil
}

func (p *pcp) parsePCPMapResponse(base *pcpBaseResponse, mapOp []byte) (*pcpMapResponse, error) {
	if len(mapOp) < 36 {
		return nil, fmt.Errorf("does not appear to be PCP MAP response")
	}

	if !bytes.Equal(p.nonce, mapOp[:12]) {
		return nil, fmt.Errorf("nonce not matching")
	}

	protocol := mapOp[12]
	// skip reserved 24bits / 3bytes
	internalPort := binary.BigEndian.Uint16(mapOp[16:18])
	externalPort := binary.BigEndian.Uint16(mapOp[18:20])
	externalIP := net.IP(mapOp[20:36])

	res := &pcpMapResponse{
		pcpBaseResponse: *base,
		protocol:        protocol,
		internalPort:    internalPort,
		externalPort:    externalPort,
		externalIP:      externalIP,
	}
	return res, nil
}

func (p *pcp) handleMapResponse(res *pcpMapResponse) error {

	p.l.Debugf("PCP parsed mapping response: %v\n", res)

	if ip := res.externalIP.To4(); ip != nil {
		p.lh.AddIP4PortMapping("pcp", NewIp4AndPort(ip, uint32(res.externalPort)))
	} else {
		p.lh.AddIP6PortMapping("pcp", NewIp6AndPort(ip, uint32(res.externalPort)))
	}

	p.latestMappingResponse = time.Now()
	p.lifetime = res.Lifetime
	p.mappingActiveUntil = time.Now().Add(time.Duration(res.Lifetime) * time.Second)

	return nil
}

func (p *pcp) startReadResponses(c *net.UDPConn) {
	for true {
		buffer := make([]byte, 1500)
		n, _, err := c.ReadFromUDP(buffer)
		if err != nil {
			p.incrementRetry()
			if p.isClosing && strings.Contains(err.Error(), "use of closed network connection") {
				return
			}
			p.l.WithError(err).Warn("failed when trying to read udp packet")
			continue
		}

		err = p.handleResponse(buffer[0:n])
		if err != nil {
			p.incrementRetry()
			p.l.WithError(err).Error("failed to handle pcp response")
			continue
		}
		p.decrementRetry()
	}
}

func (p *pcp) handleResponse(b []byte) error {
	p.l.Debugf("PCP received response")
	p.latestMappingResponse = time.Now()
	base, err := p.parsePCPResponse(b[:24])
	if err != nil {
		return fmt.Errorf("failed to parse pcp response: %s", err)
	}
	if base.ResultCode != 0 {
		return fmt.Errorf("requested port mapping failed with code %d", base.ResultCode)
	}

	opData := b[24:]

	if base.OpCode == 1 {
		mapResponse, err := p.parsePCPMapResponse(base, opData)
		if err != nil {
			return err
		}
		err = p.handleMapResponse(mapResponse)
	} else {
		err = fmt.Errorf("unsupported pcp opcode: %d", base.OpCode)
	}

	if err != nil {
		return err
	}

	return nil
}

func (p *pcp) incrementRetry() {
	p.retryAfter = time.Now().Add(time.Duration(p.retryBackoff) * time.Second)
	p.retryBackoff = p.retryBackoff * 2
	if p.retryBackoff > 300 {
		p.retryBackoff = 300
	}
}

func (p *pcp) decrementRetry() {
	if p.retryBackoff > 1 {
		p.retryBackoff = p.retryBackoff / 2
	}
}
