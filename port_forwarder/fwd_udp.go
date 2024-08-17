package port_forwarder

import (
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/service"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
)

type ForwardConfigOutgoingUdp struct {
	ForwardConfigOutgoing
}

func (cfg ForwardConfigOutgoingUdp) ConfigDescriptor() string {
	return fmt.Sprintf("outbound.udp.%s.%s", cfg.localListen, cfg.remoteConnect)
}

type ForwardConfigIncomingUdp struct {
	ForwardConfigIncoming
}

func (cfg ForwardConfigIncomingUdp) ConfigDescriptor() string {
	return fmt.Sprintf("inbound.udp.%d.%s", cfg.port, cfg.forwardLocalAddress)
}

// use UDP timeout of 300 seconds according to
// https://support.goto.com/connect/help/what-are-the-recommended-nat-keep-alive-settings
var UDP_CONNECTION_TIMEOUT_SECONDS uint32 = 300

type udpConnInterface interface {
	io.Closer
	WriteTo(b []byte, addr net.Addr) (int, error)
	Write(b []byte) (int, error)
	ReadFrom(b []byte) (int, net.Addr, error)
	LocalAddr() net.Addr
}

func resetTimer(t *time.Timer, d time.Duration) {
	if !t.Stop() {
		select {
		case <-t.C:
		default:
		}
	}
	t.Reset(d)
}

func handleUdpDestinationPortResponseReading[destConn udpConnInterface, srcConn udpConnInterface](
	l *logrus.Logger,
	loggingFields logrus.Fields,
	closedConnections *chan string,
	sourceAddr net.Addr,
	destConnection destConn,
	localListenConnection srcConn,
) error {
	// net.Conn is thread-safe according to: https://pkg.go.dev/net#Conn
	// no need for remoteConnection to protect by mutex

	defer func() { (*closedConnections) <- sourceAddr.String() }()

	l.WithFields(loggingFields).Debug("begin reading responses ...")
	wg := &sync.WaitGroup{}
	defer wg.Wait()

	timeout := time.Second * time.Duration(UDP_CONNECTION_TIMEOUT_SECONDS)
	timer := time.NewTimer(timeout)

	rr := newUdpPortReader(wg, l, loggingFields, destConnection)
	defer close(rr.receivedDataDone)
	for {
		select {
		case <-timer.C:
			destConnection.Close()
			l.WithFields(loggingFields).Debug("response read - closed due to timeout")
			return nil
		case data, ok := <-rr.receivedData:
			if !ok {
				return nil
			}
			resetTimer(timer, timeout)

			l.WithFields(loggingFields).
				WithField("payloadSize", data.n).
				Debug("response forward")
			n, err := localListenConnection.WriteTo(rr.buf[:data.n], sourceAddr)
			rr.receivedDataDone <- 1
			if (n == 0) && (err != nil) {
				l.WithFields(loggingFields).WithError(err).Debugf("response forward - write error")
				return err
			}
		}
	}
}

type PortForwardingCommonUdp struct {
	wg         *sync.WaitGroup
	l          *logrus.Logger
	tunService *service.Service
	// net.Conn is thread-safe according to: https://pkg.go.dev/net#Conn
	// no need for localListenConnection to protect by mutex
	localListenConnection io.Closer
}

func (fwd PortForwardingCommonUdp) Close() error {
	fwd.localListenConnection.Close()
	fwd.wg.Wait()
	return nil
}

type PortForwardingOutgoingUdp struct {
	PortForwardingCommonUdp
	cfg ForwardConfigOutgoingUdp
}

func (cfg ForwardConfigOutgoingUdp) SetupPortForwarding(
	tunService *service.Service,
	l *logrus.Logger,
) (io.Closer, error) {
	localUdpListenAddr, err := net.ResolveUDPAddr("udp", cfg.localListen)
	if err != nil {
		return nil, err
	}

	localListenConnection, err := net.ListenUDP("udp", localUdpListenAddr)
	if err != nil {
		return nil, err
	}

	l.Infof("UDP port forwarding to '%v': listening on local UDP addr: '%v'",
		cfg.remoteConnect, localUdpListenAddr)

	wg := &sync.WaitGroup{}

	portForwarding := &PortForwardingOutgoingUdp{
		PortForwardingCommonUdp: PortForwardingCommonUdp{
			wg:                    wg,
			l:                     l,
			tunService:            tunService,
			localListenConnection: localListenConnection,
		},
		cfg: cfg,
	}

	logPrefix := logrus.Fields{
		"a":      "UDP fwd out",
		"listen": localListenConnection.LocalAddr(),
		"dial":   cfg.remoteConnect,
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		err := listenLocalPort_generic(
			wg,
			l,
			logPrefix,
			localListenConnection,
			func(address string) (*gonet.UDPConn, error) {
				return tunService.DialUDP(address)
			},
			cfg.remoteConnect,
		)
		if err != nil {
			l.WithFields(logPrefix).WithError(err).
				Error("listening stopped with error")
		}
	}()

	return portForwarding, nil
}

type readData struct {
	n    int
	addr net.Addr
}

type readerRoutine struct {
	buf              []byte
	receivedData     chan readData
	receivedDataDone chan int
}

func newUdpPortReader(
	wg *sync.WaitGroup,
	l *logrus.Logger,
	loggingFields logrus.Fields,
	conn udpConnInterface,
) *readerRoutine {
	r := &readerRoutine{
		buf:              make([]byte, 512*1024),
		receivedData:     make(chan readData),
		receivedDataDone: make(chan int, 1),
	}
	r.receivedDataDone <- 1

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(r.receivedData)
		l.WithFields(loggingFields).
			WithField("addr", conn.LocalAddr()).
			Debug("start listening")
		for {
			_, ok := <-r.receivedDataDone
			if !ok {
				return
			}
			l.WithFields(loggingFields).
				WithField("addr", conn.LocalAddr()).
				Trace("reading data ...")
			n, addr, err := conn.ReadFrom(r.buf[0:])
			if err != nil {
				if errors.Is(err, io.EOF) {
					return
				}
				l.WithFields(loggingFields).
					WithField("addr", conn.LocalAddr()).
					WithError(err).Error("listen for data failed. stop.")
				return
			}
			r.receivedData <- readData{
				n:    n,
				addr: addr,
			}
		}
	}()

	return r
}

func listenLocalPort_generic[destConn udpConnInterface](
	wg *sync.WaitGroup,
	l *logrus.Logger,
	loggingFields logrus.Fields,
	localListenConnection udpConnInterface,
	dial func(address string) (destConn, error),
	remoteConnect string,
) error {
	dialConnResponseReaders := make(map[string]bool)
	dialConnections := make(map[string]destConn)
	closedConnections := make(chan string, 5)
	mr := newUdpPortReader(wg, l, loggingFields, localListenConnection)
	defer close(mr.receivedDataDone)

	defer func() {
		// close and wait for remaining connections
		for _, connection := range dialConnections {
			connection.Close()
		}
		for range dialConnResponseReaders {
			<-closedConnections
		}
	}()

	for {
		select {
		case closedOne := <-closedConnections:
			l.Debugf("closing connection to %s", closedOne)
			delete(dialConnections, closedOne)
			delete(dialConnResponseReaders, closedOne)
		case data, ok := <-mr.receivedData:
			if !ok {
				return nil
			}
			l.WithFields(loggingFields).
				WithField("source", data.addr).
				WithField("payloadSize", data.n).
				Trace("read data")
			dialConnection, ok := dialConnections[data.addr.String()]
			if !ok {
				newConnection, err := dial(remoteConnect)
				if err != nil {
					l.WithFields(loggingFields).WithError(err).Error("dialing dial address failed")
					continue
				}
				dialConnections[data.addr.String()] = newConnection
				dialConnection = newConnection
			}

			l.WithFields(loggingFields).
				WithField("source", data.addr).
				WithField("dialSource", dialConnection.LocalAddr()).
				WithField("payloadSize", data.n).
				Debug("forward")

			dialConnection.Write(mr.buf[:data.n])
			mr.receivedDataDone <- 1

			_, ok = dialConnResponseReaders[data.addr.String()]
			if !ok {
				loggingFieldsRsp := logrus.Fields{
					"source":     data.addr,
					"dialSource": dialConnection.LocalAddr(),
				}
				for k, v := range loggingFields {
					loggingFieldsRsp[k] = v
				}
				dialConnResponseReaders[data.addr.String()] = true
				go func() error {
					return handleUdpDestinationPortResponseReading(
						l, loggingFieldsRsp, &closedConnections, data.addr,
						dialConnection, localListenConnection)
				}()
			}
		}
	}
}

type PortForwardingIncomingUdp struct {
	PortForwardingCommonUdp
	cfg ForwardConfigIncomingUdp
}

func (cfg ForwardConfigIncomingUdp) SetupPortForwarding(
	tunService *service.Service,
	l *logrus.Logger,
) (io.Closer, error) {

	conn, err := tunService.ListenUDP(fmt.Sprintf(":%d", cfg.port))
	if err != nil {
		return nil, err
	}

	l.Infof("UDP port forwarding to '%v': listening on outside UDP addr: ':%d'",
		cfg.forwardLocalAddress, cfg.port)

	logPrefix := logrus.Fields{
		"a":          "UDP fwd in",
		"listenPort": cfg.port,
		"dial":       cfg.forwardLocalAddress,
	}

	wg := &sync.WaitGroup{}

	forwarding := &PortForwardingIncomingUdp{
		PortForwardingCommonUdp: PortForwardingCommonUdp{
			wg:                    wg,
			l:                     l,
			tunService:            tunService,
			localListenConnection: conn,
		},
		cfg: cfg,
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		err := listenLocalPort_generic(
			wg,
			l,
			logPrefix,
			conn,
			func(address string) (*net.UDPConn, error) {
				fwdAddr, err := net.ResolveUDPAddr("udp", cfg.forwardLocalAddress)
				if err != nil {
					l.WithFields(logPrefix).Error("resolve of dial address failed")
					return nil, err
				}
				return net.DialUDP("udp", nil, fwdAddr)
			},
			cfg.forwardLocalAddress,
		)
		if err != nil {
			l.WithFields(logPrefix).WithError(err).
				Error("listening stopped with error")
		}
	}()

	return forwarding, nil
}
