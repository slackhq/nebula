package port_forwarder

import (
	"context"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/service"
	"golang.org/x/sync/errgroup"
)

type ForwardConfigOutgoingTcp struct {
	ForwardConfigOutgoing
}

func (cfg ForwardConfigOutgoingTcp) ConfigDescriptor() string {
	return fmt.Sprintf("outbound.tcp.%s.%s", cfg.localListen, cfg.remoteConnect)
}

type ForwardConfigIncomingTcp struct {
	ForwardConfigIncoming
}

func (cfg ForwardConfigIncomingTcp) ConfigDescriptor() string {
	return fmt.Sprintf("inbound.tcp.%d.%s", cfg.port, cfg.forwardLocalAddress)
}

type PortForwardingOutgoingTcp struct {
	l                     *logrus.Logger
	tunService            *service.Service
	cfg                   ForwardConfigOutgoingTcp
	localListenConnection *net.TCPListener
}

func (fwd PortForwardingOutgoingTcp) Close() error {
	fwd.localListenConnection.Close()
	return nil
}

func (cf ForwardConfigOutgoingTcp) SetupPortForwarding(
	tunService *service.Service,
	l *logrus.Logger,
) (io.Closer, error) {
	localTcpListenAddr, err := net.ResolveTCPAddr("tcp", cf.localListen)
	if err != nil {
		return nil, err
	}
	localListenPort, err := net.ListenTCP("tcp", localTcpListenAddr)
	if err != nil {
		return nil, err
	}

	l.Infof("TCP port forwarding to '%v': listening on local TCP addr: '%v'",
		cf.remoteConnect, localTcpListenAddr)

	portForwarding := &PortForwardingOutgoingTcp{
		l:                     l,
		tunService:            tunService,
		cfg:                   cf,
		localListenConnection: localListenPort,
	}

	go portForwarding.acceptOnLocalListenPort()

	return portForwarding, nil
}

func (pt *PortForwardingOutgoingTcp) acceptOnLocalListenPort() error {
	for {
		pt.l.Debug("listening on local TCP port ...")
		connection, err := pt.localListenConnection.AcceptTCP()
		if err != nil {
			fmt.Println(err)
			return err
		}

		pt.l.Debugf("accept TCP connect from local TCP port: %v", connection.RemoteAddr())

		go pt.handleClientConnection(connection)
	}
}

func (pt *PortForwardingOutgoingTcp) handleClientConnection(localConnection *net.TCPConn) {
	err := pt.handleClientConnectionWithErrorReturn(localConnection)
	if err != nil {
		pt.l.Debugf("Closed TCP client connection %s. Err: %v",
			localConnection.LocalAddr().String(), err)
	}
}

func (pt *PortForwardingOutgoingTcp) handleClientConnectionWithErrorReturn(localConnection net.Conn) error {

	remoteConnection, err := pt.tunService.DialContext(context.Background(), "tcp", pt.cfg.remoteConnect)
	if err != nil {
		return err
	}
	return handleTcpClientConnection_generic(pt.l, localConnection, remoteConnection)
}

func handleTcpClientConnection_generic(l *logrus.Logger, connA, connB net.Conn) error {

	dataTransferHandler := func(from, to net.Conn) error {

		name := fmt.Sprintf("%s -> %s", from.LocalAddr().String(), to.LocalAddr().String())

		defer from.Close()
		defer to.Close()
		// defer calls are executed in inverse order.
		// this delays the deferred from/to.Close to give communication
		// in opposite direction time to finish as well.
		defer time.Sleep(time.Millisecond * 100)

		// no write/read timeout
		to.SetDeadline(time.Time{})
		from.SetDeadline(time.Time{})
		megabyte := (1 << 20)
		buf := make([]byte, 1*megabyte)
		if false {
			// this variant seems to be slightly slower on the local speed-test. 1.60GiB/s vs. 1.70GiB/s
			n, err := io.CopyBuffer(to, from, buf)
			l.WithError(err).
				WithField("payloadSize", n).
				WithField("from", from.RemoteAddr()).
				WithField("to", to.RemoteAddr()).
				WithField("localFrom", from.LocalAddr()).
				WithField("localTo", to.LocalAddr()).
				Debug("stopped data forwarding")
			return err
		} else {
			for {
				rn, r_err := from.Read(buf)
				l.Tracef("%s read(%d), err: %v", name, rn, r_err)
				for i := 0; i < rn; {
					wn, w_err := to.Write(buf[i:rn])
					if w_err != nil {
						l.Debugf("%s writing(%d) to to-connection failed: %v", name, rn, w_err)
						return w_err
					}
					i += wn
				}
				if r_err != nil {
					l.Debugf("%s reading(%d) from from-connection failed: %v", name, rn, r_err)
					return r_err
				}
			}
		}
	}

	errGroup := errgroup.Group{}

	errGroup.Go(func() error { return dataTransferHandler(connA, connB) })
	errGroup.Go(func() error { return dataTransferHandler(connB, connA) })

	return errGroup.Wait()
}

type PortForwardingIncomingTcp struct {
	l                       *logrus.Logger
	tunService              *service.Service
	cfg                     ForwardConfigIncomingTcp
	outsideListenConnection net.Listener
}

func (fwd PortForwardingIncomingTcp) Close() error {
	fwd.outsideListenConnection.Close()
	return nil
}

func (cf ForwardConfigIncomingTcp) SetupPortForwarding(
	tunService *service.Service,
	l *logrus.Logger,
) (io.Closer, error) {

	listener, err := tunService.Listen("tcp", fmt.Sprintf(":%d", cf.port))
	if err != nil {
		return nil, err
	}

	l.Infof("TCP port forwarding to '%v': listening on local, outside TCP addr: ':%d'",
		cf.forwardLocalAddress, cf.port)

	portForwarding := &PortForwardingIncomingTcp{
		l:                       l,
		tunService:              tunService,
		cfg:                     cf,
		outsideListenConnection: listener,
	}

	go portForwarding.acceptOnOutsideListenPort()

	return portForwarding, nil
}

func (pt *PortForwardingIncomingTcp) acceptOnOutsideListenPort() error {
	for {
		pt.l.Debug("listening on outside TCP port ...")
		connection, err := pt.outsideListenConnection.Accept()
		if err != nil {
			fmt.Println(err)
			return err
		}

		pt.l.Debugf("accept TCP connect from outside TCP port: %v", connection.RemoteAddr())

		go pt.handleClientConnection(connection)
	}
}

func (pt *PortForwardingIncomingTcp) handleClientConnection(localConnection net.Conn) {
	err := pt.handleClientConnectionWithErrorReturn(localConnection)
	if err != nil {
		pt.l.Debugf("Closed TCP client connection %s. Err: %v",
			localConnection.LocalAddr().String(), err)
	}
}

func (pt *PortForwardingIncomingTcp) handleClientConnectionWithErrorReturn(outsideConnection net.Conn) error {

	fwdAddr, err := net.ResolveTCPAddr("tcp", pt.cfg.forwardLocalAddress)
	if err != nil {
		return err
	}

	localConnection, err := net.DialTCP("tcp", nil, fwdAddr)
	if err != nil {
		return err
	}

	return handleTcpClientConnection_generic(pt.l, outsideConnection, localConnection)
}
