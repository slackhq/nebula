package overlay

import (
	"bytes"
	"fmt"
	"io"
	"net/netip"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/config"
)

type BufferedPipe struct {
	close chan struct{}
	buf   chan []byte
}

type BufferedPipeReader struct{ BufferedPipe }
type BufferedPipeWriter struct{ BufferedPipe }

func (p BufferedPipeReader) Read(data []byte) (int, error) {
	select {
	case d := <-p.buf:
		{
			copy(data, d)
			return len(d), nil
		}
	case <-p.close:
		{
			return 0, fmt.Errorf("pipe closed")
		}
	}
}

func (p BufferedPipeReader) Close() error {
	p.close <- struct{}{}
	return nil
}

func (p BufferedPipeWriter) Write(data []byte) (int, error) {
	c := bytes.Clone(data)
	select {
	case <-p.close:
		{
			return 0, fmt.Errorf("pipe closed")
		}
	case p.buf <- c:
		{
		}
	}
	return len(data), nil
}

func (p BufferedPipeWriter) Close() error {
	p.close <- struct{}{}
	return nil
}

func NewBufferedPipe(depth int) (BufferedPipeReader, BufferedPipeWriter) {
	pipe := BufferedPipe{
		make(chan struct{}),
		make(chan []byte, depth),
	}
	return BufferedPipeReader{pipe}, BufferedPipeWriter{pipe}
}

func NewUserDeviceFromConfig(c *config.C, l *logrus.Logger, tunCidr netip.Prefix, routines int) (Device, error) {
	return NewUserDevice(tunCidr)
}

func NewUserDevice(tunCidr netip.Prefix) (Device, error) {
	// these pipes guarantee each write/read will match 1:1
	or, ow := NewBufferedPipe(40)
	ir, iw := NewBufferedPipe(40)
	return &UserDevice{
		tunCidr:        tunCidr,
		outboundReader: or,
		outboundWriter: ow,
		inboundReader:  ir,
		inboundWriter:  iw,
	}, nil
}

type UserDevice struct {
	tunCidr netip.Prefix

	outboundReader BufferedPipeReader
	outboundWriter BufferedPipeWriter

	inboundReader BufferedPipeReader
	inboundWriter BufferedPipeWriter
}

func (d *UserDevice) Activate() error {
	return nil
}
func (d *UserDevice) Cidr() netip.Prefix                { return d.tunCidr }
func (d *UserDevice) Name() string                      { return "faketun0" }
func (d *UserDevice) RouteFor(ip netip.Addr) netip.Addr { return ip }
func (d *UserDevice) NewMultiQueueReader() (io.ReadWriteCloser, error) {
	return d, nil
}

func (d *UserDevice) Pipe() (BufferedPipeReader, BufferedPipeWriter) {
	return d.inboundReader, d.outboundWriter
}

func (d *UserDevice) Read(p []byte) (n int, err error) {
	return d.outboundReader.Read(p)
}
func (d *UserDevice) Write(p []byte) (n int, err error) {
	return d.inboundWriter.Write(p)
}
func (d *UserDevice) Close() error {
	d.inboundWriter.Close()
	d.outboundWriter.Close()
	return nil
}
