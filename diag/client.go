package diag

import (
	"bufio"
	"io"
	"net"
	"time"
)

// dialTimeout bounds the connect only. A command may take as long as it likes to answer.
const dialTimeout = 2 * time.Second

// Client is a connection to a nebula serving the ctl socket. It carries exactly one command.
type Client struct {
	conn net.Conn
}

// Dial connects to the nebula serving at path. On a platform without socket support the
// returned error wraps ErrNotSupported.
func Dial(path string) (*Client, error) {
	conn, err := dialSocket(path, dialTimeout)
	if err != nil {
		return nil, err
	}

	return &Client{conn: conn}, nil
}

// Run sends args and streams the command's output to out, returning the command's exit
// status. A non-nil error means the exchange itself failed and the status means nothing.
func (c *Client) Run(args []string, out io.Writer) (int, error) {
	if err := writeRequest(c.conn, args); err != nil {
		return 0, err
	}

	return readResponse(bufio.NewReader(c.conn), out)
}

func (c *Client) Close() error {
	return c.conn.Close()
}
