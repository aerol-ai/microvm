package worker

import (
	"fmt"
	"net"
	"time"
)

// Client talks to one worker over a Unix domain socket.
type Client struct {
	socketPath string
	dial       func(string) (net.Conn, error)
}

// NewClient dials socketPath for each request.
func NewClient(socketPath string) *Client {
	return &Client{
		socketPath: socketPath,
		dial: func(path string) (net.Conn, error) {
			return net.DialTimeout("unix", path, 2*time.Second)
		},
	}
}

func (c *Client) roundTrip(env Envelope) (Envelope, error) {
	conn, err := c.dial(c.socketPath)
	if err != nil {
		return Envelope{}, err
	}
	defer conn.Close()
	if err := writeFrame(conn, env); err != nil {
		return Envelope{}, err
	}
	reply, err := readFrame(conn)
	if err != nil {
		return Envelope{}, err
	}
	return reply, nil
}

// Ping verifies the worker responds to HealthPing.
func (c *Client) Ping(sandboxID string) error {
	reply, err := c.roundTrip(Envelope{Type: MsgHealthPing, SandboxID: sandboxID})
	if err != nil {
		return err
	}
	if reply.Type != MsgPong {
		return fmt.Errorf("unexpected reply type %q", reply.Type)
	}
	return nil
}

// TriggerPanic sends the test-only panic message. The worker process is expected to exit.
func (c *Client) TriggerPanic(sandboxID string) error {
	_, err := c.roundTrip(Envelope{Type: MsgTriggerPanic, SandboxID: sandboxID})
	return err
}
