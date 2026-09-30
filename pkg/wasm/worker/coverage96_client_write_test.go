package worker

import (
	"context"
	"errors"
	"net"
	"testing"
)

type cov96FailingWriteConn struct {
	net.Conn
	onWrite func()
}

func (c *cov96FailingWriteConn) Write([]byte) (int, error) {
	if c.onWrite != nil {
		c.onWrite()
	}
	return 0, errCov96Write
}

func TestCov96ClientRoundTripContextWriteFailure(t *testing.T) {
	dialWith := func(onWrite func()) func(string) (net.Conn, error) {
		return func(string) (net.Conn, error) {
			client, server := net.Pipe()
			t.Cleanup(func() { _ = server.Close() })
			return &cov96FailingWriteConn{Conn: client, onWrite: onWrite}, nil
		}
	}

	t.Run("write error surfaces", func(t *testing.T) {
		c := NewClient("unused")
		c.dial = dialWith(nil)
		if _, err := c.InstanceLoaded(context.Background(), "sb"); !errors.Is(err, errCov96Write) {
			t.Fatalf("InstanceLoaded = %v, want write error", err)
		}
	})
	t.Run("cancellation during write wins", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		c := NewClient("unused")
		c.dial = dialWith(cancel)
		if _, err := c.InstanceLoaded(ctx, "sb"); !errors.Is(err, context.Canceled) {
			t.Fatalf("InstanceLoaded = %v, want context.Canceled", err)
		}
	})
}
