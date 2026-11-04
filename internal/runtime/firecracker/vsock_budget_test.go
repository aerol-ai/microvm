package firecracker

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// pipeDialer hands out one end of a net.Pipe, whose deadlines work like the
// production dialer's net.Conn, carrying the dial context's deadline as the
// production dialer does. The guest side acks every op after ackDelay.
type pipeDialer struct {
	ackDelay    time.Duration
	setDeadline error
	dialed      chan time.Time // deadline of each dial context
}

func (p *pipeDialer) Dial(ctx context.Context, _ string, _, _ uint32) (io.ReadWriteCloser, error) {
	host, guest := net.Pipe()
	if dl, ok := ctx.Deadline(); ok {
		_ = host.SetDeadline(dl)
		if p.dialed != nil {
			p.dialed <- dl
		}
	}
	go func() {
		defer guest.Close()
		if _, err := bufio.NewReader(guest).ReadString('\n'); err != nil {
			return
		}
		time.Sleep(p.ackDelay)
		_, _ = guest.Write([]byte(`{"ok":true}` + "\n"))
	}()
	if p.setDeadline != nil {
		return &failingDeadlineConn{Conn: host, err: p.setDeadline}, nil
	}
	return host, nil
}

type failingDeadlineConn struct {
	net.Conn
	err error
}

func (c *failingDeadlineConn) SetDeadline(time.Time) error { return c.err }

// A guest that takes longer than the connect timeout to ack a flush is
// waited for, up to the op's own budget. Before, every op's ack shared the
// connect's 2 s, so a flush of a lot of dirty data always "failed".
func TestVsockOpBudgetOutlastsTheConnectTimeout(t *testing.T) {
	if testing.Short() {
		t.Skip("waits past the 2 s connect timeout")
	}
	d := New(Config{}, nil)
	slow := &pipeDialer{ackDelay: defaultVsockOpTimeout + 300*time.Millisecond}
	d.SetVsockDialer(slow)
	if err := d.sendVsockOpAckWithin(context.Background(), time.Minute, "/sock", 3, "sync_fs", nil); err != nil {
		t.Fatalf("a slow flush within its budget failed: %v", err)
	}
	// The default budget still gives up at the connect timeout.
	if err := d.sendVsockOpAck(context.Background(), "/sock", 3, "ping", nil); err == nil {
		t.Fatal("an ack later than the default budget was accepted")
	}
}

func TestVsockOpBudgetLimits(t *testing.T) {
	t.Run("the connect never waits past the default", func(t *testing.T) {
		d := New(Config{}, nil)
		p := &pipeDialer{dialed: make(chan time.Time, 1)}
		d.SetVsockDialer(p)
		start := time.Now()
		if err := d.sendVsockOpAckWithin(context.Background(), time.Hour, "/sock", 3, "sync_fs", nil); err != nil {
			t.Fatal(err)
		}
		if dl := <-p.dialed; dl.Sub(start) > defaultVsockOpTimeout+time.Second {
			t.Fatalf("connect deadline %s after the start", dl.Sub(start))
		}
	})
	t.Run("the caller's sooner deadline wins", func(t *testing.T) {
		d := New(Config{}, nil)
		d.SetVsockDialer(&pipeDialer{ackDelay: 300 * time.Millisecond})
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		err := d.sendVsockOpAckWithin(ctx, time.Minute, "/sock", 3, "sync_fs", nil)
		if err == nil || !strings.Contains(err.Error(), "read ack") {
			t.Fatalf("err = %v, want the ack read to time out at the caller's deadline", err)
		}
	})
	t.Run("a conn whose deadline cannot move", func(t *testing.T) {
		d := New(Config{}, nil)
		d.SetVsockDialer(&pipeDialer{setDeadline: errors.New("closed")})
		err := d.sendVsockOpAckWithin(context.Background(), time.Minute, "/sock", 3, "sync_fs", nil)
		if err == nil || !strings.Contains(err.Error(), "set op deadline") {
			t.Fatalf("err = %v", err)
		}
	})
}
