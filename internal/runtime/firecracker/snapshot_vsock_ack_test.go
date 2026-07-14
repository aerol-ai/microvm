package firecracker

import (
	"context"
	"errors"
	"io"
	"testing"
)

// ackThenHoldConn mimics the real in-guest vsock server (cmd/toolboxd
// handleVsockConn): it returns the single newline-delimited JSON ack on the
// first read, then HOLDS the connection open to serve further ops — it never
// sends EOF. It counts reads so a test can prove sendVsockOp stops at the ack's
// newline rather than reading toward a fixed byte budget.
type ackThenHoldConn struct {
	ack   []byte
	pos   int
	reads int
	wrote [][]byte
}

func (c *ackThenHoldConn) Read(p []byte) (int, error) {
	c.reads++
	if c.pos < len(c.ack) {
		n := copy(p, c.ack[c.pos:])
		c.pos += n
		return n, nil
	}
	// No EOF: the real guest keeps the connection open. Any read past the ack
	// is the pre-fix over-read; against the real guest it blocked here until
	// the connection's read deadline (~2s). Return an error so a regression
	// fails fast instead of hanging the suite.
	return 0, errors.New("guest sent only the ack line and is holding the connection open")
}

func (c *ackThenHoldConn) Write(p []byte) (int, error) {
	b := make([]byte, len(p))
	copy(b, p)
	c.wrote = append(c.wrote, b)
	return len(p), nil
}

func (c *ackThenHoldConn) Close() error { return nil }

type ackHoldDialer struct{ conn *ackThenHoldConn }

func (d ackHoldDialer) Dial(_ context.Context, _ string, _, _ uint32) (io.ReadWriteCloser, error) {
	return d.conn, nil
}

// TestSendVsockOp_StopsAtAckNewline is the regression guard for the firecracker
// post_resume create-latency fix. sendVsockOp must return as soon as it has
// read the guest's single-line ack and NOT keep reading toward a fixed byte
// budget: the guest holds the connection open (no EOF), so over-reading blocked
// for the full PostResumeTimeout (~2s) on every create — the fc_post_resume
// stage that measured 2000ms and was ~98% of firecracker create p50
// (2030ms server p50, single-node-fc). See snapshot.go sendVsockOp.
func TestSendVsockOp_StopsAtAckNewline(t *testing.T) {
	conn := &ackThenHoldConn{ack: []byte(`{"ok":true}` + "\n")}
	d := &Driver{vsockDial: ackHoldDialer{conn: conn}}

	err := d.sendVsockOp(context.Background(), "/run/vsock.sock", 3, "post_resume",
		map[string]any{"wallclock_unix_ns": int64(1)})
	if err != nil {
		t.Fatalf("sendVsockOp returned error: %v", err)
	}
	// Exactly one read: consume the ack line, stop at its newline. A second read
	// is the pre-fix io.CopyN(_, 256) over-read — against the real (open,
	// EOF-less) guest that read blocked for the full ~2s deadline on every
	// post_resume.
	if conn.reads != 1 {
		t.Fatalf("read the guest connection %d times, want exactly 1 (stop at the ack newline; do not read toward a byte budget)", conn.reads)
	}
	if len(conn.wrote) != 1 {
		t.Fatalf("wrote %d messages, want exactly 1 (the op line)", len(conn.wrote))
	}
}
