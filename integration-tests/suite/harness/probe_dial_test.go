package harness

import (
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
)

func TestDialRetryingLostSYN(t *testing.T) {
	timeout := &net.OpError{Op: "dial", Net: "tcp", Err: os.ErrDeadlineExceeded}
	refused := &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}
	reset := &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", syscall.ECONNRESET)}
	ok := &net.TCPConn{}

	for _, tc := range []struct {
		name        string
		results     []error // one per dial, in order; nil = success
		counter     bool
		cancelled   bool
		wantDials   int
		wantRetried int64
		wantErr     error
	}{
		{name: "success: one dial", results: []error{nil}, counter: true, wantDials: 1},
		{name: "timeout then success: retried once", results: []error{timeout, nil}, counter: true, wantDials: 2, wantRetried: 1},
		{name: "timeout twice: the second error comes back", results: []error{timeout, timeout}, counter: true, wantDials: 2, wantRetried: 1, wantErr: timeout},
		// A closed listener (a Caddy restart) answers at once: never retried.
		{name: "refused: not retried", results: []error{refused}, counter: true, wantDials: 1, wantErr: refused},
		{name: "reset: not retried", results: []error{reset}, counter: true, wantDials: 1, wantErr: reset},
		{name: "no counter: retry off", results: []error{timeout}, wantDials: 1, wantErr: timeout},
		// The caller gave up: its deadline, not the path, ended the dial.
		{name: "cancelled context: not retried", results: []error{timeout}, counter: true, cancelled: true, wantDials: 1, wantErr: timeout},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tc.cancelled {
				cancel()
			}
			dials := 0
			dial := func(context.Context) (net.Conn, error) {
				err := tc.results[dials]
				dials++
				if err != nil {
					return nil, err
				}
				return ok, nil
			}
			var retried *atomic.Int64
			if tc.counter {
				retried = &atomic.Int64{}
			}
			conn, err := DialRetryingLostSYN(ctx, dial, retried)
			if dials != tc.wantDials {
				t.Errorf("dials = %d, want %d", dials, tc.wantDials)
			}
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("err = %v, want %v", err, tc.wantErr)
			}
			if tc.wantErr == nil && conn == nil {
				t.Error("no connection on success")
			}
			if retried != nil && retried.Load() != tc.wantRetried {
				t.Errorf("retried = %d, want %d", retried.Load(), tc.wantRetried)
			}
		})
	}
}

func TestIsConnectTimeout(t *testing.T) {
	if !IsConnectTimeout(&net.OpError{Op: "dial", Err: os.ErrDeadlineExceeded}) {
		t.Error("a dial deadline is a connect timeout")
	}
	if IsConnectTimeout(&net.OpError{Op: "dial", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}) {
		t.Error("refused is not a timeout")
	}
	if IsConnectTimeout(errors.New("unexpected EOF")) {
		t.Error("an EOF is not a timeout")
	}
}

func TestParseNstat(t *testing.T) {
	out := `#kernel
TcpExtListenOverflows           3                  0.0
TcpExtListenDrops               4                  0.0
TcpExtTCPReqQFullDrop           0                  0.0
`
	m, err := ParseNstat(out)
	if err != nil {
		t.Fatal(err)
	}
	if got := SumListenDrops(m); got != 7 {
		t.Errorf("SumListenDrops = %d, want 7", got)
	}
	// A counter missing from the output must not read as zero drops.
	if _, err := ParseNstat("#kernel\nTcpExtListenDrops 0 0.0\n"); err == nil || !strings.Contains(err.Error(), "TcpExtListenOverflows") {
		t.Errorf("missing counter: err = %v, want it named", err)
	}
	if _, err := ParseNstat("#kernel\nTcpExtListenOverflows x 0.0\n"); err == nil {
		t.Error("a non-number value was accepted")
	}
}

func TestPathLossVerdict(t *testing.T) {
	for _, tc := range []struct {
		name         string
		retried      int64
		probes       int64
		countersRead bool
		drops        int64
		want         string // "" = forgiven
	}{
		{name: "nothing retried", probes: 800, want: ""},
		{name: "nothing retried, counters unread", probes: 800, want: ""},
		{name: "one lost SYN in 800, no drops: forgiven", retried: 1, probes: 800, countersRead: true, want: ""},
		{name: "exactly 1%: forgiven", retried: 8, probes: 800, countersRead: true, want: ""},
		{name: "over 1%: counts", retried: 9, probes: 800, countersRead: true, want: "more than the 1%"},
		{name: "kernel dropped attempts: counts", retried: 1, probes: 800, countersRead: true, drops: 2, want: "full queue"},
		{name: "counters unread: counts", retried: 1, probes: 800, want: "could not be read"},
		{name: "no probes: counts", retried: 1, countersRead: true, want: "more than the 1%"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := PathLossVerdict(tc.retried, tc.probes, tc.countersRead, tc.drops)
			if tc.want == "" {
				if err != nil {
					t.Errorf("want forgiven, got %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want one containing %q", err, tc.want)
			}
		})
	}
}
