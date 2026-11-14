package harness

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
)

// The churn gates (UC-171, UC-357) open thousands of fresh connections from
// the operator's machine and allow zero failures, because a Caddy reload
// that drops a new connection is exactly the regression they guard. The
// path from a laptop to us-east-1 also loses some connections outright: the
// SYN and every retransmit go unanswered for the whole 10 s connect
// timeout. Measured on 2026-11-10 from the operator's network over 4
// minutes: 2 of 1,419 connects to the ingress and 1 of 1,432 to S3 in the
// same region, which has nothing to do with AerolVM. That is about one per
// gate run, so both gates failed run after run with a single
// "dial tcp …: i/o timeout".
//
// A connect timeout to a port that is listening has only two causes: the
// packets were lost on the way, or the server's kernel dropped the SYN
// because the listen queue was full. The kernel answers the handshake
// itself, so a busy or reloading Caddy never causes one; a reload shows up
// as a reset or an EOF on a connection that did open, or as "connection
// refused" once the listener is closed, and none of those is retried here.
// The second cause is counted by the kernel (ListenDropCounters), so a gate
// can rule it out instead of forgiving it blindly: see PathLossVerdict.

// ListenDropCounters are the kernel counters that rise when the server side
// drops a connection attempt: an accept queue or SYN queue that was full.
const ListenDropCounters = "TcpExtListenOverflows TcpExtListenDrops TcpExtTCPReqQFullDrop"

// MaxPathLossPercent bounds how many connects in a gate may time out and be
// retried. The measured path loses about 0.1%; ten times that leaves room
// for a bad minute, and anything more means the gate measured the network
// rather than the ingress, so it fails.
const MaxPathLossPercent = 1.0

// IsConnectTimeout reports whether err is a dial that timed out (no answer),
// as opposed to one that was refused or reset.
func IsConnectTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// DialRetryingLostSYN dials, and when that dial timed out, dials once more
// on a new socket (a new source port, so a new path through the operator's
// NAT) and counts it in retried. Every other error is returned at once. A
// nil retried turns the retry off.
func DialRetryingLostSYN(ctx context.Context, dial func(context.Context) (net.Conn, error), retried *atomic.Int64) (net.Conn, error) {
	conn, err := dial(ctx)
	if err == nil || retried == nil || ctx.Err() != nil || !IsConnectTimeout(err) {
		return conn, err
	}
	retried.Add(1)
	return dial(ctx)
}

// ParseNstat reads `nstat -asz <names>` output ("Name value rate" lines
// under a "#kernel" header) into name -> value.
func ParseNstat(out string) (map[string]int64, error) {
	m := map[string]int64{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 || strings.HasPrefix(f[0], "#") {
			continue
		}
		v, err := strconv.ParseInt(f[1], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("nstat line %q: %w", line, err)
		}
		m[f[0]] = v
	}
	for _, name := range strings.Fields(ListenDropCounters) {
		if _, ok := m[name]; !ok {
			return nil, fmt.Errorf("nstat output has no %s:\n%s", name, out)
		}
	}
	return m, nil
}

// SumListenDrops adds up ListenDropCounters in one node's counters.
func SumListenDrops(m map[string]int64) int64 {
	var n int64
	for _, name := range strings.Fields(ListenDropCounters) {
		n += m[name]
	}
	return n
}

// PathLossVerdict decides whether a gate's retried connect timeouts can be
// left out of its failures. It returns nil when they can: there were none,
// or the ingress kernels' drop counters were read before and after the
// window, did not rise, and the retries stayed within MaxPathLossPercent of
// the probes. Otherwise the error says why they count as failures.
func PathLossVerdict(retried, probes int64, countersRead bool, listenDrops int64) error {
	if retried == 0 {
		return nil
	}
	if !countersRead {
		return fmt.Errorf("%d connects timed out and were retried, but the ingress drop counters could not be read, so a server-side drop is not ruled out", retried)
	}
	if listenDrops > 0 {
		return fmt.Errorf("%d connects timed out, and the ingress kernel dropped %d connection attempts from a full queue (%s)", retried, listenDrops, ListenDropCounters)
	}
	if probes <= 0 || float64(retried)*100 > MaxPathLossPercent*float64(probes) {
		return fmt.Errorf("%d of %d connects timed out, more than the %.0f%% a client's network path explains", retried, probes, MaxPathLossPercent)
	}
	return nil
}
