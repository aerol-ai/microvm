// Package toolboxhttp is the HTTP transport sandboxd uses to reach a
// sandbox's toolbox over the network.
package toolboxhttp

import (
	"context"
	"net"
	"net/http"
	"sync/atomic"
	"time"
)

// DefaultDeadPeerTimeout is how long a toolbox connection to a sandbox that
// stopped answering lives on (SB_TOOLBOX_DEAD_PEER_TIMEOUT).
const DefaultDeadPeerTimeout = 30 * time.Second

// MinDeadPeerTimeout is the smallest timeout SetDeadPeerTimeout takes: the
// kernel counts keepalive time in whole seconds, and the probe interval is a
// sixth of the timeout.
const MinDeadPeerTimeout = 6 * time.Second

// dialTimeout bounds a connect, as http.DefaultTransport's dialer did.
const dialTimeout = 30 * time.Second

// deadPeerKeepAliveCount is how many unanswered probes end a connection.
const deadPeerKeepAliveCount = 3

var deadPeerTimeout atomic.Int64

func init() { deadPeerTimeout.Store(int64(DefaultDeadPeerTimeout)) }

// SetDeadPeerTimeout sets how long a connection whose sandbox stopped
// answering lives on; the daemon calls it once at boot. 0 turns the bound off
// (Go's default keepalive, about 2.5 minutes, and the kernel's retransmission
// limit, about 15 minutes). A positive value under MinDeadPeerTimeout is
// raised to it. It applies to connections dialed afterwards.
func SetDeadPeerTimeout(d time.Duration) {
	if d < 0 {
		d = 0
	}
	if d > 0 && d < MinDeadPeerTimeout {
		d = MinDeadPeerTimeout
	}
	deadPeerTimeout.Store(int64(d))
}

// DeadPeerTimeout is the current bound (0: off).
func DeadPeerTimeout() time.Duration { return time.Duration(deadPeerTimeout.Load()) }

// deadPeerSettings splits the bound into keepalive timing and the
// TCP_USER_TIMEOUT that enforces it. A connection idle for half the bound gets
// a probe, then one every sixth; the third unanswered probe ends it, so a
// connection idle when its sandbox died is closed at the bound.
// TCP_USER_TIMEOUT is set to the bound as well, for two reasons: with it set,
// Linux ends a probed connection once nothing has come back for that long
// (instead of counting probes), and it bounds the case keepalive does not
// cover, data we sent that is never acknowledged (an upload or terminal input
// to a dead sandbox), which otherwise retransmits for about 15 minutes.
//
// A live sandbox acknowledges every probe in the kernel, whatever its
// processes do, so a command that runs for hours with no output keeps its
// connection. What does end one is a sandbox that answers nothing for the
// whole bound while still existing: a VM or a gVisor sandbox paused (a
// snapshot) for longer than the bound, or a toolbox that stops reading our
// data for that long. Raise SB_TOOLBOX_DEAD_PEER_TIMEOUT if a deployment
// pauses sandboxes for longer.
func deadPeerSettings(bound time.Duration) (net.KeepAliveConfig, time.Duration) {
	interval := bound / 6
	return net.KeepAliveConfig{
		Enable:   true,
		Idle:     bound - deadPeerKeepAliveCount*interval,
		Interval: interval,
		Count:    deadPeerKeepAliveCount,
	}, bound
}

// dialer is the net.Dialer for the current bound.
func dialer() *net.Dialer { return dialerFor(DeadPeerTimeout()) }

// dialerFor is the net.Dialer for bound.
func dialerFor(bound time.Duration) *net.Dialer {
	if bound <= 0 {
		// http.DefaultTransport's dialer, which this package used before
		// the bound existed.
		return &net.Dialer{Timeout: dialTimeout, KeepAlive: 30 * time.Second}
	}
	keepAlive, userTimeout := deadPeerSettings(bound)
	return &net.Dialer{
		Timeout:         dialTimeout,
		KeepAliveConfig: keepAlive,
		Control:         userTimeoutControl(userTimeout),
	}
}

// DialContext dials a toolbox. Every network path from sandboxd to a
// toolboxd uses it (Transport, and the SSH gateway's session WebSocket), so a
// sandbox that dies without closing its connections (a killed gVisor sandbox
// or Firecracker VM: nothing is left to send a FIN or a reset, and its address
// goes silent) is noticed within DeadPeerTimeout instead of when the kernel
// gives up, minutes later (live: an exec into a gVisor sandbox killed by a
// fork bomb answered 502 after 3m18s).
func DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return dialer().DialContext(ctx, network, addr)
}

// Transport never keeps a connection open between calls. A sandbox's
// address outlives it: the next sandbox on the same Firecracker TAP slot or
// container IP gets it, and a VM restarted or resumed there has a fresh
// kernel. A pooled keep-alive connection to the old sandbox would be sent to
// the new one and reset (live: 72 of 80 concurrent execs into a fresh
// Firecracker sandbox, and a quarter of a create/exec/destroy churn, failed
// with 502 "connection reset by peer"). A local handshake per call costs
// tens of microseconds. WebSocket upgrades are unaffected: Go never marks a
// protocol switch "Connection: close", and an upgraded connection is never
// pooled.
var Transport = func() *http.Transport {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.DisableKeepAlives = true
	t.DialContext = DialContext
	return t
}()

// Client is an http.Client over Transport (timeout 0: none).
func Client(timeout time.Duration) *http.Client {
	return &http.Client{Transport: Transport, Timeout: timeout}
}
