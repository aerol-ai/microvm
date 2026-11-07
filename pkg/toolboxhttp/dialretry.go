package toolboxhttp

import (
	"context"
	"errors"
	"expvar"
	"net"
	"net/http"
	"syscall"
	"time"
)

// dialRetryDelays are the waits before each new dial of a toolbox that
// refused the connection: three more tries after the first, 200, 400 and
// 800 ms apart, the schedule agent-sandbox's router uses
// (plans/agent-sandbox-feature-parity.md, I1). A toolbox that never
// listens costs its caller 1.4 s more before the 502.
var dialRetryDelays = []time.Duration{200 * time.Millisecond, 400 * time.Millisecond, 800 * time.Millisecond}

// aerolvm_toolbox_dial_retries_total counts re-dials of a toolbox that
// refused the connection, by what the re-dial got (key): connected (the
// call the retry saved), refused, or error (anything else). A steady
// "connected" rate means sandboxes answer calls before their toolboxd
// listens, and each of those calls waited at least 200 ms.
var dialRetriesTotal = expvar.NewMap("aerolvm_toolbox_dial_retries_total")

// waitRetry waits d and reports true, or false when ctx ends first.
// Tests replace it to run the schedule without sleeping.
var waitRetry = func(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}

// DialContextRetryRefused is DialContext that dials again, after a short
// wait, while the toolbox refuses the connection: a live address with
// nothing listening on the port yet, the gap between a sandbox reported
// started (or toolboxd restarted inside it) and toolboxd binding its port.
//
// It retries a refusal only. A refusal comes back at once, so the retry is
// cheap and bounded by dialRetryDelays. A timeout has already taken up to
// dialTimeout, and an unreachable address means the sandbox's network is
// gone; retrying those would only push the 502 back by up to minutes.
//
// The retry is safe for any request, a body that cannot be re-read
// included: it happens inside the dial, before http.Transport writes a
// byte of the request. Nothing outside the dial is retried. A RoundTrip
// level retry would not be: Transport closes the request body when
// RoundTrip fails, a failed dial included, and an error after the dial may
// come after the request (or part of it) went out. Transport's own replay
// applies only to a reused connection, which DisableKeepAlives rules out.
//
// http.Transport detaches the dial from the request's cancellation (the
// connection could serve another request), so a caller that gives up mid
// retry gets its answer at once while this dial ends within the budget; a
// connection made after that is closed unused.
func DialContextRetryRefused(ctx context.Context, network, addr string) (net.Conn, error) {
	return dialRetryingRefused(ctx, network, addr, DialContext, dialRetryDelays)
}

func dialRetryingRefused(ctx context.Context, network, addr string, dial func(context.Context, string, string) (net.Conn, error), delays []time.Duration) (net.Conn, error) {
	conn, err := dial(ctx, network, addr)
	for _, delay := range delays {
		if !isRefused(err) || !waitRetry(ctx, delay) {
			break
		}
		conn, err = dial(ctx, network, addr)
		dialRetriesTotal.Add(dialRetryResult(err), 1)
	}
	return conn, err
}

// isRefused reports a connect the peer refused (ECONNREFUSED).
func isRefused(err error) bool {
	return err != nil && errors.Is(err, syscall.ECONNREFUSED)
}

func dialRetryResult(err error) string {
	switch {
	case err == nil:
		return "connected"
	case isRefused(err):
		return "refused"
	}
	return "error"
}

// ProxyTransport is Transport whose dial is tried again while the toolbox
// refuses the connection (DialContextRetryRefused). The toolbox proxies use
// it: the v1 and Daytona reverse proxy and RoundTripToolbox
// (internal/service/toolbox_proxy.go) and E2B's runtime proxy
// (pkg/api/e2b/runtime_proxy.go). Probes keep Transport, so a probe of a
// toolbox that is down answers at once and the next probe tries again.
var ProxyTransport = func() *http.Transport {
	t := Transport.Clone()
	t.DialContext = DialContextRetryRefused
	return t
}()

// ProxyClient is an http.Client over ProxyTransport (timeout 0: none).
func ProxyClient(timeout time.Duration) *http.Client {
	return &http.Client{Transport: ProxyTransport, Timeout: timeout}
}
