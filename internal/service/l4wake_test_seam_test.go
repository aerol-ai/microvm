package service

import (
	"context"
	"net"
	"testing"
	"time"
)

func setDialL4UpstreamForTest(t testing.TB, fn func(context.Context, string, time.Duration) (net.Conn, error)) {
	t.Helper()
	dialL4UpstreamMu.Lock()
	prev := dialL4UpstreamFn
	dialL4UpstreamFn = fn
	dialL4UpstreamMu.Unlock()
	t.Cleanup(func() {
		dialL4UpstreamMu.Lock()
		dialL4UpstreamFn = prev
		dialL4UpstreamMu.Unlock()
	})
}
