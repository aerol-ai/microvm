package kubepod

// Tests for the review of #1487 (M4 PR 2). Each one fails on the code
// before its fix.

import (
	"context"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	sbruntime "github.com/aerol-ai/microvm/internal/runtime"
)

// Bug 1: while a new watch is being opened, the view must not answer. The
// reviewer's case: the watch fails (500), the next one never answers, and
// the pod is deleted meanwhile. Inspect must ask the API server (404, gone),
// not the old view (which still says started).
func TestViewNotLiveUntilTheWatchAnswers(t *testing.T) {
	f := newFakeAPI(t)
	d := newTestDriver(t, f, nil)
	f.put(podOf("worker-0", testID))
	startWatch(t, d)
	if st, err := d.Inspect(context.Background(), testID); err != nil || st.ContainerIP == "" {
		t.Fatalf("Inspect while live = %+v, %v", st, err)
	}

	f.setFailWatch(http.StatusInternalServerError)
	f.cutWatches()
	waitLive(t, d, false)
	before := f.watchCount()
	f.setHangWatch(true)
	f.setFailWatch(0)
	for f.watchCount() <= before {
		time.Sleep(time.Millisecond) // a watch is now open and unanswered
	}
	f.forceRemove(testNS, testID)

	st, err := d.Inspect(context.Background(), testID)
	if !sbruntime.InstanceGone(st, err) {
		t.Fatalf("Inspect during an unanswered watch = %+v, %v; want gone (the API server's answer), not the old view's", st, err)
	}
	if _, live := d.cache.changes(); live {
		t.Fatal("the view is live while no watch has answered")
	}
	f.setHangWatch(false)
	f.cutWatches()
}

// Bug 1, second half: opening a watch cannot hang past its header timeout.
func TestWatchHeaderTimeout(t *testing.T) {
	f := newFakeAPI(t)
	f.setHangWatch(true)
	c := f.client()
	c.watchHTTP = &http.Client{Transport: watchTransport(nil, 50*time.Millisecond)}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	start := time.Now()
	opened := false
	err := c.WatchPods(ctx, testNS, "", "", func() { opened = true }, func(WatchEvent) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "timeout") || opened {
		t.Fatalf("WatchPods against a server that never answers = %v (opened %v); want a header timeout", err, opened)
	}
	if took := time.Since(start); took > 5*time.Second {
		t.Fatalf("took %s: the header timeout did not apply", took)
	}
}

func TestWatchTransport(t *testing.T) {
	tr, ok := watchTransport(nil, time.Second).(*http.Transport)
	if !ok || tr.ResponseHeaderTimeout != time.Second || tr.TLSHandshakeTimeout == 0 || tr.DialContext == nil {
		t.Fatalf("default = %+v", tr)
	}
	if tr == http.DefaultTransport {
		t.Fatal("the default transport itself was changed")
	}
	bare, ok := watchTransport(&http.Transport{}, 2*time.Second).(*http.Transport)
	if !ok || bare.ResponseHeaderTimeout != 2*time.Second || bare.TLSHandshakeTimeout != watchConnectTimeout || bare.DialContext == nil {
		t.Fatalf("bare transport = %+v: want every bound set", bare)
	}
	other := roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, net.ErrClosed })
	if got := watchTransport(other, time.Second); got == nil {
		t.Fatal("another round tripper must be kept")
	}
	if c := NewClient("https://x", nil, nil); c.watchHTTP.Timeout != 0 {
		t.Fatal("the watch client has an overall timeout")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// Bug 3: a server that ends every watch at once, empty, must not get a
// request storm. Before the fix: thousands of watches in half a second.
func TestShortWatchesBackOff(t *testing.T) {
	f := newFakeAPI(t)
	f.setEndWatch(true)
	d := newTestDriver(t, f, nil)
	d.retryMin, d.retryMax = 10*time.Millisecond, 200*time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	d.RunWatch(ctx)
	if n := f.watchCount(); n > 20 {
		t.Fatalf("%d watches in 500 ms against a server that ends each at once; want a backoff (a handful)", n)
	}
	if n := f.watchCount(); n < 2 {
		t.Fatalf("%d watches: it must still try again", n)
	}

	// A watch that lasted past shortWatch, or carried events, is the
	// server's normal end: resumed at once, with no wait.
	f2 := newFakeAPI(t)
	d2 := newTestDriver(t, f2, nil)
	d2.retryMin, d2.retryMax, d2.shortWatch = time.Hour, time.Hour, time.Nanosecond
	f2.setEndWatch(true)
	ctx2, cancel2 := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel2()
	d2.RunWatch(ctx2)
	if n := f2.watchCount(); n < 3 {
		t.Fatalf("%d watches: a watch that lasted its normal length must be resumed at once, not after the hour-long backoff", n)
	}
}
