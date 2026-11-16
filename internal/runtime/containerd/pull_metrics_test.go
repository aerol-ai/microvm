package containerd

import (
	"context"
	"errors"
	"expvar"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	cntr "github.com/containerd/containerd/v2/client"
	"github.com/containerd/errdefs"
)

// The containerd engine reports its pulls under the aerolvm_image_pull_*
// names the SandboxdImagePull* alerts read (issue #1343). Before, it had
// its own dedup, slot cap and backoff and moved none of them, so on a
// Kubernetes worker (always containerd) the three image-pull alerts could
// never fire. The expvars are process-wide, so each test reads deltas.

const pullMetricsRef = "localhost:5000/drill/app:v1"

type pullCounters struct {
	requests, waiters, rejects, queued, inflight int64
	errors                                       map[string]int64
}

func readPullCounters() pullCounters {
	intVar := func(name string) int64 { return expvar.Get(name).(*expvar.Int).Value() }
	c := pullCounters{
		requests: intVar("aerolvm_image_pull_requests_total"),
		waiters:  intVar("aerolvm_image_pull_dedup_waiters_total"),
		rejects:  intVar("aerolvm_image_pull_backoff_rejects_total"),
		queued:   intVar("aerolvm_image_pull_queued"),
		inflight: intVar("aerolvm_image_pull_inflight"),
		errors:   map[string]int64{},
	}
	expvar.Get("aerolvm_image_pull_errors_total").(*expvar.Map).Do(func(kv expvar.KeyValue) {
		c.errors[kv.Key] = kv.Value.(*expvar.Int).Value()
	})
	return c
}

func waitForCounter(t *testing.T, what string, read func() int64, want int64) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for read() != want {
		if time.Now().After(deadline) {
			t.Fatalf("%s = %d, want %d", what, read(), want)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// A failed pull counts one request and one error by reason; the next create
// of that image inside the backoff counts a request, a backoff reject and a
// "backoff" error, and never reaches the registry.
func TestEnsureImagePullMetricsErrorsAndBackoff(t *testing.T) {
	tr := newFakeTransport()
	tr.getImageFn = func(context.Context, string) (cntr.Image, error) { return nil, errdefs.ErrNotFound }
	var pulls atomic.Int64
	tr.pullImageFn = func(context.Context, string, ...cntr.RemoteOpt) (cntr.Image, error) {
		pulls.Add(1)
		return nil, errors.New("unexpected status from HEAD request to http://localhost:5000/v2/drill/app/manifests/v1: 429 Too Many Requests")
	}
	d := New(Config{PullFailureBackoff: time.Minute}, nil, nil)
	client := NewTestClient("aerolvm", tr)
	before := readPullCounters()

	if _, err := d.ensureImage(context.Background(), client, pullMetricsRef, nil); err == nil {
		t.Fatal("first pull: want the registry's error")
	}
	if _, err := d.ensureImage(context.Background(), client, pullMetricsRef, nil); err == nil {
		t.Fatal("second pull: want the backoff's refusal")
	}

	after := readPullCounters()
	for _, c := range []struct {
		name      string
		got, want int64
	}{
		{"registry pulls", pulls.Load(), 1},
		{"requests", after.requests - before.requests, 2},
		{"backoff rejects", after.rejects - before.rejects, 1},
		{"errors{rate_limited}", after.errors["rate_limited"] - before.errors["rate_limited"], 1},
		{"errors{backoff}", after.errors["backoff"] - before.errors["backoff"], 1},
		{"dedup waiters", after.waiters - before.waiters, 0},
	} {
		if c.got != c.want {
			t.Errorf("%s = %d, want %d", c.name, c.got, c.want)
		}
	}
}

// An image already in the store is no registry request at all.
func TestEnsureImagePullMetricsLocalHitIsNoRequest(t *testing.T) {
	tr := newFakeTransport()
	tr.image = &fakeImage{name: pullMetricsRef}
	d := New(Config{}, nil, nil)
	before := readPullCounters()
	if _, err := d.ensureImage(context.Background(), NewTestClient("aerolvm", tr), pullMetricsRef, nil); err != nil {
		t.Fatal(err)
	}
	if got := readPullCounters().requests - before.requests; got != 0 {
		t.Fatalf("requests = %d, want 0 for a local image", got)
	}
}

// Concurrent creates of one image share one registry pull: every caller is
// a request, and every caller that did not pull is a dedup waiter.
func TestEnsureImagePullMetricsDedupWaiters(t *testing.T) {
	const callers = 8
	tr := newFakeTransport()
	var gets atomic.Int64
	tr.getImageFn = func(context.Context, string) (cntr.Image, error) {
		gets.Add(1)
		return nil, errdefs.ErrNotFound
	}
	release := make(chan struct{})
	var pulls atomic.Int64
	tr.pullImageFn = func(context.Context, string, ...cntr.RemoteOpt) (cntr.Image, error) {
		pulls.Add(1)
		<-release
		return &fakeImage{name: pullMetricsRef}, nil
	}
	d := New(Config{}, nil, nil)
	client := NewTestClient("aerolvm", tr)
	before := readPullCounters()

	var wg sync.WaitGroup
	errs := make(chan error, callers)
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := d.ensureImage(context.Background(), client, pullMetricsRef, nil)
			errs <- err
		}()
	}
	// Each caller looks for the image twice before it joins the flight (the
	// ref as given, then normalized; this ref is both), and the leader once
	// more inside it. Hold the pull until all of them have looked, so the
	// rest join the leader's flight instead of starting their own.
	waitForCounter(t, "image lookups", gets.Load, 2*callers+1)
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}

	after := readPullCounters()
	waiters := after.waiters - before.waiters
	if got := after.requests - before.requests; got != callers {
		t.Errorf("requests = %d, want %d", got, callers)
	}
	// Each flight's leader pulls and each other caller waits: the two add up
	// to the callers whatever the scheduling.
	if pulls.Load()+waiters != callers {
		t.Errorf("registry pulls %d + dedup waiters %d, want %d", pulls.Load(), waiters, callers)
	}
	if waiters == 0 {
		t.Errorf("no caller shared a pull (%d registry pulls for %d creates)", pulls.Load(), callers)
	}
}

// A pull waiting for a free slot is queued until it gets one, and in flight
// while it holds it: the gauges SandboxdImagePullQueueBacklog and the
// runbook read.
func TestEnsureImagePullMetricsQueuedAndInflight(t *testing.T) {
	tr := newFakeTransport()
	tr.getImageFn = func(context.Context, string) (cntr.Image, error) { return nil, errdefs.ErrNotFound }
	base := readPullCounters()
	var inflightDuringPull atomic.Int64
	tr.pullImageFn = func(context.Context, string, ...cntr.RemoteOpt) (cntr.Image, error) {
		inflightDuringPull.Store(readPullCounters().inflight - base.inflight)
		return &fakeImage{name: pullMetricsRef}, nil
	}
	d := New(Config{PullMaxConcurrent: 1}, nil, nil)
	d.pullSem <- struct{}{} // another image's pull holds the only slot

	done := make(chan error, 1)
	go func() {
		_, err := d.ensureImage(context.Background(), NewTestClient("aerolvm", tr), pullMetricsRef, nil)
		done <- err
	}()
	waitForCounter(t, "queued", func() int64 { return readPullCounters().queued - base.queued }, 1)
	<-d.pullSem // that pull ends
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if got := inflightDuringPull.Load(); got != 1 {
		t.Errorf("in flight during the pull = %d, want 1", got)
	}
	end := readPullCounters()
	if end.queued != base.queued || end.inflight != base.inflight {
		t.Errorf("after the pull: queued %d, in flight %d; want both back to %d, %d",
			end.queued, end.inflight, base.queued, base.inflight)
	}
}

// A create given up while queued leaves the queue.
func TestEnsureImagePullMetricsQueuedCancel(t *testing.T) {
	tr := newFakeTransport()
	tr.getImageFn = func(context.Context, string) (cntr.Image, error) { return nil, errdefs.ErrNotFound }
	d := New(Config{PullMaxConcurrent: 1}, nil, nil)
	d.pullSem <- struct{}{}
	t.Cleanup(func() { <-d.pullSem })
	base := readPullCounters()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := d.ensureImage(ctx, NewTestClient("aerolvm", tr), pullMetricsRef, nil)
		done <- err
	}()
	waitForCounter(t, "queued", func() int64 { return readPullCounters().queued - base.queued }, 1)
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	end := readPullCounters()
	if end.queued != base.queued {
		t.Errorf("queued = %d after the cancel, want %d", end.queued, base.queued)
	}
	if got := end.errors["canceled"] - base.errors["canceled"]; got != 1 {
		t.Errorf("errors{canceled} = %d, want 1", got)
	}
}
