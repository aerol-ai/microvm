package containerd

import (
	"context"
	"errors"
	"expvar"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	cntr "github.com/containerd/containerd/v2/client"
	remoteerrors "github.com/containerd/containerd/v2/core/remotes/errors"
	"github.com/containerd/errdefs"

	dockerpkg "github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
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

	// Both are registry trouble that passes: the API's 503 + Retry-After,
	// not the catch-all 400.
	if _, err := d.ensureImage(context.Background(), client, pullMetricsRef, nil); !errors.Is(err, models.ErrImagePullUnavailable) {
		t.Fatalf("first pull: %v, want the registry's error marked ErrImagePullUnavailable", err)
	}
	if _, err := d.ensureImage(context.Background(), client, pullMetricsRef, nil); !errors.Is(err, models.ErrImagePullUnavailable) {
		t.Fatalf("second pull: %v, want the backoff's refusal marked ErrImagePullUnavailable", err)
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

// A missing tag is the caller's to fix: neither its failure nor the backoff
// refusals after it are marked as registry trouble that passes, so the API
// keeps answering 400, not a 503 to retry.
func TestEnsureImageMissingTagStaysCallerError(t *testing.T) {
	tr := newFakeTransport()
	tr.getImageFn = func(context.Context, string) (cntr.Image, error) { return nil, errdefs.ErrNotFound }
	tr.pullImageFn = func(context.Context, string, ...cntr.RemoteOpt) (cntr.Image, error) {
		return nil, errors.New(`failed to resolve reference "localhost:5000/drill/app:v1": localhost:5000/drill/app:v1: not found`)
	}
	d := New(Config{PullFailureBackoff: time.Minute}, nil, nil)
	client := NewTestClient("aerolvm", tr)
	for i, what := range []string{"the failed pull", "the backoff refusal"} {
		_, err := d.ensureImage(context.Background(), client, pullMetricsRef, nil)
		if err == nil || errors.Is(err, models.ErrImagePullUnavailable) {
			t.Fatalf("%s (%d): %v, want an error not marked ErrImagePullUnavailable", what, i, err)
		}
		if i == 1 && !strings.Contains(err.Error(), "not found") {
			t.Fatalf("the backoff refusal does not name its cause: %v", err)
		}
	}
}

// A permanent failure that is neither a missing tag nor a refused login
// stays a 400 through its whole backoff (issue #1343 review): the refusal's
// own wording used to be classified, not its cause, so every create in the
// 30 s after it was a 503 with Retry-After, which steady traffic re-armed.
func TestEnsureImageBackoffOfPermanentFailureStays400(t *testing.T) {
	tr := newFakeTransport()
	tr.getImageFn = func(context.Context, string) (cntr.Image, error) { return nil, errdefs.ErrNotFound }
	tr.pullImageFn = func(context.Context, string, ...cntr.RemoteOpt) (cntr.Image, error) {
		// containerd 2 refuses Docker schema-1 manifests.
		return nil, errors.New("failed to pull: converting from schema 1 manifests is not supported (media type application/vnd.docker.distribution.manifest.v1+prettyjws)")
	}
	d := New(Config{PullFailureBackoff: time.Minute}, nil, nil)
	client := NewTestClient("aerolvm", tr)
	for i, what := range []string{"the failed pull", "the backoff refusal"} {
		_, err := d.ensureImage(context.Background(), client, pullMetricsRef, nil)
		if err == nil || errors.Is(err, models.ErrImagePullUnavailable) {
			t.Errorf("%s (%d): %v: marked ErrImagePullUnavailable (503); the same permanent cause stays 400", what, i, err)
		}
	}
}

// A ref's backoff entry keeps a short cause, never the registry's error
// itself, and expired entries go (issue #1343 review): containerd's
// ErrUnexpectedStatus holds up to 64 KB of the registry's body, and nothing
// pruned the entries, so creates of many distinct failing refs grew the
// worker's heap without bound.
func TestEnsureImagePullFailuresArePrunedAndCapped(t *testing.T) {
	tr := newFakeTransport()
	tr.getImageFn = func(context.Context, string) (cntr.Image, error) { return nil, errdefs.ErrNotFound }
	body := make([]byte, 64000)
	tr.pullImageFn = func(_ context.Context, ref string, _ ...cntr.RemoteOpt) (cntr.Image, error) {
		return nil, fmt.Errorf("failed to resolve reference %q: %w", ref, remoteerrors.ErrUnexpectedStatus{
			Status: "500 Internal Server Error", StatusCode: 500, Body: body,
			RequestURL: "https://evil.example/v2/x/manifests/" + ref + "/" + strings.Repeat("a", 2000), RequestMethod: "GET"})
	}
	d := New(Config{PullFailureBackoff: time.Millisecond}, nil, nil)
	client := NewTestClient("aerolvm", tr)
	const n = 200
	for i := range n {
		_, _ = d.ensureImage(context.Background(), client, fmt.Sprintf("evil.example/x:%d", i), nil)
	}
	time.Sleep(10 * time.Millisecond) // every backoff has run out
	_, err := d.ensureImage(context.Background(), client, "evil.example/x:last", nil)
	if !errors.Is(err, models.ErrImagePullUnavailable) {
		t.Fatalf("a registry 500: %v, want the 503 mark", err)
	}

	d.pullFailMu.Lock()
	defer d.pullFailMu.Unlock()
	if len(d.pullFails) != 1 {
		t.Errorf("%d backoff entries after %d expired and one new failure, want 1", len(d.pullFails), n)
	}
	for ref, f := range d.pullFails {
		if len(f.cause) > 600 || !f.transient {
			t.Errorf("%s: cause %d bytes, transient %v; want a capped cause of a transient failure", ref, len(f.cause), f.transient)
		}
	}
}

// A create whose caller left starts no backoff (issue #1343 review): the
// containerd engine used to record the leader's context.Canceled as the
// image's failure, so every create of that healthy image for the next
// backoff was refused, as a 400. dockerd already skipped it. A create that
// shared the flight gets the leader's cancel with its own ctx alive, so it
// must not record it either.
func TestEnsureImageCallerGoneStartsNoBackoff(t *testing.T) {
	for _, tc := range []struct {
		name   string
		ctx    func() (context.Context, context.CancelFunc, func())
		waiter bool
	}{
		{"cancelled", func() (context.Context, context.CancelFunc, func()) {
			ctx, cancel := context.WithCancel(context.Background())
			return ctx, cancel, cancel
		}, false},
		{"cancelled, with a create sharing its pull", func() (context.Context, context.CancelFunc, func()) {
			ctx, cancel := context.WithCancel(context.Background())
			return ctx, cancel, cancel
		}, true},
		{"its own deadline ran out", func() (context.Context, context.CancelFunc, func()) {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
			return ctx, cancel, func() {}
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tr := newFakeTransport()
			var gets atomic.Int64
			tr.getImageFn = func(context.Context, string) (cntr.Image, error) {
				gets.Add(1)
				return nil, errdefs.ErrNotFound
			}
			var pulls atomic.Int64
			started := make(chan struct{}, 1)
			tr.pullImageFn = func(ctx context.Context, _ string, _ ...cntr.RemoteOpt) (cntr.Image, error) {
				if pulls.Add(1) == 1 {
					started <- struct{}{}
					<-ctx.Done() // the registry is slow; the caller leaves
					return nil, fmt.Errorf("failed to resolve reference: %w", ctx.Err())
				}
				return &fakeImage{name: pullMetricsRef}, nil
			}
			d := New(Config{PullFailureBackoff: time.Minute}, nil, nil)
			client := NewTestClient("aerolvm", tr)

			ctx, cancel, leave := tc.ctx()
			defer cancel()
			done := make(chan error, 1)
			go func() {
				_, err := d.ensureImage(ctx, client, pullMetricsRef, nil)
				done <- err
			}()
			<-started
			waited := make(chan error, 1)
			if tc.waiter {
				go func() {
					_, err := d.ensureImage(context.Background(), client, pullMetricsRef, nil)
					waited <- err
				}()
				// The leader looked twice and once in the flight; the
				// waiter looks twice, then joins (as in the dedup test).
				waitForCounter(t, "image lookups", gets.Load, 5)
				time.Sleep(50 * time.Millisecond)
			}
			leave()
			if err := <-done; err == nil {
				t.Fatal("the pull whose caller left succeeded")
			}
			if tc.waiter {
				if err := <-waited; !errors.Is(err, context.Canceled) {
					t.Fatalf("the create sharing the pull: %v, want the leader's cancel", err)
				}
			}
			if _, err := d.ensureImage(context.Background(), client, pullMetricsRef, nil); err != nil {
				t.Fatalf("the next create of the image: %v, want a fresh pull", err)
			}
			if got := pulls.Load(); got != 2 {
				t.Errorf("registry pulls = %d, want 2: the next create was not let through to the registry", got)
			}
		})
	}
}

// The registry not answering in time still starts the backoff, though its
// error is a context.DeadlineExceeded too (net/http's response-header
// timeout): only the caller's own context ending skips it. This is the
// image-pull-storm drill's hanging registry, which the backoff must shed.
func TestEnsureImageRegistryHeaderTimeoutBacksOff(t *testing.T) {
	stall := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-stall }))
	defer srv.Close()
	defer close(stall)
	hc := &http.Client{Transport: &http.Transport{ResponseHeaderTimeout: 20 * time.Millisecond}}
	_, headerTimeout := hc.Head(srv.URL + "/v2/drill/app/manifests/v1")
	if !errors.Is(headerTimeout, context.DeadlineExceeded) {
		t.Fatalf("net/http's header timeout %v is not a context.DeadlineExceeded; this test's premise is gone", headerTimeout)
	}

	tr := newFakeTransport()
	tr.getImageFn = func(context.Context, string) (cntr.Image, error) { return nil, errdefs.ErrNotFound }
	var pulls atomic.Int64
	tr.pullImageFn = func(context.Context, string, ...cntr.RemoteOpt) (cntr.Image, error) {
		pulls.Add(1)
		return nil, fmt.Errorf("failed to resolve reference %q: failed to do request: %w", pullMetricsRef, headerTimeout)
	}
	d := New(Config{PullFailureBackoff: time.Minute}, nil, nil)
	client := NewTestClient("aerolvm", tr)
	_, _ = d.ensureImage(context.Background(), client, pullMetricsRef, nil)
	_, err := d.ensureImage(context.Background(), client, pullMetricsRef, nil)
	var refusal *dockerpkg.PullBackoffError
	if !errors.As(err, &refusal) || !errors.Is(err, models.ErrImagePullUnavailable) {
		t.Fatalf("after the registry timed out: %v, want the backoff's refusal, a 503", err)
	}
	if got := pulls.Load(); got != 1 {
		t.Errorf("registry pulls = %d, want 1 while the backoff runs", got)
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
