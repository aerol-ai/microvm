package kubepod

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
)

// startWatch runs d.RunWatch until the test ends and waits until its view
// is live.
func startWatch(t *testing.T, d *Driver) {
	t.Helper()
	d.retryMin, d.retryMax = time.Millisecond, 5*time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		d.RunWatch(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	waitLive(t, d, true)
}

func waitLive(t *testing.T, d *Driver, want bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, live := d.cache.changes(); live == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the watch's view never became live = %v", want)
		}
		time.Sleep(time.Millisecond)
	}
}

// streamEvents runs StreamEvents into a channel until the test ends, once
// it is subscribed.
func streamEvents(t *testing.T, d *Driver) <-chan docker.DockerEvent {
	t.Helper()
	out := make(chan docker.DockerEvent, 64)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- d.StreamEvents(ctx, out) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Errorf("StreamEvents ended with %v, want context.Canceled", err)
		}
	})
	deadline := time.Now().Add(5 * time.Second)
	for {
		d.cache.mu.Lock()
		n := len(d.cache.subs)
		d.cache.mu.Unlock()
		if n > 0 {
			return out
		}
		if time.Now().After(deadline) {
			t.Fatal("StreamEvents never subscribed")
		}
		time.Sleep(time.Millisecond)
	}
}

func nextEvent(t *testing.T, ch <-chan docker.DockerEvent) docker.DockerEvent {
	t.Helper()
	select {
	case ev := <-ch:
		return ev
	case <-time.After(5 * time.Second):
		t.Fatal("no event came")
		return docker.DockerEvent{}
	}
}

func noEvent(t *testing.T, ch <-chan docker.DockerEvent) {
	t.Helper()
	select {
	case ev := <-ch:
		t.Fatalf("unexpected event %+v", ev)
	case <-time.After(50 * time.Millisecond):
	}
}

const (
	podReadPrefix = "GET /api/v1/namespaces/" + testNS + "/pods/"
	listCall      = "GET /api/v1/namespaces/" + testNS + "/pods"
)

// lists counts list calls: the list path is a prefix of every pod read.
func lists(f *fakeAPI) int { return f.count(listCall) - f.count(podReadPrefix) }

func TestWatchServesReadsAndWaits(t *testing.T) {
	f := newFakeAPI(t)
	f.setKubelet(runningKubelet)
	f.setGoneAfter(2)
	f.runKubelet(2 * time.Millisecond)
	d := newTestDriver(t, f, nil)
	startWatch(t, d)

	st := mustCreate(t, d)
	if st.ContainerIP == "" || st.StartedAt.IsZero() {
		t.Fatalf("create = %+v", st)
	}
	got, err := d.Inspect(context.Background(), testID)
	if err != nil || got.Status != models.SandboxStatusStarted {
		t.Fatalf("Inspect = %+v, %v", got, err)
	}
	all, err := d.ListManaged(context.Background())
	if err != nil || all[testID] == nil {
		t.Fatalf("ListManaged = %v, %v", all, err)
	}
	if err := d.Stop(context.Background(), testID); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if got, err := d.Inspect(context.Background(), testID); err != nil || got.Status != models.SandboxStatusStopped {
		t.Fatalf("Inspect after stop = %+v, %v", got, err)
	}
	if _, err := d.Start(context.Background(), testID); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := d.Destroy(context.Background(), &models.Sandbox{ID: testID}); err != nil {
		t.Fatalf("Destroy: %v", err)
	}

	if n := f.count(podReadPrefix); n != 0 {
		t.Errorf("%d pod reads went to the API server with a live watch, want 0", n)
	}
	if n := lists(f); n != 1 {
		t.Errorf("lists = %d, want the one the watch started from", n)
	}
	if n := f.watchCount(); n != 1 {
		t.Errorf("watches = %d, want 1", n)
	}
}

func TestWatchEvents(t *testing.T) {
	f := newFakeAPI(t)
	f.setKubelet(runningKubelet)
	f.runKubelet(2 * time.Millisecond)
	d := newTestDriver(t, f, nil)
	// A pod already running when the worker starts sends no event.
	f.put(podOf("worker-0", "sb-a000000000000000"))
	startWatch(t, d)
	events := streamEvents(t, d)
	noEvent(t, events)

	mustCreate(t, d)
	ev := nextEvent(t, events)
	started := time.Date(2026, 11, 26, 10, 0, 0, 0, time.UTC)
	if ev.Action != "start" || ev.SandboxID != testID || ev.ContainerID != testID || !ev.Time.Equal(started) {
		t.Fatalf("event = %+v, want start at the container's start", ev)
	}

	finished := started.Add(time.Minute)
	f.change(testNS, testID, func(p *Pod) {
		p.Status.ContainerStatuses[0].State = ContainerState{Terminated: &StateTerminated{ExitCode: 137, Reason: "OOMKilled", FinishedAt: &finished}}
	})
	if ev := nextEvent(t, events); ev.Action != "oom" || ev.SandboxID != testID {
		t.Fatalf("event = %+v, want oom", ev)
	}
	if ev := nextEvent(t, events); ev.Action != "die" || ev.ExitCode != 137 || !ev.Time.Equal(finished) {
		t.Fatalf("event = %+v, want die 137 at the finish", ev)
	}
	// The same end seen again (another status change) is not a second exit.
	f.change(testNS, testID, func(p *Pod) { p.Status.Phase = PhaseFailed })
	noEvent(t, events)

	// A running pod removed with no end seen exits at its deletion time.
	f.forceRemove(testNS, "sb-a000000000000000")
	if ev := nextEvent(t, events); ev.Action != "die" || ev.SandboxID != "sb-a000000000000000" || ev.ExitCode != 0 ||
		!ev.Time.Equal(time.Date(2026, 11, 26, 11, 0, 0, 0, time.UTC)) {
		t.Fatalf("event = %+v, want die at the deletion time", ev)
	}
	// A bookmark moves the version and sends nothing.
	f.bookmark()
	noEvent(t, events)
	if d.cache.version() != fmt.Sprint(f.rv) {
		t.Errorf("version = %s after a bookmark, want %d", d.cache.version(), f.rv)
	}
}

func TestWatchResumesAndRelists(t *testing.T) {
	f := newFakeAPI(t)
	d := newTestDriver(t, f, nil)
	f.put(podOf("worker-0", "sb-a000000000000000"))
	f.put(podOf("worker-0", "sb-b000000000000000"))
	startWatch(t, d)
	events := streamEvents(t, d)

	// A dropped connection: the watch resumes from the last version, with
	// no new list.
	f.cutWatches()
	deadline := time.Now().Add(5 * time.Second)
	for f.watchCount() < 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	waitLive(t, d, true)
	if n := lists(f); n != 1 {
		t.Fatalf("lists after a dropped watch = %d, want 1", n)
	}

	// An outage: the watch fails, so reads go to the API server.
	f.setFailWatch(http.StatusInternalServerError)
	f.cutWatches()
	waitLive(t, d, false)
	before := f.count(podReadPrefix)
	if st, err := d.Inspect(context.Background(), "sb-a000000000000000"); err != nil || st.Status != models.SandboxStatusStarted {
		t.Fatalf("Inspect during the outage = %+v, %v", st, err)
	}
	if f.count(podReadPrefix) != before+1 {
		t.Error("Inspect without a live watch must read the API server")
	}
	// Meanwhile one sandbox ends and the other's pod goes away, and the
	// API server forgets the history.
	finished := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	f.change(testNS, "sb-a000000000000000", func(p *Pod) {
		p.Status.ContainerStatuses = []ContainerStatus{{Name: sandboxContainer, State: ContainerState{Terminated: &StateTerminated{ExitCode: 3, FinishedAt: &finished}}}}
	})
	f.forceRemove(testNS, "sb-b000000000000000")
	f.compact()
	f.setFailWatch(0)
	waitLive(t, d, true)

	got := map[string]docker.DockerEvent{}
	for i := 0; i < 2; i++ {
		ev := nextEvent(t, events)
		got[ev.SandboxID] = ev
	}
	if ev := got["sb-a000000000000000"]; ev.Action != "die" || ev.ExitCode != 3 || !ev.Time.Equal(finished) {
		t.Errorf("event for the ended sandbox = %+v", ev)
	}
	if ev := got["sb-b000000000000000"]; ev.Action != "die" {
		t.Errorf("event for the removed sandbox = %+v", ev)
	}
	if n := lists(f); n != 2 {
		t.Errorf("lists = %d, want a second one after the 410", n)
	}
	if _, found, _ := d.cache.lookup("sb-b000000000000000"); found {
		t.Error("the removed pod is still in the view")
	}
}

func TestWatchRetriesErrors(t *testing.T) {
	f := newFakeAPI(t)
	d := newTestDriver(t, f, nil)
	d.retryMin, d.retryMax = time.Millisecond, 5*time.Millisecond
	f.setFail(listCall, http.StatusForbidden, false)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		d.RunWatch(ctx)
	}()
	defer func() {
		cancel()
		<-done
	}()
	for lists(f)+f.count(listCall) < 6 {
		time.Sleep(time.Millisecond)
	}
	if _, live := d.cache.changes(); live {
		t.Fatal("live with no list")
	}
	f.setFail(listCall, 0, false)
	f.setFailWatch(http.StatusForbidden)
	for f.watchCount() < 3 {
		time.Sleep(time.Millisecond)
	}
	f.setFailWatch(0)
	waitLive(t, d, true)
}

func TestRunWatchStopsWhileWaiting(t *testing.T) {
	f := newFakeAPI(t)
	d := newTestDriver(t, f, nil)
	d.retryMin, d.retryMax = time.Hour, time.Hour
	f.setFail(listCall, http.StatusInternalServerError, false)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		d.RunWatch(ctx)
	}()
	for f.count(listCall) == 0 {
		time.Sleep(time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("RunWatch did not stop during its retry wait")
	}
}

// liveView makes d's view live over pods, with no watch running.
func liveView(d *Driver, pods ...Pod) {
	d.cache.replace(pods, "1")
	d.cache.setLive(true)
}

func TestWaitRunningWithTheView(t *testing.T) {
	f := newFakeAPI(t)
	d := newTestDriver(t, f, func(c *Config) { c.StartTimeout = 30 * time.Millisecond })
	liveView(d)
	// Made, but never shown: the wait says what it waited for.
	_, err := d.waitRunning(context.Background(), testID, "uid-9")
	if err == nil || !strings.Contains(err.Error(), "not shown by the watch yet") {
		t.Fatalf("waitRunning = %v", err)
	}
	// Shown deleted before it was ever shown running.
	d.cache.mu.Lock()
	d.cache.gone["uid-9"] = time.Now()
	d.cache.mu.Unlock()
	if _, err := d.waitRunning(context.Background(), testID, "uid-9"); err == nil || !strings.Contains(err.Error(), "deleted while it started") {
		t.Fatalf("waitRunning = %v", err)
	}
	if n := f.count(""); n != 0 {
		t.Errorf("%d API calls with a live view", n)
	}
}

func TestPodCache(t *testing.T) {
	c := newPodCache()
	now := time.Date(2026, 11, 26, 9, 0, 0, 0, time.UTC)
	c.now = func() time.Time { return now }
	if err := c.apply(WatchEvent{Type: "SURPRISE"}); err == nil {
		t.Error("an unknown event type: want an error")
	}
	ch, _ := c.subscribe()
	running := *podOf("worker-0", testID)
	running.Metadata.UID = "uid-1"
	running.Status.ContainerStatuses = []ContainerStatus{{Name: sandboxContainer, State: ContainerState{Running: &StateRunning{}}}}
	c.replace(nil, "1")
	if err := c.apply(WatchEvent{Type: "ADDED", Object: running}); err != nil {
		t.Fatal(err)
	}
	if ev := <-ch; ev.Action != "start" || !ev.Time.IsZero() {
		t.Fatalf("event = %+v", ev)
	}
	// The name taken by a new pod: the old one ended unseen.
	next := *withPhase(podOf("worker-0", testID), PhasePending) // never runs
	next.Metadata.UID = "uid-2"
	if err := c.apply(WatchEvent{Type: "MODIFIED", Object: next}); err != nil {
		t.Fatal(err)
	}
	if ev := <-ch; ev.Action != "die" {
		t.Fatalf("event = %+v, want the old pod's die", ev)
	}
	if !c.deleted("uid-1") || c.deleted("uid-2") {
		t.Error("tombstones wrong")
	}
	// Tombstones are forgotten after goneKeep.
	now = now.Add(goneKeep + time.Second)
	if err := c.apply(WatchEvent{Type: "DELETED", Object: next}); err != nil {
		t.Fatal(err)
	}
	if c.deleted("uid-1") || !c.deleted("uid-2") {
		t.Error("an old tombstone was kept, or the new one lost")
	}
	// A pod that never ran sends nothing when it goes.
	select {
	case ev := <-ch:
		t.Fatalf("unexpected event %+v", ev)
	default:
	}
	// A reader that falls behind loses events, and the watch never waits.
	for i := 0; i < eventBuffer+5; i++ {
		c.mu.Lock()
		c.publishLocked(docker.DockerEvent{Action: "start"})
		c.mu.Unlock()
	}
	if got := c.droppedEvents(); got != 5 {
		t.Errorf("dropped = %d, want 5", got)
	}
	if _, found, live := c.lookup(testID); live || found {
		t.Error("a view no watch made live must not answer")
	}
	if _, live := c.all(); live {
		t.Error("all must not answer when not live")
	}
}

func TestContainerPID(t *testing.T) {
	d := newTestDriver(t, newFakeAPI(t), nil)
	if _, err := d.ContainerPID(context.Background(), testID); !errors.Is(err, ErrNoProcessView) {
		t.Fatalf("ContainerPID = %v", err)
	}
}

func TestStreamEventsWaitsForTheReader(t *testing.T) {
	d := newTestDriver(t, newFakeAPI(t), nil)
	out := make(chan docker.DockerEvent) // nobody reads
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- d.StreamEvents(ctx, out) }()
	for {
		d.cache.mu.Lock()
		n := len(d.cache.subs)
		if n > 0 {
			d.cache.publishLocked(docker.DockerEvent{Action: "start"})
		}
		d.cache.mu.Unlock()
		if n > 0 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	time.Sleep(10 * time.Millisecond)
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("StreamEvents = %v", err)
	}
}

func TestWatchPodsStream(t *testing.T) {
	cases := []struct {
		name  string
		body  string
		code  int
		check func(t *testing.T, err error, got []WatchEvent)
	}{
		{"events then end", `{"type":"ADDED","object":{"metadata":{"name":"p","resourceVersion":"5"}}}` + "\n" +
			`{"type":"BOOKMARK","object":{"metadata":{"resourceVersion":"6"}}}`, 200,
			func(t *testing.T, err error, got []WatchEvent) {
				if err != nil || len(got) != 2 || got[0].Object.Metadata.Name != "p" || got[1].Type != "BOOKMARK" {
					t.Fatalf("got %+v, %v", got, err)
				}
			}},
		{"expired in the stream", `{"type":"ERROR","object":{"kind":"Status","code":410,"reason":"Expired","message":"too old"}}`, 200,
			func(t *testing.T, err error, _ []WatchEvent) {
				if !isGone(err) {
					t.Fatalf("err = %v, want 410", err)
				}
			}},
		{"expired at the start", `{"kind":"Status","code":410,"reason":"Gone"}`, 410,
			func(t *testing.T, err error, _ []WatchEvent) {
				if !isGone(err) {
					t.Fatalf("err = %v, want 410", err)
				}
			}},
		{"broken stream", `{"type":"ADDED","object":`, 200,
			func(t *testing.T, err error, _ []WatchEvent) {
				if err == nil || isGone(err) {
					t.Fatalf("err = %v, want a decode error", err)
				}
			}},
		{"bad object", `{"type":"ADDED","object":[1]}`, 200,
			func(t *testing.T, err error, _ []WatchEvent) {
				if err == nil || !strings.Contains(err.Error(), "decode event") {
					t.Fatalf("err = %v", err)
				}
			}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				q := r.URL.Query()
				if q.Get("watch") != "1" || q.Get("allowWatchBookmarks") != "true" || q.Get("resourceVersion") != "4" || q.Get("labelSelector") != "a=b" {
					t.Errorf("query = %v", q)
				}
				w.WriteHeader(tc.code)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			var got []WatchEvent
			err := NewClient(srv.URL, nil, nil).WatchPods(context.Background(), "ns", "a=b", "4", func(ev WatchEvent) error {
				got = append(got, ev)
				return nil
			})
			tc.check(t, err, got)
		})
	}
	t.Run("the caller's error ends the watch", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"type":"ADDED","object":{}}` + "\n" + `{"type":"ADDED","object":{}}`))
		}))
		defer srv.Close()
		calls := 0
		stop := errors.New("stop")
		err := NewClient(srv.URL, nil, nil).WatchPods(context.Background(), "ns", "", "", func(WatchEvent) error {
			calls++
			return stop
		})
		if !errors.Is(err, stop) || calls != 1 {
			t.Fatalf("err = %v after %d calls", err, calls)
		}
	})
	t.Run("transport error", func(t *testing.T) {
		srv := httptest.NewServer(http.NotFoundHandler())
		srv.Close()
		if err := NewClient(srv.URL, nil, nil).WatchPods(context.Background(), "ns", "", "", nil); err == nil {
			t.Fatal("want an error")
		}
	})
}
