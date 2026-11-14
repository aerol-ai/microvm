package service

import (
	"context"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
)

// sendEvent hands ev to the stream loop, failing if the loop does not take
// it: the channel is unbuffered, so a loop that waits on one sandbox cannot
// take the next event.
func sendEvent(t *testing.T, events chan<- docker.DockerEvent, ev docker.DockerEvent) {
	t.Helper()
	select {
	case events <- ev:
	case <-time.After(2 * time.Second):
		t.Fatalf("the event loop did not take %s for %s: it is waiting on another sandbox", ev.Action, ev.SandboxID)
	}
}

func waitForSandboxStatus(t *testing.T, h *restartHarness, id string, want models.SandboxStatus, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		if h.row(t, id).Status == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s is %s after %s, want %s", id, h.row(t, id).Status, within, want)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestALongLifecycleStepDoesNotDelayOtherSandboxesEvents: one sandbox is
// held by a long step inside its lifecycle boundary (a restart or a destroy
// can hold it up to restartStartTimeout), and its die event waits for it.
// Another sandbox's die, which comes next on the stream, is handled at once.
// Before, the one event loop waited for the first sandbox, and every other
// sandbox's events waited with it.
func TestALongLifecycleStepDoesNotDelayOtherSandboxesEvents(t *testing.T) {
	ctx := context.Background()
	h := newRestartHarness(t)
	h.seedStarted(t, "sb-slow", models.Lifecycle{}, 0, 0)
	h.seedStarted(t, "sb-other", models.Lifecycle{}, 0, 0)

	unlock, err := h.svc.lifecycleLocks.lockCtx(ctx, "sb-slow")
	if err != nil {
		t.Fatal(err)
	}
	events := make(chan docker.DockerEvent)
	done := make(chan struct{})
	go func() {
		h.svc.consumeEvents(ctx, events)
		close(done)
	}()

	sendEvent(t, events, docker.DockerEvent{SandboxID: "sb-slow", ContainerID: "sb-slow", Action: "die", ExitCode: 1})
	sendEvent(t, events, docker.DockerEvent{SandboxID: "sb-other", ContainerID: "sb-other", Action: "die", ExitCode: 1})
	waitForSandboxStatus(t, h, "sb-other", models.SandboxStatusStopped, 2*time.Second)
	if got := h.row(t, "sb-slow").Status; got != models.SandboxStatusStarted {
		t.Fatalf("sb-slow is %s while its lifecycle step still runs", got)
	}

	unlock()
	close(events)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the held sandbox's event never ran after its step ended")
	}
	if got := h.row(t, "sb-slow"); got.Status != models.SandboxStatusStopped || got.StatusReason != models.StatusReasonCrashed {
		t.Fatalf("sb-slow after its step: %s %q, want stopped crashed", got.Status, got.StatusReason)
	}
}

// TestASandboxsEventsKeepTheirOrderBehindItsLifecycleBoundary: a die that
// waits for the sandbox's boundary keeps the start that came after it
// waiting too, so the start is handled second and the sandbox ends started.
// Handled out of order it would end stopped.
func TestASandboxsEventsKeepTheirOrderBehindItsLifecycleBoundary(t *testing.T) {
	ctx := context.Background()
	h := newRestartHarness(t)
	id := "sb-ordered"
	h.seedStarted(t, id, models.Lifecycle{}, 0, 0)
	h.rt.inspect = map[string]*models.SandboxRuntimeState{
		id: {ContainerID: id, ContainerIP: "10.0.0.7", Status: models.SandboxStatusStarted},
	}

	unlock, err := h.svc.lifecycleLocks.lockCtx(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	queues := h.svc.newEventQueues(ctx)
	events := make(chan docker.DockerEvent)
	fed := make(chan struct{})
	go func() {
		h.svc.feedEvents(ctx, events, queues)
		close(fed)
	}()
	sendEvent(t, events, docker.DockerEvent{SandboxID: id, ContainerID: id, Action: "die", ExitCode: 137})
	sendEvent(t, events, docker.DockerEvent{SandboxID: id, ContainerID: id, Action: "start"})
	time.Sleep(50 * time.Millisecond)
	if n := queues.pending(id); n != 1 {
		t.Fatalf("pending behind the waiting die = %d, want the start", n)
	}

	unlock()
	close(events)
	<-fed
	queues.wait()
	if got := h.row(t, id); got.Status != models.SandboxStatusStarted {
		t.Fatalf("after die then start: %s, want started (the start handled second)", got.Status)
	}
}

// recordedEvents is a handler that records what each sandbox's events were,
// in the order handled, and can hold one sandbox's first event.
type recordedEvents struct {
	mu   sync.Mutex
	seen map[string][]string
	hold map[string]chan struct{}
	// taken, when set for a sandbox, is closed once its held event reaches
	// the handler, so a test can wait for the worker to hold it.
	taken map[string]chan struct{}
}

func (r *recordedEvents) handle(_ context.Context, ev docker.DockerEvent) {
	r.mu.Lock()
	gate := r.hold[ev.SandboxID]
	delete(r.hold, ev.SandboxID)
	taken := r.taken[ev.SandboxID]
	delete(r.taken, ev.SandboxID)
	r.mu.Unlock()
	if taken != nil {
		close(taken)
	}
	if gate != nil {
		<-gate
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.seen[ev.SandboxID] = append(r.seen[ev.SandboxID], fmt.Sprintf("%s:%d", ev.Action, ev.ExitCode))
}

func (r *recordedEvents) of(id string) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.seen[id])
}

// TestSandboxEventQueuesOrderFoldAndBound: each sandbox's events run in
// order; a held sandbox holds up only its own; a burst of OOM kills takes
// one entry and every kill is still handled; a full queue drops its oldest
// pending entry and the add returns at once.
func TestSandboxEventQueuesOrderFoldAndBound(t *testing.T) {
	ctx := context.Background()
	gate := make(chan struct{})
	rec := &recordedEvents{seen: map[string][]string{}, hold: map[string]chan struct{}{"a": gate}}
	q := newSandboxEventQueues(ctx, 4, rec.handle)
	ev := func(id, action string, code int) docker.DockerEvent {
		return docker.DockerEvent{SandboxID: id, ContainerID: "ctr-" + id, Action: action, ExitCode: code}
	}
	mustAdd := func(e docker.DockerEvent) {
		t.Helper()
		if !q.add(ctx, e) {
			t.Fatalf("add %v refused", e)
		}
	}

	mustAdd(ev("a", "die", 1)) // its worker takes it and is held
	deadline := time.Now().Add(2 * time.Second)
	for q.pending("a") != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	for i := 0; i < 5; i++ {
		mustAdd(ev("a", "oom", 0))
	}
	mustAdd(ev("a", "start", 0))
	mustAdd(ev("a", "die", 2))
	mustAdd(ev("a", "stop", 0))
	if n := q.pending("a"); n != 4 {
		t.Fatalf("pending for a = %d, want 4 (five OOM kills in one entry)", n)
	}

	// Another sandbox is not held up.
	for i := 0; i < 3; i++ {
		mustAdd(ev("b", "die", i))
	}
	deadline = time.Now().Add(2 * time.Second)
	for len(rec.of("b")) < 3 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := rec.of("b"); !slices.Equal(got, []string{"die:0", "die:1", "die:2"}) {
		t.Fatalf("b while a is held: %v", got)
	}

	// a's queue is full: an add for a does not wait. It drops the oldest
	// pending entry (the five folded OOM kills) and is counted and reported.
	var droppedAction string
	var droppedTimes int
	q.dropped = func(e docker.DockerEvent, times int) { droppedAction, droppedTimes = e.Action, times }
	before := sandboxEventsDropped.Value()
	gaveUp, cancel := context.WithCancel(ctx)
	cancel()
	if q.add(gaveUp, ev("a", "start", 9)) {
		t.Fatal("an add with a done context was taken")
	}
	added := make(chan bool, 1)
	go func() { added <- q.add(ctx, ev("a", "start", 0)) }()
	select {
	case ok := <-added:
		if !ok {
			t.Fatal("an add to a full queue was refused")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("an add to a full queue waited")
	}
	if droppedAction != "oom" || droppedTimes != 5 || sandboxEventsDropped.Value()-before != 5 {
		t.Fatalf("dropped %q x%d (counter +%d), want the oldest entry: oom x5", droppedAction, droppedTimes, sandboxEventsDropped.Value()-before)
	}
	if n := q.pending("a"); n != 4 {
		t.Fatalf("pending for a = %d, want the limit 4", n)
	}

	close(gate)
	q.wait()
	want := []string{"die:1", "start:0", "die:2", "stop:0", "start:0"}
	if got := rec.of("a"); !slices.Equal(got, want) {
		t.Fatalf("a handled %v, want %v", got, want)
	}
	q.mu.Lock()
	left := len(q.queues)
	q.mu.Unlock()
	if left != 0 {
		t.Fatalf("%d queues left after every event was handled", left)
	}
}

// TestSandboxEventQueuesStopWithTheirContext: once the monitor's context
// ends, the workers stop, a waiting add gives up, and feeding stops.
func TestSandboxEventQueuesStopWithTheirContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	gate := make(chan struct{})
	rec := &recordedEvents{seen: map[string][]string{}, hold: map[string]chan struct{}{"a": gate}}
	q := newSandboxEventQueues(ctx, 1, rec.handle)
	e := docker.DockerEvent{SandboxID: "a", Action: "die"}
	q.add(context.Background(), e)
	deadline := time.Now().Add(2 * time.Second)
	for q.pending("a") != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	q.add(context.Background(), docker.DockerEvent{SandboxID: "a", Action: "start"}) // fills it

	svc := &Service{}
	events := make(chan docker.DockerEvent, 1)
	events <- docker.DockerEvent{SandboxID: "a", Action: "stop"}
	fed := make(chan struct{})
	go func() {
		svc.feedEvents(context.Background(), events, q) // a is full: drops its oldest, then waits for more events
		close(fed)
	}()
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case <-fed:
	case <-time.After(2 * time.Second):
		t.Fatal("feeding did not stop with the queues' context")
	}
	close(gate)
	q.wait()
	if got := rec.of("a"); !slices.Equal(got, []string{"die:0"}) {
		t.Fatalf("handled after the context ended: %v", got)
	}
}

// TestFeedEventsNeverWaitsForOneFullSandbox: one sandbox held by a long step
// with a full queue must not hold up the stream loop. Before, the loop
// waited for room in that queue, and every other sandbox's events waited
// with it (up to restartStartTimeout).
func TestFeedEventsNeverWaitsForOneFullSandbox(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	gate := make(chan struct{})
	busyTaken := make(chan struct{})
	rec := &recordedEvents{seen: map[string][]string{}, hold: map[string]chan struct{}{"busy": gate},
		taken: map[string]chan struct{}{"busy": busyTaken}}
	q := newSandboxEventQueues(ctx, 2, rec.handle)
	events := make(chan docker.DockerEvent) // unbuffered: each send is taken by the loop
	fed := make(chan struct{})
	svc := &Service{}
	go func() {
		svc.feedEvents(ctx, events, q)
		close(fed)
	}()
	send := func(e docker.DockerEvent) {
		t.Helper()
		select {
		case events <- e:
		case <-time.After(2 * time.Second):
			t.Fatalf("the stream loop did not take %s for %s: it is waiting on a full queue", e.Action, e.SandboxID)
		}
	}
	// busy's first event holds its worker (the handler waits on gate);
	// wait until the handler has it, so the queue holds only what comes
	// after. Polling pending("busy") for 0 raced: send returns when the loop
	// receives the event, before it is queued, so 0 could mean "not queued
	// yet" and the burst below then dropped start:0 as the oldest entry.
	send(docker.DockerEvent{SandboxID: "busy", Action: "start", ExitCode: 0})
	select {
	case <-busyTaken:
	case <-time.After(2 * time.Second):
		t.Fatal("busy's first event never reached its handler")
	}
	for i := 1; i < 10; i++ { // far past busy's limit of 2
		send(docker.DockerEvent{SandboxID: "busy", Action: "start", ExitCode: i})
	}
	send(docker.DockerEvent{SandboxID: "other", Action: "die", ExitCode: 7})
	deadline := time.Now().Add(2 * time.Second)
	for len(rec.of("other")) == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := rec.of("other"); !slices.Equal(got, []string{"die:7"}) {
		t.Fatalf("other sandbox while busy is held with a full queue: %v", got)
	}
	close(gate)
	close(events)
	<-fed
	q.wait()
	if got := rec.of("busy"); len(got) != 3 || got[0] != "start:0" || got[2] != "start:9" {
		t.Fatalf("busy handled %v, want its first event and the newest two", got)
	}
}
