package kubeview

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
)

func row(id, owner string, version uint64) cluster.Placement {
	return cluster.Placement{SandboxID: id, OwnerRef: owner, OwnerNodeID: "w1", Version: version}
}

func upsert(p cluster.Placement, index uint64) cluster.PlacementChange {
	return cluster.PlacementChange{SandboxID: p.SandboxID, Index: index, Placement: &p}
}

func del(p cluster.Placement, index uint64) cluster.PlacementChange {
	return cluster.PlacementChange{SandboxID: p.SandboxID, Index: index, Deleted: true, Placement: &p}
}

func readyHub(t *testing.T, opts Options, rows ...cluster.Placement) *Hub {
	t.Helper()
	h := New(opts)
	h.Apply(cluster.PlacementFeedEvent{View: true, Full: rows, Next: 10})
	return h
}

// next reads one event, or fails after a second.
func next(t *testing.T, ch <-chan Event) Event {
	t.Helper()
	select {
	case ev, ok := <-ch:
		if !ok {
			t.Fatal("the watch ended")
		}
		return ev
	case <-time.After(time.Second):
		t.Fatal("no event")
	}
	return Event{}
}

func TestHubNotReadyUntilAView(t *testing.T) {
	h := New(Options{})
	if _, err := h.Position(); !errors.Is(err, ErrNotReady) {
		t.Fatalf("Position = %v", err)
	}
	if _, _, _, err := h.List("team:a", "", 0); !errors.Is(err, ErrNotReady) {
		t.Fatalf("List = %v", err)
	}
	if _, _, err := h.Get("team:a", "sb1"); !errors.Is(err, ErrNotReady) {
		t.Fatalf("Get = %v", err)
	}
	if _, err := h.Watch(context.Background(), "team:a", 0); !errors.Is(err, ErrNotReady) {
		t.Fatalf("Watch = %v", err)
	}
	if _, err := h.Owners(); !errors.Is(err, ErrNotReady) {
		t.Fatalf("Owners = %v", err)
	}
	// Deltas before the first view are not a view.
	h.Apply(cluster.PlacementFeedEvent{Changes: []cluster.PlacementChange{upsert(row("sb1", "team:a", 5), 5)}, Next: 5})
	if _, err := h.Position(); !errors.Is(err, ErrNotReady) {
		t.Fatal("ready from deltas alone")
	}
}

func TestHubListGetAndOwners(t *testing.T) {
	reserved := row("sb-r", "team:a", 3)
	reserved.State = cluster.PlacementStateReserved
	h := readyHub(t, Options{}, row("sb2", "team:a", 4), row("sb1", "team:a", 3), row("sb3", "team:b", 5), reserved, row("sb-op", "", 6))
	items, rv, more, err := h.List("team:a", "", 0)
	if err != nil || rv != 10 || more || len(items) != 2 || items[0].Placement.SandboxID != "sb1" || items[1].Placement.SandboxID != "sb2" {
		t.Fatalf("List = %+v %d %v %v", items, rv, more, err)
	}
	page, _, more, _ := h.List("team:a", "", 1)
	if len(page) != 1 || !more {
		t.Fatalf("first page = %+v more=%v", page, more)
	}
	page, _, more, _ = h.List("team:a", page[0].Placement.SandboxID, 1)
	if len(page) != 1 || page[0].Placement.SandboxID != "sb2" || more {
		t.Fatalf("second page = %+v more=%v", page, more)
	}
	if it, ok, err := h.Get("team:a", "sb2"); err != nil || !ok || it.RV != 4 {
		t.Fatalf("Get = %+v %v %v", it, ok, err)
	}
	if _, ok, _ := h.Get("team:b", "sb2"); ok {
		t.Fatal("another owner's sandbox")
	}
	if _, ok, _ := h.Get("team:a", "sb-r"); ok {
		t.Fatal("a reservation is shown")
	}
	owners, err := h.Owners()
	if err != nil || fmt.Sprint(owners) != "[team:a team:b]" {
		t.Fatalf("Owners = %v %v", owners, err)
	}
}

// A row's resourceVersion is the later of its Version and its run state.
func TestItemRV(t *testing.T) {
	if got := ItemRV(cluster.Placement{Version: 5, RunStateIndex: 9}); got != 9 {
		t.Fatalf("ItemRV = %d", got)
	}
	if got := ItemRV(cluster.Placement{Version: 12, RunStateIndex: 9}); got != 12 {
		t.Fatalf("ItemRV = %d", got)
	}
}

func TestHubLiveEvents(t *testing.T) {
	h := readyHub(t, Options{}, row("sb1", "team:a", 3))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch, err := h.Watch(ctx, "team:a", 10)
	if err != nil {
		t.Fatal(err)
	}
	stopped := row("sb1", "team:a", 3)
	stopped.RunState, stopped.RunStateIndex = cluster.RunStateSuspended, 12
	h.Apply(cluster.PlacementFeedEvent{Changes: []cluster.PlacementChange{
		upsert(row("sb2", "team:a", 11), 11),
		upsert(row("sb9", "team:b", 11), 11), // another owner's
		upsert(stopped, 12),
	}, Next: 12})
	if ev := next(t, ch); ev.Type != Added || ev.Item.Placement.SandboxID != "sb2" || ev.Item.RV != 11 {
		t.Fatalf("event = %+v", ev)
	}
	if ev := next(t, ch); ev.Type != Modified || ev.Item.Placement.RunState != cluster.RunStateSuspended || ev.Item.RV != 12 {
		t.Fatalf("event = %+v", ev)
	}
	// Moving to another owner leaves this namespace.
	moved := row("sb2", "team:b", 13)
	h.Apply(cluster.PlacementFeedEvent{Changes: []cluster.PlacementChange{upsert(moved, 13)}, Next: 13})
	if ev := next(t, ch); ev.Type != Deleted || ev.Item.Placement.SandboxID != "sb2" {
		t.Fatalf("event = %+v", ev)
	}
	h.Apply(cluster.PlacementFeedEvent{Changes: []cluster.PlacementChange{del(row("sb1", "team:a", 3), 14)}, Next: 14})
	if ev := next(t, ch); ev.Type != Deleted || ev.Item.Placement.SandboxID != "sb1" || ev.Item.RV != 14 {
		t.Fatalf("event = %+v", ev)
	}
	// A delete of an unknown row, or one turning into a reservation, is ignored or a delete.
	h.Apply(cluster.PlacementFeedEvent{Changes: []cluster.PlacementChange{del(row("sb-x", "team:a", 1), 15)}, Next: 15})
	cancel()
	for range ch {
	}
}

// A watch from an older position gets each sandbox the owner changed since,
// at its current state, before live events.
func TestHubResume(t *testing.T) {
	h := readyHub(t, Options{}, row("sb1", "team:a", 3), row("sb2", "team:a", 4))
	h.Apply(cluster.PlacementFeedEvent{Changes: []cluster.PlacementChange{upsert(row("sb1", "team:a", 11), 11)}, Next: 11})
	h.Apply(cluster.PlacementFeedEvent{Changes: []cluster.PlacementChange{upsert(row("sb3", "team:a", 12), 12)}, Next: 12})
	h.Apply(cluster.PlacementFeedEvent{Changes: []cluster.PlacementChange{del(row("sb2", "team:a", 4), 13)}, Next: 13})
	h.Apply(cluster.PlacementFeedEvent{Changes: []cluster.PlacementChange{upsert(row("sb4", "team:a", 14), 14)}, Next: 14})
	h.Apply(cluster.PlacementFeedEvent{Changes: []cluster.PlacementChange{del(row("sb4", "team:a", 14), 15)}, Next: 15})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ch, err := h.Watch(ctx, "team:a", 10)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"MODIFIED sb1 11", "ADDED sb3 12", "DELETED sb2 13"} // sb4 came and went: nothing
	for _, w := range want {
		ev := next(t, ch)
		if got := fmt.Sprintf("%s %s %d", ev.Type, ev.Item.Placement.SandboxID, ev.Item.RV); got != w {
			t.Fatalf("event = %s, want %s", got, w)
		}
	}
	h.Apply(cluster.PlacementFeedEvent{Changes: []cluster.PlacementChange{upsert(row("sb5", "team:a", 16), 16)}, Next: 16})
	if ev := next(t, ch); ev.Item.Placement.SandboxID != "sb5" {
		t.Fatalf("live after the backlog = %+v", ev)
	}

	// From 0: every current sandbox as Added.
	all, err := h.Watch(ctx, "team:a", 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"sb1", "sb3", "sb5"} {
		if ev := next(t, all); ev.Type != Added || ev.Item.Placement.SandboxID != id {
			t.Fatalf("from 0 = %+v, want %s", ev, id)
		}
	}
	// Then the end of the initial list, at the position it was read at.
	if ev, pos := next(t, all), h.position; ev.Type != Bookmark || ev.RV != pos {
		t.Fatalf("after the replay = %+v, want a Bookmark at %d", ev, pos)
	}
	// A watch from a version replays changes only: no such marker.
	h.Apply(cluster.PlacementFeedEvent{Changes: []cluster.PlacementChange{upsert(row("sb5", "team:a", 17), 17)}, Next: 17})
	if ev := next(t, ch); ev.Type != Modified {
		t.Fatalf("a watch from a version = %+v", ev)
	}
}

func TestHubExpiredAndTooNew(t *testing.T) {
	h := readyHub(t, Options{RingSize: 2, TooNewWait: 50 * time.Millisecond}, row("sb1", "team:a", 3))
	ctx := context.Background()
	if _, err := h.Watch(ctx, "team:a", 9); !errors.Is(err, ErrExpired) {
		t.Fatalf("before the ring's start: %v", err)
	}
	for i := uint64(11); i <= 13; i++ {
		h.Apply(cluster.PlacementFeedEvent{Changes: []cluster.PlacementChange{upsert(row("sb1", "team:a", i), i)}, Next: i})
	}
	// The ring holds 12 and 13 now: 10 is no longer covered.
	if _, err := h.Watch(ctx, "team:a", 10); !errors.Is(err, ErrExpired) {
		t.Fatalf("past the ring: %v", err)
	}
	if _, err := h.Watch(ctx, "team:a", 99); !errors.Is(err, ErrTooNew) {
		t.Fatalf("ahead of the view: %v", err)
	}
	// Ahead, then the view catches up within the wait.
	h2 := readyHub(t, Options{TooNewWait: 2 * time.Second})
	go func() {
		time.Sleep(20 * time.Millisecond)
		h2.Apply(cluster.PlacementFeedEvent{Next: 12})
	}()
	if _, err := h2.Watch(ctx, "team:a", 12); err != nil {
		t.Fatalf("a view that caught up: %v", err)
	}
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := h2.Watch(cctx, "team:a", 99); !errors.Is(err, context.Canceled) {
		t.Fatalf("a cancelled wait: %v", err)
	}
}

// A resync, or the real view back after the in-flux one, ends every watch:
// what changed in between is unknown.
func TestHubResyncAndInFlux(t *testing.T) {
	h := readyHub(t, Options{}, row("sb1", "team:a", 3))
	ctx := context.Background()
	ch, err := h.Watch(ctx, "team:a", 10)
	if err != nil {
		t.Fatal(err)
	}
	h.Apply(cluster.PlacementFeedEvent{View: true, Full: []cluster.Placement{row("sb1", "team:a", 3)}, Next: 20, InFlux: true})
	if _, err := h.Position(); !errors.Is(err, ErrNotReady) {
		t.Fatalf("in flux: %v", err)
	}
	h.Apply(cluster.PlacementFeedEvent{View: true, Full: []cluster.Placement{row("sb2", "team:a", 21)}, Next: 21})
	if ev := next(t, ch); ev.Type != Closed || !errors.Is(ev.Err, ErrExpired) {
		t.Fatalf("after a resync = %+v", ev)
	}
	if _, ok := <-ch; ok {
		t.Fatal("the watch did not end")
	}
	if _, err := h.Watch(ctx, "team:a", 20); !errors.Is(err, ErrExpired) {
		t.Fatalf("a position before the resync: %v", err)
	}
	items, rv, _, err := h.List("team:a", "", 0)
	if err != nil || rv != 21 || len(items) != 1 || items[0].Placement.SandboxID != "sb2" {
		t.Fatalf("after the resync = %+v %d %v", items, rv, err)
	}
}

// A watcher too slow to take its events is ended, not silently skipped.
func TestHubSlowWatcherIsEnded(t *testing.T) {
	h := readyHub(t, Options{WatchBuffer: 1})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch, err := h.Watch(ctx, "team:a", 10)
	if err != nil {
		t.Fatal(err)
	}
	// The stream goroutine may take one event into its hands; flood past it.
	for i := uint64(11); i < 20; i++ {
		h.Apply(cluster.PlacementFeedEvent{Changes: []cluster.PlacementChange{upsert(row(fmt.Sprintf("sb%d", i), "team:a", i), i)}, Next: i})
	}
	deadline := time.After(2 * time.Second)
	for {
		select {
		case _, ok := <-ch:
			if !ok {
				h.mu.Lock()
				n := len(h.watchers)
				h.mu.Unlock()
				if n != 0 {
					t.Fatalf("%d watchers left", n)
				}
				return
			}
		case <-deadline:
			t.Fatal("a slow watcher was never ended")
		}
	}
}

// Cancelling a watch removes it.
func TestHubWatchCancel(t *testing.T) {
	h := readyHub(t, Options{})
	ctx, cancel := context.WithCancel(context.Background())
	ch, err := h.Watch(ctx, "team:a", 10)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	for range ch {
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.watchers) != 0 {
		t.Fatalf("%d watchers left", len(h.watchers))
	}
}

type fakeFeed struct{ events []cluster.PlacementFeedEvent }

func (f *fakeFeed) WatchPlacementFeed(_ context.Context, fn cluster.PlacementFeedHandler) bool {
	for _, ev := range f.events {
		fn(ev)
	}
	return true
}

func TestHubFollow(t *testing.T) {
	h := New(Options{})
	if !h.Follow(context.Background(), &fakeFeed{events: []cluster.PlacementFeedEvent{{View: true, Full: []cluster.Placement{row("sb1", "team:a", 3)}, Next: 7}}}) {
		t.Fatal("Follow refused")
	}
	if rv, err := h.Position(); err != nil || rv != 7 {
		t.Fatalf("Position = %d %v", rv, err)
	}
}

// An empty cluster's view (no rows at all) still makes the hub ready.
func TestHubReadyOnAnEmptyView(t *testing.T) {
	h := New(Options{})
	h.Apply(cluster.PlacementFeedEvent{View: true, Next: 4})
	if rv, err := h.Position(); err != nil || rv != 4 {
		t.Fatalf("Position = %d %v", rv, err)
	}
}

// AllOwners watches every owner at once: the backlog and live events of
// each.
func TestHubWatchAllOwners(t *testing.T) {
	h := readyHub(t, Options{}, row("sb1", "team:a", 3), row("sb2", "team:b", 4))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	all, err := h.Watch(ctx, AllOwners, 0)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	got[next(t, all).Item.Placement.SandboxID] = true
	got[next(t, all).Item.Placement.SandboxID] = true
	if !got["sb1"] || !got["sb2"] {
		t.Fatalf("backlog = %v", got)
	}
	if ev := next(t, all); ev.Type != Bookmark {
		t.Fatalf("after the backlog = %+v, want its end", ev)
	}
	h.Apply(cluster.PlacementFeedEvent{Changes: []cluster.PlacementChange{upsert(row("sb3", "team:c", 11), 11)}, Next: 11})
	if ev := next(t, all); ev.Item.Placement.SandboxID != "sb3" {
		t.Fatalf("live = %+v", ev)
	}
	resumed, err := h.Watch(ctx, AllOwners, 10)
	if err != nil {
		t.Fatal(err)
	}
	if ev := next(t, resumed); ev.Type != Added || ev.Item.Placement.SandboxID != "sb3" {
		t.Fatalf("resumed = %+v", ev)
	}
}
