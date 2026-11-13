package cluster

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
)

// feedEvents collects a WatchPlacementFeed consumer's events.
type feedEvents struct {
	mu     sync.Mutex
	events []PlacementFeedEvent
}

func (e *feedEvents) add(ev PlacementFeedEvent) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.events = append(e.events, ev)
}

func (e *feedEvents) find(match func(PlacementFeedEvent) bool) (PlacementFeedEvent, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, ev := range e.events {
		if match(ev) {
			return ev, true
		}
	}
	return PlacementFeedEvent{}, false
}

func changeFor(ev PlacementFeedEvent, id string) (PlacementChange, bool) {
	for _, ch := range ev.Changes {
		if ch.SandboxID == id {
			return ch, true
		}
	}
	return PlacementChange{}, false
}

// A feed consumer gets each step with its position: the full view, the rows
// that moved (a run-state change at the same Version included), a delete
// with the row as it was, the in-flux view and the way back. Positions never
// go backwards.
func TestWatchPlacementFeedEvents(t *testing.T) {
	oldMin := feedBackoffMin
	feedBackoffMin = 20 * time.Millisecond
	defer func() { feedBackoffMin = oldMin }()
	if (&Agent{}).WatchPlacementFeed(context.Background(), func(PlacementFeedEvent) {}) {
		t.Fatal("a watcher with the feed off")
	}

	srv, cleanup := newTestCluster(t, "srv-feed-events", true, nil)
	defer cleanup()
	waitForLeader(t, srv, 10*time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := srv.applyCommand(ctx, place("sb1", "w1")); err != nil {
		t.Fatal(err)
	}
	var offline atomic.Bool
	agent := newAgentControlPlaneHarness(t, feedControlPlane(srv, nil, &offline), Member{NodeID: "gw-self", Alive: true, Role: config.NodeRoleWorker})
	agent.cfg.IngressProxyRouting = true
	agent.startPlacementFeed()
	defer agent.stopPlacementFeed()
	waitForFeed(t, "the first resync", func() bool {
		rows, ok := agent.feedPlacements(PlacementShardFilter{})
		return ok && len(rows) == 1 && rows[0].SandboxID == "sb1"
	})

	var got feedEvents
	if !agent.WatchPlacementFeed(ctx, got.add) {
		t.Fatal("a watcher refused with the feed on")
	}
	initial, ok := got.find(func(ev PlacementFeedEvent) bool { return ev.View })
	if !ok || initial.Next == 0 || initial.InFlux || len(initial.Full) != 1 {
		t.Fatalf("initial view = %+v", initial)
	}

	if err := srv.applyCommand(ctx, place("sb2", "w1")); err != nil {
		t.Fatal(err)
	}
	waitForFeed(t, "sb2 as a change", func() bool {
		_, ok := got.find(func(ev PlacementFeedEvent) bool { _, ok := changeFor(ev, "sb2"); return ok })
		return ok
	})
	if _, err := srv.SetRunStates(ctx, []RunStateReport{{SandboxID: "sb2", IncarnationID: "inc-sb2", OwnerNodeID: "w1", State: RunStateSuspended}}); err != nil {
		t.Fatal(err)
	}
	waitForFeed(t, "sb2's stop as a change", func() bool {
		_, ok := got.find(func(ev PlacementFeedEvent) bool {
			ch, ok := changeFor(ev, "sb2")
			return ok && ch.Placement != nil && ch.Placement.RunState == RunStateSuspended && ev.Next >= ch.Placement.RunStateIndex
		})
		return ok
	})
	if err := srv.applyCommand(ctx, command{Op: opDelete, SandboxID: "sb1", ExpectedIncarnationID: "inc-sb1"}); err != nil {
		t.Fatal(err)
	}
	waitForFeed(t, "sb1's delete with its row", func() bool {
		_, ok := got.find(func(ev PlacementFeedEvent) bool {
			ch, ok := changeFor(ev, "sb1")
			return ok && ch.Deleted && ch.Placement != nil && ch.Placement.OwnerNodeID == "w1"
		})
		return ok
	})

	// Past the age limit (the control plane cut off) the consumer gets the
	// in-flux view, then the real one when the control plane answers again.
	offline.Store(true)
	f := agent.feed
	f.mu.Lock()
	f.lastAnswered = time.Now().Add(-time.Hour)
	f.mu.Unlock()
	if !agent.checkPlacementFeedAge(f) {
		t.Fatal("no in-flux transition past the age limit")
	}
	if ev, ok := got.find(func(ev PlacementFeedEvent) bool { return ev.InFlux }); !ok || !ev.View || ev.Next == 0 {
		t.Fatalf("in-flux view = %+v (%v)", ev, ok)
	}
	// sb3 lands while the agent is cut off, so the first answer after the
	// cut carries it inside the real view.
	if err := srv.applyCommand(ctx, place("sb3", "w1")); err != nil {
		t.Fatal(err)
	}
	offline.Store(false)
	waitForFeed(t, "the real view back with sb3", func() bool {
		_, ok := got.find(func(ev PlacementFeedEvent) bool {
			if !ev.View || ev.InFlux {
				return false
			}
			for _, p := range ev.Full {
				if p.SandboxID == "sb3" {
					return true
				}
			}
			return false
		})
		return ok
	})

	got.mu.Lock()
	defer got.mu.Unlock()
	var last uint64
	for i, ev := range got.events {
		if ev.Next < last {
			t.Fatalf("event %d moved the position back: %d after %d", i, ev.Next, last)
		}
		last = ev.Next
	}
}

// A consumer that registers before the first sync gets no initial view; one
// that registers past the age limit gets the in-flux view.
func TestPlacementFeedView(t *testing.T) {
	now := time.Unix(1000, 0)
	clock := func() time.Time { return now }
	if _, ok := (&agentPlacementFeed{clock: clock}).view(); ok {
		t.Fatal("a view before the first sync")
	}
	row := Placement{SandboxID: "sb1", OwnerNodeID: "w1", OwnerAPIURL: "http://w1", Spec: nil}
	stale := &agentPlacementFeed{rows: map[string]Placement{"sb1": row}, synced: true, cursor: 7,
		lastAnswered: now.Add(-time.Minute), maxStale: time.Second, clock: clock}
	ev, ok := stale.view()
	if !ok || !ev.View || !ev.InFlux || ev.Next != 7 || len(ev.Full) != 1 {
		t.Fatalf("stale view = %+v (%v)", ev, ok)
	}
	if want := staleViewPlacement(row); ev.Full[0].OwnerAPIURL != want.OwnerAPIURL {
		t.Fatalf("stale row = %+v, want %+v", ev.Full[0], want)
	}
}

// The route responder (WatchPlacementChanges) is called exactly as before:
// for every view, an empty one included, and for every change; never for a
// position-only event.
func TestNotifyWatchersKeepsTheLegacyCalls(t *testing.T) {
	var calls []string
	f := &agentPlacementFeed{watchers: map[int]PlacementChangeHandler{0: func(full []Placement, changes []PlacementChange) {
		calls = append(calls, fmt.Sprintf("full=%v changes=%d", full != nil, len(changes)))
	}}}
	f.notifyWatchers(PlacementFeedEvent{View: true, Next: 3}, nil)
	f.notifyWatchers(PlacementFeedEvent{Next: 4}, nil)
	f.notifyWatchers(PlacementFeedEvent{Changes: []PlacementChange{{SandboxID: "sb1"}}, Next: 5}, []PlacementChange{{SandboxID: "sb1"}, {SandboxID: "sb2"}})
	if got := fmt.Sprint(calls); got != "[full=false changes=0 full=false changes=2]" {
		t.Fatalf("legacy calls = %s", got)
	}
}
