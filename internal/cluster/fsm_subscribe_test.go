package cluster

import (
	"sync"
	"testing"
)

// TestSubscribeCancelRacesNotify: Apply calls notifySubscribers after
// releasing the FSM lock, so the fan-out walks a snapshot of the subscriber
// list while watchers subscribe and cancel. Cancel used to remove a
// subscriber by compacting that list in place, writing into the same array a
// running fan-out was reading; CI caught it under -race in
// TestClusterWatchPlacementChanges. Run with -race: the old code fails here.
func TestSubscribeCancelRacesNotify(t *testing.T) {
	fsm := newPlacementFSM()

	// Long-lived subscribers keep the list non-empty, so every fan-out walks
	// an array that the churning goroutines below compact around.
	for range 4 {
		cancel := fsm.subscribe(make(chan struct{}, 1))
		t.Cleanup(cancel)
	}

	stop := make(chan struct{})
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				cancel := fsm.subscribe(make(chan struct{}, 1))
				cancel()
			}
		}()
	}
	for range 2000 {
		fsm.notifySubscribers()
	}
	close(stop)
	wg.Wait()
}

// TestSubscribeCancelKeepsOthersSubscribed pins the list bookkeeping the
// copy-on-write change rewrote: cancelling one subscriber removes exactly
// that one, a second cancel is a no-op, and the rest still get signalled.
func TestSubscribeCancelKeepsOthersSubscribed(t *testing.T) {
	fsm := newPlacementFSM()
	a, b, c := make(chan struct{}, 1), make(chan struct{}, 1), make(chan struct{}, 1)
	cancelA := fsm.subscribe(a)
	cancelB := fsm.subscribe(b)
	cancelC := fsm.subscribe(c)
	defer cancelA()
	defer cancelC()

	cancelB()
	cancelB()
	fsm.notifySubscribers()

	for name, ch := range map[string]chan struct{}{"a": a, "c": c} {
		select {
		case <-ch:
		default:
			t.Fatalf("subscriber %s was not signalled after another subscriber cancelled", name)
		}
	}
	select {
	case <-b:
		t.Fatal("a cancelled subscriber was still signalled")
	default:
	}
	fsm.subMu.Lock()
	n := len(fsm.subscribers)
	fsm.subMu.Unlock()
	if n != 2 {
		t.Fatalf("subscribers = %d, want 2", n)
	}
}
