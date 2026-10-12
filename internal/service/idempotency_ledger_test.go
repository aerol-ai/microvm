package service

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

// request_idempotency used to grow forever. A claim now triggers at most one
// bounded sweep per interval, which removes only rows a claim would already
// treat as free.
func TestClaimTriggersIdempotencySweep(t *testing.T) {
	ctx := context.Background()
	svc, _ := newFacadeStateTestService(t)
	past := time.Now().Add(-2 * time.Hour)
	if _, _, err := svc.store.ClaimIdempotentRequest(ctx, "s", "stale", past, time.Minute); err != nil {
		t.Fatal(err)
	}

	// A process's first claim only schedules the sweep.
	if _, _, err := svc.ClaimIdempotentRequest(ctx, "s", "first", time.Now(), time.Hour); err != nil {
		t.Fatal(err)
	}
	if next := time.Unix(0, svc.idempotencySweepAt.Load()); time.Until(next) < idempotencySweepInterval/2 {
		t.Fatalf("first claim scheduled the sweep for %v", next)
	}
	if _, err := svc.GetIdempotentRequest(ctx, "s", "stale"); err != nil {
		t.Fatalf("first claim swept at once: %v", err)
	}
	svc.idempotencySweepAt.Store(1) // due
	if _, _, err := svc.ClaimIdempotentRequest(ctx, "s", "fresh", time.Now(), time.Hour); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := svc.GetIdempotentRequest(ctx, "s", "stale"); err != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("expired row survived the claim-triggered sweep")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := svc.GetIdempotentRequest(ctx, "s", "fresh"); err != nil {
		t.Fatalf("live row swept: %v", err)
	}

	// Within the interval no second sweep starts.
	next := svc.idempotencySweepAt.Load()
	svc.maybeSweepIdempotentRequests()
	if svc.idempotencySweepAt.Load() != next {
		t.Fatal("a sweep ran again inside the interval")
	}
}

func TestIdempotencySweepBacklogAndFailure(t *testing.T) {
	ctx := context.Background()
	svc, st := newFacadeStateTestService(t)
	past := time.Now().Add(-2 * time.Hour)
	for i := range idempotencySweepBatch + 1 {
		if _, _, err := st.ClaimIdempotentRequest(ctx, "s", string(rune('a'+i%26))+time.Duration(i).String(), past, time.Minute); err != nil {
			t.Fatal(err)
		}
	}
	// A full batch makes the sweep due again so the next claim continues.
	svc.sweepIdempotentRequests(time.Now())
	if next := svc.idempotencySweepAt.Load(); next == 0 || next > time.Now().UnixNano() {
		t.Fatal("a full batch must let the next claim continue the sweep")
	}
	svc.sweepIdempotentRequests(time.Now())
	rows, err := svc.ListIdempotentRequests(ctx, "s", models.RequestStatePending, "", 0)
	if err != nil || len(rows) != 0 {
		t.Fatalf("rows left after the backlog = %d, %v", len(rows), err)
	}

	// No store: nothing to list.
	if rows, err := (&Service{}).ListIdempotentRequests(ctx, "s", models.RequestStatePending, "", 1); rows != nil || err != nil {
		t.Fatalf("store-less list = %v, %v", rows, err)
	}

	// A store failure is logged, not fatal.
	_ = st.Close()
	svc.sweepIdempotentRequests(time.Now())
	if err := svc.SetIdempotentRequestTarget(ctx, "s", "x", "y"); err == nil {
		t.Fatal("closed store accepted a target write")
	}
}

// Claims that all find the sweep due at once start it once: the CAS lets
// one through, and every other claim returns without waiting on a lock.
func TestIdempotencySweepIsSingleFlight(t *testing.T) {
	svc, _ := newFacadeStateTestService(t)
	svc.idempotencySweepAt.Store(1) // due
	start := make(chan struct{})
	var wg sync.WaitGroup
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			svc.maybeSweepIdempotentRequests()
		}()
	}
	close(start)
	wg.Wait()
	until := time.Until(time.Unix(0, svc.idempotencySweepAt.Load()))
	if until <= 0 || until > idempotencySweepInterval {
		t.Fatalf("next sweep due in %v, want within one interval", until)
	}
}
