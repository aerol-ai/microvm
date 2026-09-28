package service

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	storepkg "github.com/aerol-ai/microvm/internal/store"
)

// newRejoinSweepHarness is a node whose one peer never answers, so every
// obligation stays in its outbox and each attempt is countable.
func newRejoinSweepHarness(t *testing.T) (*Service, *storepkg.Store, *fakePeerPusher, time.Time) {
	t.Helper()
	st := openSealTestStore(t)
	pusher := &fakePeerPusher{
		deleteErr: errors.New("node-b unreachable"),
		pushErr:   errors.New("node-b unreachable"),
	}
	svc := &Service{store: st, cluster: cluster.NewNoop("node-a", "http://a", ""), testSecretPeerPusher: pusher}
	base := time.Now().UTC()
	secretLifecycleNow = func() time.Time { return base }
	t.Cleanup(func() { secretLifecycleNow = time.Now })
	return svc, st, pusher, base
}

func deleteAttempts(p *fakePeerPusher) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.deletes)
}

// A sweep attempts each obligation at most once, however its pass is told to
// ignore the retry schedule. Both shapes below make every row due on every
// page: a clock placed past the backoff cap, and the rejoin override. Pages
// are re-read from the queue, so without a per-pass guard the rows this page
// just attempted come straight back on the next one and a single tick works
// the whole backlog several times over.
func TestSecretOutboxSweepAttemptsEachRowOncePerPass(t *testing.T) {
	// One full page: with fewer rows the sweep stops after a single listing
	// and the amplification never shows.
	const rows = secretDeleteReconcileBatch
	for _, tc := range []struct {
		name string
		pass func(base time.Time) secretOutboxPass
	}{
		{"clock ahead of every backoff", func(base time.Time) secretOutboxPass {
			return secretOutboxPass{now: base.Add(storepkg.SecretOutboxBackoffCap)}
		}},
		{"rejoin override", func(base time.Time) secretOutboxPass {
			return secretOutboxPass{now: base, ignoreBackoff: true}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			svc, st, pusher, base := newRejoinSweepHarness(t)
			for i := range rows {
				if err := st.UpsertSecretDeleteOutbox(ctx, fmt.Sprintf("sb-%05d", i), "inc", []string{"node-b"}, 1); err != nil {
					t.Fatalf("seed outbox row %d: %v", i, err)
				}
			}

			if err := svc.reconcileSecretDeleteOutboxPass(ctx, tc.pass(base)); err != nil {
				t.Fatalf("sweep: %v", err)
			}

			if got := deleteAttempts(pusher); got != rows {
				t.Fatalf("peer delete attempts = %d, want exactly one per obligation (%d)", got, rows)
			}
			if rec := deleteOutboxRow(t, st, "sb-00000", "inc"); rec.Attempts != 1 {
				t.Fatalf("attempts recorded after one pass = %d, want 1", rec.Attempts)
			}
		})
	}
}

// The rejoin override is what buys a returning member its immediate retry: a
// normal pass leaves a backed-off obligation alone, and the override tries it
// once without disturbing the schedule any further.
func TestRejoinPassRetriesBackedOffObligationsExactlyOnce(t *testing.T) {
	ctx := context.Background()
	svc, st, pusher, base := newRejoinSweepHarness(t)

	for _, id := range []string{"sb-fresh", "sb-backed-off"} {
		if err := st.UpsertSecretDeleteOutbox(ctx, id, "inc", []string{"node-b"}, 1); err != nil {
			t.Fatal(err)
		}
	}
	for range 9 {
		if err := st.BumpSecretDeleteOutboxAttempt(ctx, "sb-backed-off", "inc", 1); err != nil {
			t.Fatal(err)
		}
	}
	// A put obligation needs the sealed row it replicates.
	putSecretRow(t, st, "sb-put", "inc", 1, []string{"node-a", "node-b"})
	if err := st.UpsertSecretPutOutbox(ctx, "sb-put", "inc", 1, []string{"node-b"}); err != nil {
		t.Fatal(err)
	}
	for range 9 {
		if err := st.BumpSecretPutOutboxAttempt(ctx, "sb-put", "inc", 1); err != nil {
			t.Fatal(err)
		}
	}

	// Ordinary tick: the capped row is not due, so only the fresh one is tried.
	if err := svc.reconcileSecretDeleteOutboxPass(ctx, secretOutboxPass{now: base}); err != nil {
		t.Fatal(err)
	}
	if err := svc.reconcileSecretPutOutboxPass(ctx, secretOutboxPass{now: base}); err != nil {
		t.Fatal(err)
	}
	if got := deleteAttempts(pusher); got != 1 {
		t.Fatalf("ordinary pass attempts = %d, want 1 (the backed-off row is not due)", got)
	}
	pusher.mu.Lock()
	pushesBefore := pusher.pushCalls
	pusher.mu.Unlock()
	if pushesBefore != 0 {
		t.Fatalf("ordinary pass pushed a backed-off put obligation %d times", pushesBefore)
	}
	if rec := deleteOutboxRow(t, st, "sb-backed-off", "inc"); rec.Attempts != 9 {
		t.Fatalf("backed-off row attempts = %d, want it untouched at 9", rec.Attempts)
	}

	// Rejoin: both obligations get exactly one immediate try.
	if err := svc.reconcileSecretDeleteOutboxPass(ctx, secretOutboxPass{now: base, ignoreBackoff: true}); err != nil {
		t.Fatal(err)
	}
	if err := svc.reconcileSecretPutOutboxPass(ctx, secretOutboxPass{now: base, ignoreBackoff: true}); err != nil {
		t.Fatal(err)
	}
	if got := deleteAttempts(pusher); got != 3 {
		t.Fatalf("attempts after the rejoin pass = %d, want 3 (one more per obligation)", got)
	}
	pusher.mu.Lock()
	pushes := pusher.pushCalls
	pusher.mu.Unlock()
	if pushes != 1 {
		t.Fatalf("put obligations pushed on the rejoin pass = %d, want 1", pushes)
	}
	if rec := deleteOutboxRow(t, st, "sb-backed-off", "inc"); rec.Attempts != 10 {
		t.Fatalf("backed-off row attempts after rejoin = %d, want 10", rec.Attempts)
	}
}
