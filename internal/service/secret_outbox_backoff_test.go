package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	storepkg "github.com/aerol-ai/microvm/internal/store"
)

// unreadablePlacementsCluster is a cluster whose authoritative placement read
// fails, the condition under which a sweep must defer rows without counting
// an attempt.
type unreadablePlacementsCluster struct {
	*cluster.Noop
}

func (*unreadablePlacementsCluster) AuthoritativePlacementsByIDs(context.Context, []string) (map[string]cluster.Placement, error) {
	return nil, errors.New("placement store unavailable")
}

// A recipient that keeps failing is retried on the schedule, not every tick:
// the second sweep inside the backoff window makes no attempt, the sweep after
// it makes one, and each failure doubles the wait. A member rejoining gets one
// immediate try regardless.
func TestSecretOutboxReconcileBacksOffFailingRecipients(t *testing.T) {
	ctx := context.Background()
	st := openSealTestStore(t)
	pusher := &fakePeerPusher{deleteErr: errors.New("peer-b unreachable"), pushErr: errors.New("peer-b unreachable")}
	svc := &Service{store: st, cluster: cluster.NewNoop("node-a", "http://a", ""), testSecretPeerPusher: pusher}
	base := time.Now().UTC()
	secretLifecycleNow = func() time.Time { return base }
	t.Cleanup(func() { secretLifecycleNow = time.Now })

	if _, err := st.DeleteClusterSecretsOriginatorWithOutbox(ctx, "sb-del", "inc-1", []string{"node-b"}); err != nil {
		t.Fatal(err)
	}
	putSecretRow(t, st, "sb-put", "inc-1", 1, []string{"node-a", "node-b"})
	if err := st.UpsertSecretPutOutbox(ctx, "sb-put", "inc-1", 1, []string{"node-b"}); err != nil {
		t.Fatal(err)
	}
	attempts := func() (deletes, pushes int) {
		pusher.mu.Lock()
		defer pusher.mu.Unlock()
		return len(pusher.deletes), pusher.pushCalls
	}
	sweep := func(now time.Time) {
		t.Helper()
		if err := svc.reconcileSecretDeleteOutboxAt(ctx, now); err != nil {
			t.Fatal(err)
		}
		if err := svc.reconcileSecretPutOutboxAt(ctx, now); err != nil {
			t.Fatal(err)
		}
	}

	sweep(base)
	if d, p := attempts(); d != 1 || p != 1 {
		t.Fatalf("first sweep attempts deletes=%d pushes=%d, want 1/1", d, p)
	}
	rec, _ := st.GetSecretDeleteOutboxForIncarnation(ctx, "sb-del", "inc-1")
	if rec == nil || rec.Attempts != 1 {
		t.Fatalf("delete row after one failure = %+v", rec)
	}
	// Rows are bumped with the wall clock; move the sweep clock relative to that.
	stamped := rec.UpdatedAt
	sweep(stamped.Add(10 * time.Second))
	if d, p := attempts(); d != 1 || p != 1 {
		t.Fatalf("a sweep inside the 30s backoff must not retry: deletes=%d pushes=%d", d, p)
	}
	sweep(stamped.Add(31 * time.Second))
	if d, p := attempts(); d != 2 || p != 2 {
		t.Fatalf("a sweep after the backoff retries once: deletes=%d pushes=%d", d, p)
	}
	rec = deleteOutboxRow(t, st, "sb-del", "inc-1")
	stamped = rec.UpdatedAt
	sweep(stamped.Add(45 * time.Second))
	if d, _ := attempts(); d != 2 {
		t.Fatalf("second failure waits a full minute, got %d attempts after 45s", d)
	}
	sweep(stamped.Add(61 * time.Second))
	if d, _ := attempts(); d != 3 {
		t.Fatalf("retry after the doubled wait, got %d attempts", d)
	}

	// Rejoin: the sweep clock is placed past every backoff.
	rec = deleteOutboxRow(t, st, "sb-del", "inc-1")
	sweep(rec.UpdatedAt.Add(storepkg.SecretOutboxBackoffCap))
	if d, _ := attempts(); d != 4 {
		t.Fatalf("a pass placed past the cap must try every obligation once: %d", d)
	}
	rec = deleteOutboxRow(t, st, "sb-del", "inc-1")
	if rec.Attempts != 4 {
		t.Fatalf("attempts after four failures = %d", rec.Attempts)
	}

	// Once the peer answers, the obligation clears on its next due sweep.
	pusher.mu.Lock()
	pusher.deleteErr, pusher.pushErr, pusher.acked = nil, nil, []string{"node-b"}
	pusher.mu.Unlock()
	sweep(rec.UpdatedAt.Add(storepkg.SecretOutboxBackoffCap + time.Second))
	if rec, _ := st.GetSecretDeleteOutboxForIncarnation(ctx, "sb-del", "inc-1"); rec != nil {
		t.Fatalf("acked delete obligation still present: %+v", rec)
	}
	if rec, _ := st.GetSecretPutOutboxForIncarnation(ctx, "sb-put", "inc-1"); rec != nil {
		t.Fatalf("acked put obligation still present: %+v", rec)
	}
}

// Nothing tried, nothing counted: when the authoritative placement cannot be
// read, rows are moved to the back of the queue but keep attempts 0, so they
// are due again on the very next tick instead of backing off.
func TestSecretOutboxPlacementReadFailureTouchesInsteadOfBackingOff(t *testing.T) {
	ctx := context.Background()
	st := openSealTestStore(t)
	svc := &Service{store: st, cfg: config.Config{EnableCluster: true}, testSecretPeerPusher: &fakePeerPusher{}}
	svc.cluster = &unreadablePlacementsCluster{Noop: cluster.NewNoop("node-a", "http://a", "")}

	putSecretRow(t, st, "sb-put", "inc-1", 1, []string{"node-a", "node-b"})
	if err := st.UpsertSecretPutOutbox(ctx, "sb-put", "inc-1", 1, []string{"node-b"}); err != nil {
		t.Fatal(err)
	}
	if err := svc.reconcileSecretPutOutboxAt(ctx, time.Now().UTC()); err == nil {
		t.Fatal("placement read failure must surface from the sweep")
	}
	rec, err := st.GetSecretPutOutboxForIncarnation(ctx, "sb-put", "inc-1")
	if err != nil || rec == nil || rec.Attempts != 0 {
		t.Fatalf("put row after placement failure = %+v err=%v, want attempts 0 (touched)", rec, err)
	}
	// The single-row path behaves the same.
	svc.reconcileSecretPutOutboxIncarnation(ctx, "sb-put", "inc-1")
	rec, _ = st.GetSecretPutOutboxForIncarnation(ctx, "sb-put", "inc-1")
	if rec == nil || rec.Attempts != 0 {
		t.Fatalf("single-row placement failure counted an attempt: %+v", rec)
	}
}

func deleteOutboxRow(t *testing.T, st *storepkg.Store, sandboxID, incarnationID string) *storepkg.SecretDeleteOutboxRecord {
	t.Helper()
	rec, err := st.GetSecretDeleteOutboxForIncarnation(context.Background(), sandboxID, incarnationID)
	if err != nil || rec == nil {
		t.Fatalf("delete outbox row %s/%s = %+v err=%v", sandboxID, incarnationID, rec, err)
	}
	return rec
}
