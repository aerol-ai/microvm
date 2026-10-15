package service

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	storepkg "github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
)

// A recorded tombstone round-trips, is scoped to its owner, and lapses past
// the replay window (D6).
func TestDeletedSandboxViewRecordAndGet(t *testing.T) {
	ctx := context.Background()
	svc, st := newFacadeStateTestService(t)

	if err := svc.RecordDeletedSandboxView(ctx, "sb-gone", models.FacadeRunloop, "acme", `{"id":"sb-gone"}`); err != nil {
		t.Fatalf("record: %v", err)
	}

	// The owner reads it back.
	if blob, ok, err := svc.GetDeletedSandboxView(userCtx("acme"), "sb-gone", models.FacadeRunloop); err != nil || !ok || blob != `{"id":"sb-gone"}` {
		t.Fatalf("owner get = %q ok=%v err=%v", blob, ok, err)
	}
	// The operator reads it back.
	if _, ok, err := svc.GetDeletedSandboxView(operatorCtx(), "sb-gone", models.FacadeRunloop); err != nil || !ok {
		t.Fatalf("operator get ok=%v err=%v", ok, err)
	}
	// A different tenant does not see it.
	if _, ok, err := svc.GetDeletedSandboxView(userCtx("globex"), "sb-gone", models.FacadeRunloop); err != nil || ok {
		t.Fatalf("cross-owner get ok=%v err=%v, want not found", ok, err)
	}
	// An unknown id has none.
	if _, ok, err := svc.GetDeletedSandboxView(ctx, "nope", models.FacadeRunloop); err != nil || ok {
		t.Fatalf("unknown get ok=%v err=%v", ok, err)
	}

	// A tombstone past the replay window is not returned (the sweep removes it).
	old := time.Now().Add(-deletedViewRetention - time.Minute)
	if err := st.PutDeletedSandboxView(ctx, "sb-old", models.FacadeRunloop, "acme", `{"id":"sb-old"}`, old); err != nil {
		t.Fatalf("put old: %v", err)
	}
	if _, ok, err := svc.GetDeletedSandboxView(userCtx("acme"), "sb-old", models.FacadeRunloop); err != nil || ok {
		t.Fatalf("expired get ok=%v err=%v, want not found", ok, err)
	}
}

// A store error that is not "no row" propagates (it is not swallowed as a
// missing tombstone).
func TestGetDeletedSandboxViewStoreError(t *testing.T) {
	st, err := storepkg.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	svc := &Service{store: st}
	st.Close() // force a query error that is not ErrNotFound
	if _, ok, err := svc.GetDeletedSandboxView(userCtx("acme"), "x", models.FacadeRunloop); err == nil || ok {
		t.Fatalf("closed-store get = ok %v err %v, want a propagated error", ok, err)
	}
}

// A nil service / unwired store is a safe no-op, not a panic (embedded wiring).
func TestDeletedSandboxViewNilSafe(t *testing.T) {
	var svc *Service
	if _, ok, err := svc.GetDeletedSandboxView(context.Background(), "x", models.FacadeRunloop); ok || err != nil {
		t.Fatalf("nil service get ok=%v err=%v", ok, err)
	}
	if err := svc.RecordDeletedSandboxView(context.Background(), "x", models.FacadeRunloop, "", "{}"); err != nil {
		t.Fatalf("nil service record err=%v", err)
	}
}

// The idempotency sweep also collects expired tombstones on the same pass.
func TestSweepCollectsExpiredTombstones(t *testing.T) {
	ctx := context.Background()
	svc, st := newFacadeStateTestService(t)

	old := time.Now().Add(-deletedViewRetention - time.Minute)
	if err := st.PutDeletedSandboxView(ctx, "sb-expired", models.FacadeRunloop, "acme", `{}`, old); err != nil {
		t.Fatalf("put expired: %v", err)
	}
	if err := svc.RecordDeletedSandboxView(ctx, "sb-fresh", models.FacadeRunloop, "acme", `{}`); err != nil {
		t.Fatalf("put fresh: %v", err)
	}

	svc.sweepIdempotentRequests(time.Now())

	if _, err := st.GetDeletedSandboxView(ctx, "sb-expired", models.FacadeRunloop); err == nil {
		t.Fatal("sweep left the expired tombstone")
	}
	if _, err := st.GetDeletedSandboxView(ctx, "sb-fresh", models.FacadeRunloop); err != nil {
		t.Fatalf("sweep removed the fresh tombstone: %v", err)
	}
}
