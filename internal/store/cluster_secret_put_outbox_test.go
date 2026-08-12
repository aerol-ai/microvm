package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestSecretPutOutboxCRUD(t *testing.T) {
	ctx := context.Background()
	st, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	if err := st.UpsertSecretPutOutbox(ctx, "sb-put", "inc-1", 3, []string{"node-b", "node-c"}); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	got, err := st.GetSecretPutOutbox(ctx, "sb-put")
	if err != nil || got == nil {
		t.Fatalf("get: %v %#v", err, got)
	}
	if got.SealGeneration != 3 || got.IncarnationID != "inc-1" || len(got.Recipients) != 2 {
		t.Fatalf("got = %+v", got)
	}
	if err := st.BumpSecretPutOutboxAttempt(ctx, "sb-put", "inc-1", 3); err != nil {
		t.Fatal(err)
	}
	if err := st.UpdateSecretPutOutboxRecipients(ctx, "sb-put", "inc-1", []string{"node-c"}, 3); err != nil {
		t.Fatal(err)
	}
	got, err = st.GetSecretPutOutbox(ctx, "sb-put")
	if err != nil || got == nil || len(got.Recipients) != 1 || got.Recipients[0] != "node-c" || got.Attempts != 1 {
		t.Fatalf("after shrink = %+v err=%v", got, err)
	}
	batch, err := st.ListSecretPutOutboxBatch(ctx, 10)
	if err != nil || len(batch) != 1 {
		t.Fatalf("batch = %v err=%v", batch, err)
	}
	// Stale delete of an older identity must not clear the current job.
	if err := st.DeleteSecretPutOutbox(ctx, "sb-put", "inc-1", 2); err != nil {
		t.Fatal(err)
	}
	if got, err = st.GetSecretPutOutbox(ctx, "sb-put"); err != nil || got == nil {
		t.Fatalf("stale delete cleared outbox: %#v err=%v", got, err)
	}
	if err := st.UpdateSecretPutOutboxRecipients(ctx, "sb-put", "inc-1", nil, 3); err != nil {
		t.Fatal(err)
	}
	if got, err = st.GetSecretPutOutbox(ctx, "sb-put"); err != nil || got != nil {
		t.Fatalf("expected cleared outbox, got %#v err=%v", got, err)
	}
}

func TestPutClusterSecretStaleGeneration(t *testing.T) {
	ctx := context.Background()
	st, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	now := time.Now().UTC()
	ref := "cluster-secret://sandbox/sb-stale/v1"
	if err := st.PutClusterSecret(ctx, ClusterSecretRecord{
		Ref: ref, SandboxID: "sb-stale", Version: 1,
		Recipients: []string{"a"}, SealedPayload: []byte("gen2"),
		SealGeneration: 2, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	err = st.PutClusterSecret(ctx, ClusterSecretRecord{
		Ref: ref, SandboxID: "sb-stale", Version: 1,
		Recipients: []string{"a"}, SealedPayload: []byte("gen1"),
		SealGeneration: 1, CreatedAt: now, UpdatedAt: now,
	})
	if !errors.Is(err, ErrClusterSecretStaleGeneration) {
		t.Fatalf("stale put = %v, want ErrClusterSecretStaleGeneration", err)
	}
	got, err := st.GetClusterSecret(ctx, ref)
	if err != nil {
		t.Fatal(err)
	}
	if got.SealGeneration != 2 || string(got.SealedPayload) != "gen2" {
		t.Fatalf("downgraded row: gen=%d payload=%q", got.SealGeneration, got.SealedPayload)
	}
}

func TestSecretPutOutboxRejectsDowngrade(t *testing.T) {
	ctx := context.Background()
	st, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	if err := st.UpsertSecretPutOutbox(ctx, "sb-put", "inc-2", 5, []string{"node-b"}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSecretPutOutbox(ctx, "sb-put", "inc-1", 4, []string{"node-c"}); err != nil {
		t.Fatal(err)
	}
	got, err := st.GetSecretPutOutbox(ctx, "sb-put")
	if err != nil || got == nil {
		t.Fatalf("get: %v %#v", err, got)
	}
	if got.SealGeneration != 5 || got.IncarnationID != "inc-2" || len(got.Recipients) != 1 || got.Recipients[0] != "node-b" {
		t.Fatalf("downgrade clobbered outbox: %+v", got)
	}
}

func TestPutClusterSecretEqualGenerationPayload(t *testing.T) {
	ctx := context.Background()
	st, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	now := time.Now().UTC()
	ref := "cluster-secret://sandbox/sb-digest/v1"
	rec := ClusterSecretRecord{
		Ref: ref, SandboxID: "sb-digest", Version: 1,
		Recipients: []string{"a"}, SealedPayload: []byte("same"),
		SealGeneration: 2, CreatedAt: now, UpdatedAt: now,
	}
	if err := st.PutClusterSecret(ctx, rec); err != nil {
		t.Fatal(err)
	}
	if err := st.PutClusterSecret(ctx, rec); err != nil {
		t.Fatalf("identical equal-gen put should noop: %v", err)
	}
	rec.SealedPayload = []byte("different")
	if err := st.PutClusterSecret(ctx, rec); !errors.Is(err, ErrClusterSecretPayloadConflict) {
		t.Fatalf("conflict = %v, want ErrClusterSecretPayloadConflict", err)
	}
	got, err := st.GetClusterSecretForSandbox(ctx, "sb-digest")
	if err != nil || string(got.SealedPayload) != "same" {
		t.Fatalf("row mutated on conflict: %+v err=%v", got, err)
	}
}
