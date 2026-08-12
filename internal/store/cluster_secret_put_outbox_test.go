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
	if err := st.BumpSecretPutOutboxAttempt(ctx, "sb-put"); err != nil {
		t.Fatal(err)
	}
	if err := st.UpdateSecretPutOutboxRecipients(ctx, "sb-put", []string{"node-c"}, 3); err != nil {
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
	if err := st.UpdateSecretPutOutboxRecipients(ctx, "sb-put", nil, 3); err != nil {
		t.Fatal(err)
	}
	if got, err = st.GetSecretPutOutbox(ctx, "sb-put"); err != nil || got != nil {
		t.Fatalf("expected cleared outbox, got %#v err=%v", got, err)
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
