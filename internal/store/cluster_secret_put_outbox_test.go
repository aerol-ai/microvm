package store

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
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

func TestPutClusterSecretJournalsPutOutboxAtomically(t *testing.T) {
	ctx := context.Background()
	st, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	now := time.Now().UTC()
	peers := []string{"node-b", "node-c"}
	gen, err := st.PutClusterSecret(ctx, ClusterSecretRecord{
		Ref: "cluster-secret://sandbox/sb-atomic/v1", SandboxID: "sb-atomic", Version: 1,
		Recipients: []string{"node-a", "node-b", "node-c"}, SealedPayload: []byte("sealed"),
		SealGeneration: 1, CreatedAt: now, UpdatedAt: now,
		PutOutboxIncarnationID: "inc-a",
		PutOutboxRecipients:    &peers,
	})
	if err != nil || gen != 1 {
		t.Fatalf("put: gen=%d err=%v", gen, err)
	}
	got, err := st.GetSecretPutOutbox(ctx, "sb-atomic")
	if err != nil || got == nil {
		t.Fatalf("expected outbox with sealed row, got %#v err=%v", got, err)
	}
	if got.IncarnationID != "inc-a" || got.SealGeneration != 1 || len(got.Recipients) != 2 {
		t.Fatalf("outbox = %+v", got)
	}

	// A newer put clears its PUT journal but must preserve any independent
	// delete obligations; peer deletion is generation-fenced.
	if _, err := st.PutClusterSecret(ctx, ClusterSecretRecord{
		Ref: "cluster-secret://sandbox/sb-atomic/v1", SandboxID: "sb-atomic", Version: 1,
		Recipients: []string{"node-a", "node-b", "node-c"}, SealedPayload: []byte("sealed-2"),
		SealGeneration: 2, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if got, err = st.GetSecretPutOutbox(ctx, "sb-atomic"); err != nil || got != nil {
		t.Fatalf("peer put should clear outbox, got %#v err=%v", got, err)
	}
}

func TestPutClusterSecretStagesAndMergesRetiredRecipients(t *testing.T) {
	ctx := context.Background()
	st, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	if err := st.UpsertSecretDeleteOutbox(ctx, "sb-retire", []string{"old-a"}, 1); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	retired := []string{"old-b", "old-a"}
	if _, err := st.PutClusterSecret(ctx, ClusterSecretRecord{
		Ref: "cluster-secret://sandbox/sb-retire/v1", SandboxID: "sb-retire", Version: 1,
		Recipients: []string{"new-a", "new-b"}, SealedPayload: []byte("generation-2"),
		SealGeneration: 2, CreatedAt: now, UpdatedAt: now, RetireRecipients: &retired,
	}); err != nil {
		t.Fatalf("put resealed row: %v", err)
	}
	got, err := st.GetSecretDeleteOutbox(ctx, "sb-retire")
	if err != nil || got == nil {
		t.Fatalf("get staged retirement: got=%#v err=%v", got, err)
	}
	if got.Generation != 2 || !got.AwaitingPromotion {
		t.Fatalf("staged retirement = %+v, want generation 2 awaiting promotion", got)
	}
	if want := []string{"old-a", "old-b"}; !slices.Equal(got.Recipients, want) {
		t.Fatalf("merged retired recipients = %v, want %v", got.Recipients, want)
	}

	// Confirming the same generation makes the union eligible without losing
	// either the older pending recipient or the newly retired recipient.
	if err := st.UpsertSecretDeleteOutbox(ctx, "sb-retire", []string{"old-b"}, 2); err != nil {
		t.Fatal(err)
	}
	got, err = st.GetSecretDeleteOutbox(ctx, "sb-retire")
	if err != nil || got == nil || got.AwaitingPromotion || !slices.Equal(got.Recipients, []string{"old-a", "old-b"}) {
		t.Fatalf("promoted retirement = %+v err=%v", got, err)
	}
}

func TestPutClusterSecretDoesNotRetireReaddedCurrentRecipient(t *testing.T) {
	ctx := context.Background()
	st, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	// peer-a was pending deletion from an older generation, but generation 3
	// selects it again while retiring peer-b. The merged journal must never
	// delete peer-a's current generation.
	if err := st.UpsertSecretDeleteOutbox(ctx, "sb-readd", []string{"peer-a"}, 2); err != nil {
		t.Fatal(err)
	}
	retired := []string{"peer-b"}
	if _, err := st.PutClusterSecret(ctx, ClusterSecretRecord{
		Ref: "cluster-secret://sandbox/sb-readd/v1", SandboxID: "sb-readd", Version: 1,
		Recipients: []string{"node-a", "peer-a", "peer-c"}, SealedPayload: []byte("generation-3"),
		SealGeneration: 3, RetireRecipients: &retired,
	}); err != nil {
		t.Fatal(err)
	}
	got, err := st.GetSecretDeleteOutbox(ctx, "sb-readd")
	if err != nil || got == nil {
		t.Fatalf("get staged retirement: got=%+v err=%v", got, err)
	}
	if !got.AwaitingPromotion || got.Generation != 3 || !slices.Equal(got.Recipients, []string{"peer-b"}) {
		t.Fatalf("staged retirement = %+v, want only peer-b at generation 3", got)
	}
}

func TestOrdinarySecretPutPreservesPendingDeleteObligation(t *testing.T) {
	ctx := context.Background()
	st, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	if err := st.UpsertSecretDeleteOutbox(ctx, "sb-recreate", []string{"former-peer"}, 2); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if _, err := st.PutClusterSecret(ctx, ClusterSecretRecord{
		Ref: "cluster-secret://sandbox/sb-recreate/v1", SandboxID: "sb-recreate", Version: 1,
		Recipients: []string{"new-peer"}, SealedPayload: []byte("generation-3"),
		SealGeneration: 3, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	got, err := st.GetSecretDeleteOutbox(ctx, "sb-recreate")
	if err != nil || got == nil || !slices.Equal(got.Recipients, []string{"former-peer"}) {
		t.Fatalf("ordinary put lost prior cleanup obligation: got=%+v err=%v", got, err)
	}
}

func TestSecretOutboxCorruptionFailsClosed(t *testing.T) {
	ctx := context.Background()
	st, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	if err := st.UpsertSecretDeleteOutbox(ctx, "sb-bad-delete", []string{"peer-a"}, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.ExecContext(ctx, `UPDATE cluster_secret_delete_outbox SET recipients_json = '{' WHERE sandbox_id = 'sb-bad-delete'`); err != nil {
		t.Fatal(err)
	}
	if rec, err := st.GetSecretDeleteOutbox(ctx, "sb-bad-delete"); err == nil || rec != nil {
		t.Fatalf("corrupt delete outbox = rec=%+v err=%v, want fail closed", rec, err)
	}
	if rows, err := st.ListSecretDeleteOutboxBatch(ctx, 10); err == nil || rows != nil {
		t.Fatalf("corrupt delete outbox list = rows=%+v err=%v, want fail closed", rows, err)
	}
	if err := st.UpsertSecretDeleteOutbox(ctx, "sb-bad-delete", []string{"peer-b"}, 1); err == nil {
		t.Fatal("corrupt delete outbox merge must not overwrite and lose peer-a")
	}

	if err := st.UpsertSecretPutOutbox(ctx, "sb-bad-put", "inc-1", 1, []string{"peer-a"}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.ExecContext(ctx, `UPDATE cluster_secret_put_outbox SET recipients_json = '{' WHERE sandbox_id = 'sb-bad-put'`); err != nil {
		t.Fatal(err)
	}
	if rec, err := st.GetSecretPutOutbox(ctx, "sb-bad-put"); err == nil || rec != nil {
		t.Fatalf("corrupt put outbox = rec=%+v err=%v, want fail closed", rec, err)
	}
	if rows, err := st.ListSecretPutOutboxBatch(ctx, 10); err == nil || rows != nil {
		t.Fatalf("corrupt put outbox list = rows=%+v err=%v, want fail closed", rows, err)
	}
	if err := st.UpsertSecretPutOutbox(ctx, "sb-bad-put", "inc-1", 1, []string{"peer-b"}); err == nil {
		t.Fatal("corrupt put outbox merge must not overwrite and lose peer-a")
	}
}

func TestMarkSecretDeleteOutboxPromotedIsGenerationFenced(t *testing.T) {
	ctx := context.Background()
	st, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	retired := []string{"peer-a"}
	if _, err := st.PutClusterSecret(ctx, ClusterSecretRecord{
		Ref: "cluster-secret://sandbox/sb-promote/v1", SandboxID: "sb-promote", Version: 1,
		Recipients: []string{"node-a", "peer-b"}, SealedPayload: []byte("sealed"),
		SealGeneration: 2, RetireRecipients: &retired,
	}); err != nil {
		t.Fatal(err)
	}
	if promoted, err := st.MarkSecretDeleteOutboxPromoted(ctx, "sb-promote", 1); err != nil || promoted {
		t.Fatalf("stale promotion = %v, %v; want false, nil", promoted, err)
	}
	if rec, err := st.GetSecretDeleteOutbox(ctx, "sb-promote"); err != nil || rec == nil || !rec.AwaitingPromotion {
		t.Fatalf("stale promotion released staged row: rec=%+v err=%v", rec, err)
	}
	if promoted, err := st.MarkSecretDeleteOutboxPromoted(ctx, "sb-promote", 2); err != nil || !promoted {
		t.Fatalf("matching promotion = %v, %v; want true, nil", promoted, err)
	}
	if promoted, err := st.MarkSecretDeleteOutboxPromoted(ctx, "sb-promote", 2); err != nil || promoted {
		t.Fatalf("duplicate promotion = %v, %v; want false, nil", promoted, err)
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
	if _, err := st.PutClusterSecret(ctx, ClusterSecretRecord{
		Ref: ref, SandboxID: "sb-stale", Version: 1,
		Recipients: []string{"a"}, SealedPayload: []byte("gen2"),
		SealGeneration: 2, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	_, err = st.PutClusterSecret(ctx, ClusterSecretRecord{
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

func TestUpdateSecretPutOutboxMissingRowIsNotSilent(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	err = st.UpdateSecretPutOutboxRecipients(context.Background(), "missing", "inc-1", []string{"node-b"}, 1)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("UpdateSecretPutOutboxRecipients error = %v, want ErrNotFound", err)
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
	if _, err := st.PutClusterSecret(ctx, rec); err != nil {
		t.Fatal(err)
	}
	if _, err := st.PutClusterSecret(ctx, rec); err != nil {
		t.Fatalf("identical equal-gen put should noop: %v", err)
	}
	rec.SealedPayload = []byte("different")
	if _, err := st.PutClusterSecret(ctx, rec); !errors.Is(err, ErrClusterSecretPayloadConflict) {
		t.Fatalf("conflict = %v, want ErrClusterSecretPayloadConflict", err)
	}
	got, err := st.GetClusterSecretForSandbox(ctx, "sb-digest")
	if err != nil || string(got.SealedPayload) != "same" {
		t.Fatalf("row mutated on conflict: %+v err=%v", got, err)
	}
}
