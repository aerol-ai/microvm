package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestApplyPeerSecretDeleteEqualGenerationDeletes(t *testing.T) {
	ctx := context.Background()
	st, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	now := time.Now().UTC()
	if _, err := st.PutClusterSecret(ctx, ClusterSecretRecord{
		Ref: "cluster-secret://sandbox/sb-eq/v1", SandboxID: "sb-eq", Version: 1,
		Recipients: []string{"a", "b"}, SealedPayload: []byte("sealed"),
		SealGeneration: 3, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	// Delete generation == seal generation must remove the row (not ACK-no-op).
	if err := st.ApplyPeerSecretDelete(ctx, "sb-eq", 3); err != nil {
		t.Fatalf("ApplyPeerSecretDelete: %v", err)
	}
	if _, err := st.GetClusterSecret(ctx, "cluster-secret://sandbox/sb-eq/v1"); err == nil {
		t.Fatal("expected secret row deleted for equal generation")
	}
	// Newer reseal must survive a stale delete.
	if err := st.ClearClusterSecretTomb(ctx, "sb-eq"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.PutClusterSecret(ctx, ClusterSecretRecord{
		Ref: "cluster-secret://sandbox/sb-eq/v1", SandboxID: "sb-eq", Version: 1,
		Recipients: []string{"a", "b"}, SealedPayload: []byte("resealed"),
		SealGeneration: 4, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.ApplyPeerSecretDelete(ctx, "sb-eq", 3); err != nil {
		t.Fatalf("stale delete: %v", err)
	}
	got, err := st.GetClusterSecret(ctx, "cluster-secret://sandbox/sb-eq/v1")
	if err != nil || string(got.SealedPayload) != "resealed" {
		t.Fatalf("resealed row should survive stale delete: %+v err=%v", got, err)
	}
}

func TestSecretDeleteOutboxCRUDAndGenerationQueries(t *testing.T) {
	ctx := context.Background()
	st, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	if gen, err := st.NextClusterSecretSealGeneration(ctx, " "); err != nil || gen != 1 {
		t.Fatalf("blank next generation = %d, %v", gen, err)
	}
	if gen, err := st.MaxClusterSecretSealGeneration(ctx, " "); err != nil || gen != 0 {
		t.Fatalf("blank max generation = %d, %v", gen, err)
	}
	if gen, err := st.ClusterSecretTombGeneration(ctx, " "); err != nil || gen != 0 {
		t.Fatalf("blank tomb generation = %d, %v", gen, err)
	}
	if err := st.UpdateSecretDeleteOutboxRecipients(ctx, " ", []string{"peer"}, 1); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteSecretDeleteOutbox(ctx, " "); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	if _, err := st.PutClusterSecret(ctx, ClusterSecretRecord{
		Ref: "cluster-secret://sandbox/sb-generations/v1", SandboxID: "sb-generations", Version: 1,
		Recipients: []string{"self", "peer-a", "peer-b"}, SealedPayload: []byte("sealed"),
		SealGeneration: 2, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if gen, err := st.MaxClusterSecretSealGeneration(ctx, "sb-generations"); err != nil || gen != 2 {
		t.Fatalf("max generation = %d, %v", gen, err)
	}
	if gen, err := st.NextClusterSecretSealGeneration(ctx, "sb-generations"); err != nil || gen != 3 {
		t.Fatalf("next generation = %d, %v", gen, err)
	}
	deleteGen, err := st.DeleteClusterSecretsOriginatorWithOutbox(ctx, "sb-generations", []string{"peer-a", "peer-b"})
	if err != nil || deleteGen != 3 {
		t.Fatalf("originator delete generation = %d, %v", deleteGen, err)
	}
	if gen, err := st.ClusterSecretTombGeneration(ctx, "sb-generations"); err != nil || gen != deleteGen {
		t.Fatalf("tomb generation = %d, %v", gen, err)
	}
	if gen, err := st.NextClusterSecretSealGeneration(ctx, "sb-generations"); err != nil || gen != deleteGen+1 {
		t.Fatalf("post-delete next generation = %d, %v", gen, err)
	}

	rows, err := st.ListSecretDeleteOutbox(ctx)
	if err != nil || len(rows) != 1 || rows[0].SandboxID != "sb-generations" {
		t.Fatalf("delete outbox rows = %+v, %v", rows, err)
	}
	if err := st.UpdateSecretDeleteOutboxRecipients(ctx, "sb-generations", []string{"peer-b"}, deleteGen); err != nil {
		t.Fatal(err)
	}
	if err := st.BumpSecretDeleteOutboxAttempt(ctx, "sb-generations"); err != nil {
		t.Fatal(err)
	}
	rec, err := st.GetSecretDeleteOutbox(ctx, "sb-generations")
	if err != nil || rec == nil || len(rec.Recipients) != 1 || rec.Recipients[0] != "peer-b" || rec.Attempts != 1 {
		t.Fatalf("updated delete outbox = %+v, %v", rec, err)
	}
	if err := st.UpdateSecretDeleteOutboxRecipients(ctx, "sb-generations", nil, deleteGen); err != nil {
		t.Fatal(err)
	}
	if rec, err := st.GetSecretDeleteOutbox(ctx, "sb-generations"); err != nil || rec != nil {
		t.Fatalf("ACKed delete outbox = %+v, %v", rec, err)
	}
	if err := st.DeleteSecretDeleteOutbox(ctx, "sb-generations"); err != nil {
		t.Fatal(err)
	}
	if n, err := st.PruneClusterSecretTombs(ctx, time.Time{}, 1); err != nil || n != 0 {
		t.Fatalf("zero-cutoff prune = %d, %v", n, err)
	}
	if n, err := st.PruneClusterSecretTombs(ctx, now.Add(time.Hour), 0); err != nil || n != 0 {
		t.Fatalf("zero-limit prune = %d, %v", n, err)
	}
}

func TestSecretLifecycleStatsTracksBothDurableQueues(t *testing.T) {
	ctx := context.Background()
	st, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	if err := st.UpsertSecretDeleteOutbox(ctx, "sb-delete", []string{"peer"}, 1); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSecretPutOutbox(ctx, "sb-put", "inc-a", 2, []string{"peer"}); err != nil {
		t.Fatal(err)
	}
	if err := st.ApplyPeerSecretDelete(ctx, "sb-tomb", 4); err != nil {
		t.Fatal(err)
	}
	stats, err := st.SecretLifecycleStats(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if stats.OutboxPending != 1 || stats.PutOutboxPending != 1 || stats.Tombstones != 1 || stats.OldestOutbox.IsZero() || stats.OldestPutOutbox.IsZero() {
		t.Fatalf("lifecycle stats = %+v", stats)
	}
}
