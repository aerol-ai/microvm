package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestSecretDeleteLifecycleRejectsMissingGeneration(t *testing.T) {
	ctx := context.Background()
	st, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	for name, call := range map[string]func() error{
		"apply peer delete": func() error {
			return st.ApplyPeerSecretDelete(ctx, "sb-current-contract", "inc-current", 0)
		},
		"shrink delete outbox": func() error {
			return st.UpdateSecretDeleteOutboxRecipients(ctx, "sb-current-contract", "inc-current", nil, 0)
		},
		"promote delete outbox": func() error {
			_, err := st.MarkSecretDeleteOutboxPromoted(ctx, "sb-current-contract", "inc-current", 0)
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := call(); err == nil {
				t.Fatalf("missing generation error = %v", err)
			}
		})
	}
}

func TestApplyPeerSecretDeleteEqualGenerationDeletes(t *testing.T) {
	ctx := context.Background()
	st, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	now := time.Now().UTC()
	if _, err := st.PutClusterSecret(ctx, ClusterSecretRecord{
		Ref: "cluster-secret://sandbox/sb-eq/i/inc-eq/v1", SandboxID: "sb-eq", Version: 1,
		Recipients: []string{"a", "b"}, SealedPayload: []byte("sealed"),
		SealGeneration: 3, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	// Delete generation == seal generation must remove the row (not ACK-no-op).
	if err := st.ApplyPeerSecretDelete(ctx, "sb-eq", "inc-eq", 3); err != nil {
		t.Fatalf("ApplyPeerSecretDelete: %v", err)
	}
	if _, err := st.GetClusterSecret(ctx, "cluster-secret://sandbox/sb-eq/i/inc-eq/v1"); err == nil {
		t.Fatal("expected secret row deleted for equal generation")
	}
	// Newer reseal must survive a stale delete.
	if err := st.ClearClusterSecretTombForIncarnation(ctx, "sb-eq", "inc-eq"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.PutClusterSecret(ctx, ClusterSecretRecord{
		Ref: "cluster-secret://sandbox/sb-eq/i/inc-eq/v1", SandboxID: "sb-eq", Version: 1,
		Recipients: []string{"a", "b"}, SealedPayload: []byte("resealed"),
		SealGeneration: 4, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.ApplyPeerSecretDelete(ctx, "sb-eq", "inc-eq", 3); err != nil {
		t.Fatalf("stale delete: %v", err)
	}
	got, err := st.GetClusterSecret(ctx, "cluster-secret://sandbox/sb-eq/i/inc-eq/v1")
	if err != nil || string(got.SealedPayload) != "resealed" {
		t.Fatalf("resealed row should survive stale delete: %+v err=%v", got, err)
	}
}

func TestPeerDeleteIsIncarnationFencedAcrossSandboxIDReuse(t *testing.T) {
	ctx := context.Background()
	st, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	ref := "cluster-secret://sandbox/sb-reused/i/inc-new/v1"
	if _, err := st.PutClusterSecret(ctx, ClusterSecretRecord{
		Ref: ref, SandboxID: "sb-reused", Version: 1,
		Recipients: []string{"node-a"}, SealedPayload: []byte("new-lifecycle"), SealGeneration: 1,
	}); err != nil {
		t.Fatal(err)
	}
	// A delayed request from the destroyed lifecycle may carry a much larger
	// generation. Incarnation identity, not generation ordering, must win.
	if err := st.ApplyPeerSecretDelete(ctx, "sb-reused", "inc-old", 99); err != nil {
		t.Fatal(err)
	}
	got, err := st.GetClusterSecret(ctx, ref)
	if err != nil || string(got.SealedPayload) != "new-lifecycle" {
		t.Fatalf("prior-incarnation delete erased reused ID: got=%+v err=%v", got, err)
	}
	if generation, err := st.ClusterSecretTombGenerationForIncarnation(ctx, "sb-reused", "inc-old"); err != nil || generation != 99 {
		t.Fatalf("prior-incarnation delete tomb: generation=%d err=%v, want 99", generation, err)
	}
	if _, err := st.PutClusterSecret(ctx, ClusterSecretRecord{
		Ref: "cluster-secret://sandbox/sb-reused/i/inc-old/v1", SandboxID: "sb-reused", Version: 1,
		Recipients: []string{"node-old"}, SealedPayload: []byte("delayed-old-put"), SealGeneration: 99,
	}); !errors.Is(err, ErrClusterSecretTombBlocksPut) {
		t.Fatalf("delayed prior-incarnation put error = %v, want tomb rejection", err)
	}
}

func TestNewLifecyclePutPreservesPriorIncarnationTomb(t *testing.T) {
	ctx := context.Background()
	st, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	if err := st.ApplyPeerSecretDelete(ctx, "sb-reused", "inc-old", 99); err != nil {
		t.Fatal(err)
	}
	ref := "cluster-secret://sandbox/sb-reused/i/inc-new/v1"
	if _, err := st.PutClusterSecret(ctx, ClusterSecretRecord{
		Ref: ref, SandboxID: "sb-reused", Version: 1,
		Recipients: []string{"node-a"}, SealedPayload: []byte("new-lifecycle"), SealGeneration: 1,
	}); err != nil {
		t.Fatalf("old lifecycle tomb blocked current put: %v", err)
	}
	if generation, err := st.ClusterSecretTombGenerationForIncarnation(ctx, "sb-reused", "inc-old"); err != nil || generation != 99 {
		t.Fatalf("current put cleared prior-incarnation tomb: generation=%d err=%v", generation, err)
	}
	if _, err := st.PutClusterSecret(ctx, ClusterSecretRecord{
		Ref: "cluster-secret://sandbox/sb-reused/i/inc-old/v1", SandboxID: "sb-reused", Version: 1,
		Recipients: []string{"node-old"}, SealedPayload: []byte("delayed-old-put"), SealGeneration: 99,
	}); !errors.Is(err, ErrClusterSecretTombBlocksPut) {
		t.Fatalf("delayed prior-incarnation put error = %v, want tomb rejection", err)
	}
}

func TestDeleteOutboxMutationsAreIncarnationFenced(t *testing.T) {
	ctx := context.Background()
	st, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	if err := st.UpsertSecretDeleteOutbox(ctx, "sb-reused", "inc-old", []string{"old-peer"}, 2); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSecretDeleteOutbox(ctx, "sb-reused", "inc-new", []string{"new-peer"}, 2); err != nil {
		t.Fatal(err)
	}
	if err := st.UpdateSecretDeleteOutboxRecipients(ctx, "sb-reused", "inc-old", nil, 2); err != nil {
		t.Fatal(err)
	}
	if err := st.BumpSecretDeleteOutboxAttempt(ctx, "sb-reused", "inc-old", 2); err != nil {
		t.Fatal(err)
	}
	if promoted, err := st.MarkSecretDeleteOutboxPromoted(ctx, "sb-reused", "inc-old", 2); err != nil || promoted {
		t.Fatalf("old lifecycle promotion = %v, %v", promoted, err)
	}
	rec, err := st.GetSecretDeleteOutboxForIncarnation(ctx, "sb-reused", "inc-new")
	if err != nil || rec == nil || rec.IncarnationID != "inc-new" || rec.Attempts != 0 || len(rec.Recipients) != 1 || rec.Recipients[0] != "new-peer" {
		t.Fatalf("old lifecycle mutated current outbox: rec=%+v err=%v", rec, err)
	}
}

func TestSecretGenerationReadsFailClosedOnSchemaError(t *testing.T) {
	ctx := context.Background()
	st, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if _, err := st.db.ExecContext(ctx, `DROP TABLE cluster_secrets`); err != nil {
		t.Fatal(err)
	}
	if gen, err := st.NextClusterSecretSealGenerationForIncarnation(ctx, "sb-error", "inc-error"); err == nil || gen != 0 {
		t.Fatalf("schema error synthesized generation: gen=%d err=%v", gen, err)
	}
}

func TestSecretDeleteOutboxCRUDAndGenerationQueries(t *testing.T) {
	ctx := context.Background()
	st, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	if gen, err := st.NextClusterSecretSealGenerationForIncarnation(ctx, " ", " "); err == nil || gen != 0 {
		t.Fatalf("blank next generation = %d, %v", gen, err)
	}
	if gen, holds, err := st.ClusterSecretSealGeneration(ctx, " ", " "); err != nil || holds || gen != 0 {
		t.Fatalf("blank seal generation = %d, %v, %v", gen, holds, err)
	}
	if gen, err := st.ClusterSecretTombGenerationForIncarnation(ctx, " ", " "); err != nil || gen != 0 {
		t.Fatalf("blank tomb generation = %d, %v", gen, err)
	}
	if err := st.UpdateSecretDeleteOutboxRecipients(ctx, " ", "inc-empty", []string{"peer"}, 1); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteSecretDeleteOutbox(ctx, " ", "inc-empty", 1); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	if _, err := st.PutClusterSecret(ctx, ClusterSecretRecord{
		Ref: "cluster-secret://sandbox/sb-generations/i/inc-generations/v1", SandboxID: "sb-generations", Version: 1,
		Recipients: []string{"self", "peer-a", "peer-b"}, SealedPayload: []byte("sealed"),
		SealGeneration: 2, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if gen, holds, err := st.ClusterSecretSealGeneration(ctx, "sb-generations", "inc-generations"); err != nil || !holds || gen != 2 {
		t.Fatalf("seal generation = %d, %v, %v", gen, holds, err)
	}
	if gen, err := st.NextClusterSecretSealGenerationForIncarnation(ctx, "sb-generations", "inc-generations"); err != nil || gen != 3 {
		t.Fatalf("next generation = %d, %v", gen, err)
	}
	deleteGen, err := st.DeleteClusterSecretsOriginatorWithOutbox(ctx, "sb-generations", "inc-generations", []string{"peer-a", "peer-b"})
	if err != nil || deleteGen != 3 {
		t.Fatalf("originator delete generation = %d, %v", deleteGen, err)
	}
	if gen, err := st.ClusterSecretTombGenerationForIncarnation(ctx, "sb-generations", "inc-generations"); err != nil || gen != deleteGen {
		t.Fatalf("tomb generation = %d, %v", gen, err)
	}
	if gen, err := st.NextClusterSecretSealGenerationForIncarnation(ctx, "sb-generations", "inc-generations"); err != nil || gen != deleteGen+1 {
		t.Fatalf("post-delete next generation = %d, %v", gen, err)
	}

	rows, err := st.ListSecretDeleteOutboxBatch(ctx, 10)
	if err != nil || len(rows) != 1 || rows[0].SandboxID != "sb-generations" {
		t.Fatalf("delete outbox rows = %+v, %v", rows, err)
	}
	if err := st.UpdateSecretDeleteOutboxRecipients(ctx, "sb-generations", "inc-generations", []string{"peer-b"}, deleteGen); err != nil {
		t.Fatal(err)
	}
	if err := st.BumpSecretDeleteOutboxAttempt(ctx, "sb-generations", "inc-generations", deleteGen); err != nil {
		t.Fatal(err)
	}
	rec, err := st.GetSecretDeleteOutboxForIncarnation(ctx, "sb-generations", "inc-generations")
	if err != nil || rec == nil || len(rec.Recipients) != 1 || rec.Recipients[0] != "peer-b" || rec.Attempts != 1 {
		t.Fatalf("updated delete outbox = %+v, %v", rec, err)
	}
	if err := st.UpdateSecretDeleteOutboxRecipients(ctx, "sb-generations", "inc-generations", nil, deleteGen); err != nil {
		t.Fatal(err)
	}
	if rec, err := st.GetSecretDeleteOutboxForIncarnation(ctx, "sb-generations", "inc-generations"); err != nil || rec != nil {
		t.Fatalf("ACKed delete outbox = %+v, %v", rec, err)
	}
	if err := st.DeleteSecretDeleteOutbox(ctx, "sb-generations", "inc-generations", deleteGen); err != nil {
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

	if err := st.UpsertSecretDeleteOutbox(ctx, "sb-delete", "inc-delete", []string{"peer"}, 1); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSecretPutOutbox(ctx, "sb-put", "inc-a", 2, []string{"peer"}); err != nil {
		t.Fatal(err)
	}
	if err := st.ApplyPeerSecretDelete(ctx, "sb-tomb", "inc-tomb", 4); err != nil {
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
