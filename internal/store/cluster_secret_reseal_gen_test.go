package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestDeleteGenerationSurvivesReseal(t *testing.T) {
	ctx := context.Background()
	st, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	now := time.Now().UTC()
	if _, err := st.PutClusterSecret(ctx, ClusterSecretRecord{
		Ref: "cluster-secret://sandbox/sb-mono/i/inc-mono/v1", SandboxID: "sb-mono", Version: 1,
		Recipients: []string{"a", "b"}, SealedPayload: []byte("sealed-1"),
		SealGeneration: 1, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	gen1, err := st.DeleteClusterSecretsOriginatorWithOutbox(ctx, "sb-mono", "inc-mono", []string{"b"})
	if err != nil || gen1 != 2 {
		t.Fatalf("first delete gen=%d err=%v, want 2", gen1, err)
	}
	// Reseal clears tomb atomically with put, but delete gen must still advance.
	if _, err := st.PutClusterSecret(ctx, ClusterSecretRecord{
		Ref: "cluster-secret://sandbox/sb-mono/i/inc-mono/v1", SandboxID: "sb-mono", Version: 1,
		Recipients: []string{"a", "b"}, SealedPayload: []byte("sealed-2"),
		SealGeneration: 3, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	tombGeneration, err := st.ClusterSecretTombGenerationForIncarnation(ctx, "sb-mono", "inc-mono")
	if err != nil || tombGeneration != 0 {
		t.Fatalf("tomb after reseal = %d %v, want zero", tombGeneration, err)
	}
	gen2, err := st.DeleteClusterSecretsOriginatorWithOutbox(ctx, "sb-mono", "inc-mono", []string{"b"})
	if err != nil {
		t.Fatalf("second delete: %v", err)
	}
	if gen2 <= gen1 {
		t.Fatalf("delete generation reset after reseal: first=%d second=%d", gen1, gen2)
	}
	if gen2 < 4 {
		t.Fatalf("second delete gen=%d, want >=4 (max seal 3 + 1)", gen2)
	}
}

func TestPutClusterSecretRejectsDowngrade(t *testing.T) {
	ctx := context.Background()
	st, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	now := time.Now().UTC()
	ref := "cluster-secret://sandbox/sb-ooo/i/inc-ooo/v1"
	if _, err := st.PutClusterSecret(ctx, ClusterSecretRecord{
		Ref: ref, SandboxID: "sb-ooo", Version: 1,
		Recipients: []string{"a"}, SealedPayload: []byte("gen2"),
		SealGeneration: 2, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.PutClusterSecret(ctx, ClusterSecretRecord{
		Ref: ref, SandboxID: "sb-ooo", Version: 1,
		Recipients: []string{"a"}, SealedPayload: []byte("gen1"),
		SealGeneration: 1, CreatedAt: now, UpdatedAt: now,
	}); !errors.Is(err, ErrClusterSecretStaleGeneration) {
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

func TestPutClusterSecretKeepsReusedSandboxIncarnationsIndependent(t *testing.T) {
	ctx := context.Background()
	st, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	now := time.Now().UTC()
	row := ClusterSecretRecord{
		Ref: "cluster-secret://sandbox/sb-equal/i/inc-a/v1", SandboxID: "sb-equal", Version: 1,
		Recipients: []string{"a"}, SealedPayload: []byte("inc-a"), SealGeneration: 7,
		CreatedAt: now, UpdatedAt: now,
	}
	if _, err := st.PutClusterSecret(ctx, row); err != nil {
		t.Fatal(err)
	}
	row.Ref = "cluster-secret://sandbox/sb-equal/i/inc-b/v1"
	row.SealedPayload = []byte("inc-b")
	row.SealGeneration = 1
	if _, err := st.PutClusterSecret(ctx, row); err != nil {
		t.Fatalf("replacement lifecycle put = %v", err)
	}
	rows, err := st.ListClusterSecretsBatch(ctx, "", 10)
	if err != nil || len(rows) != 2 {
		t.Fatalf("independent lifecycle rows = %+v err=%v", rows, err)
	}
	if gen, holds, err := st.ClusterSecretSealGeneration(ctx, "sb-equal", "inc-b"); err != nil || !holds || gen != 1 {
		t.Fatalf("replacement lifecycle generation = %d holds=%v err=%v", gen, holds, err)
	}
	if err := st.ApplyPeerSecretDelete(ctx, "sb-equal", "inc-a", 7); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetClusterSecret(ctx, row.Ref); err != nil {
		t.Fatalf("old lifecycle delete erased replacement: %v", err)
	}
	if gen, err := st.ClusterSecretTombGenerationForIncarnation(ctx, "sb-equal", "inc-a"); err != nil || gen != 7 {
		t.Fatalf("old lifecycle tomb = %d err=%v", gen, err)
	}
	if gen, err := st.NextClusterSecretSealGenerationForIncarnation(ctx, "sb-equal", "inc-b"); err != nil || gen != 2 {
		t.Fatalf("replacement next generation = %d err=%v", gen, err)
	}
}

func TestSecretOutboxesKeepReusedSandboxCleanupObligationsIndependent(t *testing.T) {
	ctx := context.Background()
	st, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	if err := st.UpsertSecretDeleteOutbox(ctx, "sb-outbox-reuse", "inc-old", []string{"old-peer"}, 4); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSecretDeleteOutbox(ctx, "sb-outbox-reuse", "inc-new", []string{"new-peer"}, 1); err != nil {
		t.Fatal(err)
	}
	deleteRows, err := st.ListSecretDeleteOutboxBatch(ctx, 10)
	if err != nil || len(deleteRows) != 2 {
		t.Fatalf("delete obligations = %+v err=%v", deleteRows, err)
	}
	if err := st.UpdateSecretDeleteOutboxRecipients(ctx, "sb-outbox-reuse", "inc-old", nil, 4); err != nil {
		t.Fatal(err)
	}
	if rec, err := st.GetSecretDeleteOutboxForIncarnation(ctx, "sb-outbox-reuse", "inc-new"); err != nil || rec == nil || len(rec.Recipients) != 1 || rec.Recipients[0] != "new-peer" {
		t.Fatalf("new delete obligation after old ACK = %+v err=%v", rec, err)
	}

	if err := st.UpsertSecretPutOutbox(ctx, "sb-outbox-reuse", "inc-old", 4, []string{"old-peer"}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSecretPutOutbox(ctx, "sb-outbox-reuse", "inc-new", 1, []string{"new-peer"}); err != nil {
		t.Fatal(err)
	}
	putRows, err := st.ListSecretPutOutboxBatch(ctx, 10)
	if err != nil || len(putRows) != 2 {
		t.Fatalf("put obligations = %+v err=%v", putRows, err)
	}
	if err := st.DeleteSecretPutOutbox(ctx, "sb-outbox-reuse", "inc-old", 4); err != nil {
		t.Fatal(err)
	}
	if rec, err := st.GetSecretPutOutboxForIncarnation(ctx, "sb-outbox-reuse", "inc-new"); err != nil || rec == nil || len(rec.Recipients) != 1 || rec.Recipients[0] != "new-peer" {
		t.Fatalf("new put obligation after old ACK = %+v err=%v", rec, err)
	}
}

func TestPutClusterSecretBlockedByTombInsideTx(t *testing.T) {
	ctx := context.Background()
	st, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	now := time.Now().UTC()
	if _, err := st.PutClusterSecret(ctx, ClusterSecretRecord{
		Ref: "cluster-secret://sandbox/sb-race/i/inc-race/v1", SandboxID: "sb-race", Version: 1,
		Recipients: []string{"a"}, SealedPayload: []byte("live"),
		SealGeneration: 2, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.ApplyPeerSecretDelete(ctx, "sb-race", "inc-race", 2); err != nil {
		t.Fatal(err)
	}
	_, err = st.PutClusterSecret(ctx, ClusterSecretRecord{
		Ref: "cluster-secret://sandbox/sb-race/i/inc-race/v1", SandboxID: "sb-race", Version: 1,
		Recipients: []string{"a"}, SealedPayload: []byte("stale"),
		SealGeneration: 2, CreatedAt: now, UpdatedAt: now,
	})
	if err == nil || !errors.Is(err, ErrClusterSecretTombBlocksPut) {
		t.Fatalf("equal-gen put after delete = %v, want ErrClusterSecretTombBlocksPut", err)
	}
	tombGeneration, err := st.ClusterSecretTombGenerationForIncarnation(ctx, "sb-race", "inc-race")
	if err != nil || tombGeneration == 0 {
		t.Fatalf("tomb must remain after blocked put: %d %v", tombGeneration, err)
	}
	if _, err := st.GetClusterSecret(ctx, "cluster-secret://sandbox/sb-race/i/inc-race/v1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("stale put must not resurrect row: %v", err)
	}
}

func TestDeleteClusterSecretsRowsOnlyNoTomb(t *testing.T) {
	ctx := context.Background()
	st, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	now := time.Now().UTC()
	if _, err := st.PutClusterSecret(ctx, ClusterSecretRecord{
		Ref: "cluster-secret://sandbox/sb-local/i/inc-local/v1", SandboxID: "sb-local", Version: 1,
		Recipients: []string{"a"}, SealedPayload: []byte("x"),
		SealGeneration: 1, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteClusterSecretRowsForIncarnation(ctx, "sb-local", "inc-local"); err != nil {
		t.Fatal(err)
	}
	tombGeneration, err := st.ClusterSecretTombGenerationForIncarnation(ctx, "sb-local", "inc-local")
	if err != nil || tombGeneration != 0 {
		t.Fatalf("rows-only delete must not tomb: %d %v", tombGeneration, err)
	}
}
