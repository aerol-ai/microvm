package store

import (
	"context"
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
	if err := st.PutClusterSecret(ctx, ClusterSecretRecord{
		Ref: "cluster-secret://sandbox/sb-mono/v1", SandboxID: "sb-mono", Version: 1,
		Recipients: []string{"a", "b"}, SealedPayload: []byte("sealed-1"),
		SealGeneration: 1, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	gen1, err := st.DeleteClusterSecretsOriginatorWithOutbox(ctx, "sb-mono", []string{"b"})
	if err != nil || gen1 != 2 {
		t.Fatalf("first delete gen=%d err=%v, want 2", gen1, err)
	}
	// Reseal clears tomb atomically with put, but delete gen must still advance.
	if err := st.PutClusterSecret(ctx, ClusterSecretRecord{
		Ref: "cluster-secret://sandbox/sb-mono/v1", SandboxID: "sb-mono", Version: 1,
		Recipients: []string{"a", "b"}, SealedPayload: []byte("sealed-2"),
		SealGeneration: 3, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	tomb, err := st.HasClusterSecretTomb(ctx, "sb-mono")
	if err != nil || tomb {
		t.Fatalf("tomb after reseal = %v %v, want false", tomb, err)
	}
	gen2, err := st.DeleteClusterSecretsOriginatorWithOutbox(ctx, "sb-mono", []string{"b"})
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
	ref := "cluster-secret://sandbox/sb-ooo/v1"
	if err := st.PutClusterSecret(ctx, ClusterSecretRecord{
		Ref: ref, SandboxID: "sb-ooo", Version: 1,
		Recipients: []string{"a"}, SealedPayload: []byte("gen2"),
		SealGeneration: 2, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.PutClusterSecret(ctx, ClusterSecretRecord{
		Ref: ref, SandboxID: "sb-ooo", Version: 1,
		Recipients: []string{"a"}, SealedPayload: []byte("gen1"),
		SealGeneration: 1, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("stale put should be idempotent no-op: %v", err)
	}
	got, err := st.GetClusterSecret(ctx, ref)
	if err != nil {
		t.Fatal(err)
	}
	if got.SealGeneration != 2 || string(got.SealedPayload) != "gen2" {
		t.Fatalf("downgraded row: gen=%d payload=%q", got.SealGeneration, got.SealedPayload)
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
	if err := st.PutClusterSecret(ctx, ClusterSecretRecord{
		Ref: "cluster-secret://sandbox/sb-local/v1", SandboxID: "sb-local", Version: 1,
		Recipients: []string{"a"}, SealedPayload: []byte("x"),
		SealGeneration: 1, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteClusterSecretsRowsOnly(ctx, "sb-local"); err != nil {
		t.Fatal(err)
	}
	tomb, err := st.HasClusterSecretTomb(ctx, "sb-local")
	if err != nil || tomb {
		t.Fatalf("rows-only delete must not tomb: %v %v", tomb, err)
	}
}
