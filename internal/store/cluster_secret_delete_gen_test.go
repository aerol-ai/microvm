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
	if err := st.PutClusterSecret(ctx, ClusterSecretRecord{
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
	if err := st.PutClusterSecret(ctx, ClusterSecretRecord{
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
