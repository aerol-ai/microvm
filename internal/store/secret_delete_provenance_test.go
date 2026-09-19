package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/secrets"
)

// The provenance map is what fences a storage-retirement discharge, so its
// encoding has to survive a legacy row (no column), a merge, and a recipient
// leaving the obligation.
func TestSecretDeleteProvenanceEncoding(t *testing.T) {
	old := time.Now().Add(-time.Hour).UTC().Truncate(time.Second)
	now := time.Now().UTC().Truncate(time.Second)

	// A row written before the column existed has no provenance; callers fall
	// back to the row-wide created_at.
	if got, err := decodeSecretDeleteProvenance(""); err != nil || got != nil {
		t.Fatalf("legacy row decoded to %v err=%v", got, err)
	}
	if _, err := decodeSecretDeleteProvenance("{not json"); err == nil {
		t.Fatal("a corrupt provenance blob decoded cleanly")
	}

	raw, err := mergeSecretDeleteProvenance("", []string{"peer-a"}, old)
	if err != nil {
		t.Fatal(err)
	}
	merged, err := mergeSecretDeleteProvenance(raw, []string{"peer-a", "peer-b"}, now)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeSecretDeleteProvenance(merged)
	if err != nil {
		t.Fatal(err)
	}
	if !decoded["peer-a"].Equal(old) {
		t.Fatalf("peer-a = %v, want its own older timestamp kept across the merge", decoded["peer-a"])
	}
	if !decoded["peer-b"].Equal(now) {
		t.Fatalf("peer-b = %v, want the new copy's timestamp", decoded["peer-b"])
	}

	// A recipient that is no longer owed anything drops out, so the map
	// cannot outgrow the recipient list.
	shrunk, err := mergeSecretDeleteProvenance(merged, []string{"peer-b"}, now)
	if err != nil {
		t.Fatal(err)
	}
	decoded, _ = decodeSecretDeleteProvenance(shrunk)
	if len(decoded) != 1 {
		t.Fatalf("provenance kept %d entries for one recipient", len(decoded))
	}
	if _, err := mergeSecretDeleteProvenance("{not json", []string{"peer-a"}, now); err == nil {
		t.Fatal("a corrupt existing blob merged cleanly")
	}
}

// With no copiedAt supplied, the sealed row's own last write is the best
// evidence of when its recipients received their copies.
func TestSecretDeleteOutboxDefaultsProvenanceFromTheSealedRow(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	ctx := context.Background()

	if _, err := st.PutClusterSecret(ctx, ClusterSecretRecord{
		Ref:            secrets.FormatRef("sb-prov", "inc", secrets.RefVersion),
		SandboxID:      "sb-prov",
		Version:        secrets.RefVersion,
		Recipients:     []string{"peer-a"},
		SealedPayload:  []byte("sealed"),
		SealGeneration: 1,
	}); err != nil {
		t.Fatalf("seed sealed row: %v", err)
	}
	rowWritten := time.Now().UTC()

	// No copiedAt: the live sealed row dates the copies.
	if err := st.UpsertSecretDeleteOutbox(ctx, "sb-prov", "inc", []string{"peer-a"}, 1); err != nil {
		t.Fatal(err)
	}
	rec, err := st.GetSecretDeleteOutboxForIncarnation(ctx, "sb-prov", "inc")
	if err != nil || rec == nil {
		t.Fatalf("outbox row: %v", err)
	}
	at, ok := rec.RecipientCopiedAt["peer-a"]
	if !ok {
		t.Fatal("no provenance recorded for the recipient")
	}
	if at.After(rowWritten.Add(time.Second)) {
		t.Fatalf("provenance %v is later than the sealed row's own write; it must not be dated at journal time", at)
	}
}
