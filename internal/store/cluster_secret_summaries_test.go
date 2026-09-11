package store

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/secrets"
)

func TestClusterSecretSealSummariesBatchesAcrossChunks(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	const n = clusterSecretSummaryChunk*2 + 7
	refs := make([]string, 0, n+3)
	for i := range n {
		ref := secrets.FormatRef(fmt.Sprintf("sb-%d", i), "inc", secrets.RefVersion)
		refs = append(refs, ref)
		rec := ClusterSecretRecord{
			Ref: ref, SandboxID: fmt.Sprintf("sb-%d", i), Version: secrets.RefVersion,
			Recipients: []string{"node-a", fmt.Sprintf("node-%d", i%3)}, SealedPayload: []byte("x"),
			SealGeneration: int64(i%5 + 1), CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
		}
		if _, err := st.PutClusterSecret(ctx, rec); err != nil {
			t.Fatalf("put %d: %v", i, err)
		}
	}
	// Missing, blank and duplicate refs are harmless.
	refs = append(refs, secrets.FormatRef("sb-missing", "inc", secrets.RefVersion), "  ", refs[0])
	got, err := st.ClusterSecretSealSummaries(ctx, refs)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != n {
		t.Fatalf("summaries = %d, want %d", len(got), n)
	}
	for i := range n {
		sum, ok := got[secrets.FormatRef(fmt.Sprintf("sb-%d", i), "inc", secrets.RefVersion)]
		if !ok || sum.SealGeneration != int64(i%5+1) || len(sum.Recipients) != 2 || sum.Recipients[1] != fmt.Sprintf("node-%d", i%3) {
			t.Fatalf("summary %d = %+v ok=%v", i, sum, ok)
		}
	}
	if _, ok := got[secrets.FormatRef("sb-missing", "inc", secrets.RefVersion)]; ok {
		t.Fatal("missing ref reported")
	}
	if empty, err := st.ClusterSecretSealSummaries(ctx, nil); err != nil || len(empty) != 0 {
		t.Fatalf("empty = %v err=%v", empty, err)
	}
	// The per-row reader and the batch agree.
	gen, holds, err := st.ClusterSecretSealGeneration(ctx, "sb-3", "inc")
	if err != nil || !holds || gen != got[secrets.FormatRef("sb-3", "inc", secrets.RefVersion)].SealGeneration {
		t.Fatalf("point read = %d/%v/%v", gen, holds, err)
	}
	// Corrupt recipients fail loudly rather than silently emptying the set.
	if _, err := st.db.ExecContext(ctx, `UPDATE cluster_secrets SET recipients_json = 'nope' WHERE sandbox_id = 'sb-1'`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ClusterSecretSealSummaries(ctx, refs[:2]); err == nil {
		t.Fatal("corrupt recipients accepted")
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ClusterSecretSealSummaries(ctx, refs[:1]); err == nil {
		t.Fatal("closed store succeeded")
	}
}
