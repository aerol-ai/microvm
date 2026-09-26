package service

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	storepkg "github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/secrets"
)

// failoverReadyPage builds a List page of recreate-policy sandboxes on a
// node with `members` gossip members, with a sealed row held locally for
// every sandbox (generation 1, recipients self + one backup) and ACKs
// recorded for both holders, so each row resolves to ready=true.
func failoverReadyPage(t testing.TB, st *storepkg.Store, rows, members int) (*Service, []*models.Sandbox) {
	t.Helper()
	ctx := context.Background()
	mem := make([]cluster.Member, 0, members)
	for i := range members {
		mem = append(mem, cluster.Member{NodeID: fmt.Sprintf("node-%d", i), Alive: i%50 != 7})
	}
	svc := &Service{cfg: config.Config{}, store: st}
	svc.AttachCluster(&placementRecipientsCluster{
		Noop:          cluster.NewNoop("node-0", "", ""),
		recipients:    []string{"node-0", "node-1"},
		incarnationID: "inc",
		members:       mem,
	})
	sandboxes := make([]*models.Sandbox, 0, rows)
	now := time.Now().UTC()
	for i := range rows {
		id := fmt.Sprintf("sb-%d", i)
		if _, err := st.PutClusterSecret(ctx, storepkg.ClusterSecretRecord{
			Ref: secrets.FormatRef(id, "inc", secrets.RefVersion), SandboxID: id, Version: secrets.RefVersion,
			Recipients: []string{"node-0", "node-1"}, SealedPayload: []byte("sealed"), SealGeneration: 1,
			CreatedAt: now, UpdatedAt: now,
		}); err != nil {
			t.Fatal(err)
		}
		clearSecretFanoutHolders(id)
		addSecretHolderNodes(id, "inc", 1, "node-0", "node-1")
		sandboxes = append(sandboxes, &models.Sandbox{ID: id, AuditIncarnationID: "inc", Failover: &models.Failover{Policy: models.FailoverPolicyRecreate}})
	}
	return svc, sandboxes
}

func TestFailoverReadyBatchMatchesPerRowAndReadsStoreOncePerPage(t *testing.T) {
	st := openSealTestStore(t)
	svc, page := failoverReadyPage(t, st, 120, 300)
	// A few rows that must resolve differently: one with no local row (self
	// cannot count), one without a policy (omitted), one whose backup is dead.
	page = append(page,
		&models.Sandbox{ID: "sb-unsealed", AuditIncarnationID: "inc", Failover: &models.Failover{Policy: models.FailoverPolicyRecreate}},
		&models.Sandbox{ID: "sb-plain"},
		nil,
	)
	clearSecretFanoutHolders("sb-unsealed")
	addSecretHolderNodes("sb-unsealed", "inc", 1, "node-0", "node-1")
	clearSecretFanoutHolders("sb-3")
	addSecretHolderNodes("sb-3", "inc", 1, "node-0", "node-7") // node-7 is dead in the fixture

	reads := failoverReadyStoreReads.Load()
	svc.failoverReadyBatch(context.Background(), page)
	if got := failoverReadyStoreReads.Load() - reads; got != 1 {
		t.Fatalf("store reads for one page = %d, want 1", got)
	}
	want := map[string]string{}
	for _, sb := range page {
		if sb == nil {
			continue
		}
		switch {
		case sb.FailoverReady == nil:
			want[sb.ID] = "omitted"
		case *sb.FailoverReady:
			want[sb.ID] = "true"
		default:
			want[sb.ID] = "false"
		}
	}
	if want["sb-plain"] != "omitted" || want["sb-unsealed"] != "false" || want["sb-3"] != "false" || want["sb-0"] != "true" || want["sb-119"] != "true" {
		t.Fatalf("page verdicts = plain:%s unsealed:%s dead-backup:%s first:%s last:%s", want["sb-plain"], want["sb-unsealed"], want["sb-3"], want["sb-0"], want["sb-119"])
	}
	// The single-row path is the same computation with a page of one.
	for _, sb := range page {
		if sb == nil {
			continue
		}
		single := &models.Sandbox{ID: sb.ID, AuditIncarnationID: sb.AuditIncarnationID, Failover: sb.Failover}
		got := svc.computeFailoverReady(context.Background(), single)
		verdict := "omitted"
		if got != nil {
			verdict = fmt.Sprint(*got)
		}
		if verdict != want[sb.ID] {
			t.Fatalf("%s: single-row verdict %s, batch %s", sb.ID, verdict, want[sb.ID])
		}
	}
	// A page with no recreate-policy rows does no store work at all.
	reads = failoverReadyStoreReads.Load()
	svc.failoverReadyBatch(context.Background(), []*models.Sandbox{{ID: "a"}, {ID: "b"}})
	if failoverReadyStoreReads.Load() != reads {
		t.Fatal("page without recreate rows hit the store")
	}
	// A page larger than one summary chunk is still one batch call.
	big := make([]*models.Sandbox, 0, 700)
	for i := range 700 {
		big = append(big, &models.Sandbox{ID: fmt.Sprintf("sb-%d", i), AuditIncarnationID: "inc", Failover: &models.Failover{Policy: models.FailoverPolicyRecreate}})
	}
	reads = failoverReadyStoreReads.Load()
	svc.failoverReadyBatch(context.Background(), big)
	if got := failoverReadyStoreReads.Load() - reads; got != 1 {
		t.Fatalf("store reads for a 700-row page = %d, want 1", got)
	}
}

func TestFailoverReadyBatchFailsClosedWhenStoreReadFails(t *testing.T) {
	st := openSealTestStore(t)
	svc, page := failoverReadyPage(t, st, 5, 10)
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	svc.failoverReadyBatch(context.Background(), page)
	for _, sb := range page {
		if sb.FailoverReady == nil || *sb.FailoverReady {
			t.Fatalf("%s: readiness with an unreadable store = %v, want false", sb.ID, sb.FailoverReady)
		}
	}
}

// BenchmarkFailoverReadyBatch is the review's scenario: a 100-row List page
// on a 2,000-node cluster. Before the batch rewrite each row rebuilt the
// alive set from the member slice and ran its own SQLite query.
func BenchmarkFailoverReadyBatch(b *testing.B) {
	st, err := storepkg.Open(filepath.Join(b.TempDir(), "state.db"))
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = st.Close() })
	svc, page := failoverReadyPage(b, st, 100, 2000)
	ctx := context.Background()
	b.ResetTimer()
	b.ReportAllocs()
	for range b.N {
		svc.failoverReadyBatch(ctx, page)
	}
}
