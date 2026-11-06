package store

import (
	"context"
	"errors"
	"sort"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

func TestTeamQuotaCRUD(t *testing.T) {
	st := openEgressProfileStore(t)
	ctx := context.Background()
	now := time.Now()
	limits := models.TeamQuotaRequest{MaxSandboxes: 3, MaxCPU: 4, MaxMemoryMB: 8192}
	q, changed, err := st.PutTeamQuota(ctx, "risk", limits, now)
	if err != nil || !changed || q.Generation != 1 || q.Team != "risk" || q.Limits() != limits || !q.CreatedAt.Equal(now.UTC()) {
		t.Fatalf("create = %+v %v %v", q, changed, err)
	}
	// The same body twice is a no-op: a retried PUT changes nothing.
	if q, changed, err = st.PutTeamQuota(ctx, "risk", limits, now.Add(time.Second)); err != nil || changed || q.Generation != 1 {
		t.Fatalf("same body must be a no-op: %+v %v %v", q, changed, err)
	}
	raised := models.TeamQuotaRequest{MaxSandboxes: 5}
	if q, changed, err = st.PutTeamQuota(ctx, "risk", raised, now.Add(2*time.Second)); err != nil || !changed || q.Generation != 2 || q.Limits() != raised || !q.CreatedAt.Equal(now.UTC()) {
		t.Fatalf("update = %+v %v %v", q, changed, err)
	}
	got, err := st.GetTeamQuota(ctx, "risk")
	if err != nil || got.Limits() != raised || got.Generation != 2 {
		t.Fatalf("get = %+v %v", got, err)
	}
	if _, err := st.GetTeamQuota(ctx, "other"); !errors.Is(err, models.ErrTeamQuotaNotFound) {
		t.Fatalf("missing team = %v, want ErrTeamQuotaNotFound", err)
	}
	if _, _, err := st.PutTeamQuota(ctx, "alpha", limits, now); err != nil {
		t.Fatal(err)
	}
	all, err := st.ListTeamQuotas(ctx)
	if err != nil || len(all) != 2 || all[0].Team != "alpha" || all[1].Team != "risk" {
		t.Fatalf("list = %+v %v", all, err)
	}
	if err := st.DeleteTeamQuota(ctx, "risk"); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteTeamQuota(ctx, "risk"); err != nil {
		t.Fatalf("a repeated delete must succeed: %v", err)
	}
	if _, err := st.GetTeamQuota(ctx, "risk"); !errors.Is(err, models.ErrTeamQuotaNotFound) {
		t.Fatalf("after delete = %v", err)
	}
}

// The ledger's source of truth: an owner's live sandboxes and their sizes,
// destroyed rows and other owners left out.
func TestTeamQuotaSandboxes(t *testing.T) {
	st := openEgressProfileStore(t)
	ctx := context.Background()
	rows := []models.Sandbox{
		{ID: "sb-a", Image: "alpine", Status: models.SandboxStatusStarted, OwnerRef: "team:risk", CPU: 1, MemoryMB: 512},
		{ID: "sb-b", Image: "alpine", Status: models.SandboxStatusStopped, OwnerRef: "team:risk", CPU: 2, MemoryMB: 1024},
		{ID: "sb-c", Image: "alpine", Status: models.SandboxStatusDestroyed, OwnerRef: "team:risk", CPU: 4, MemoryMB: 4096},
		{ID: "sb-d", Image: "alpine", Status: models.SandboxStatusStarted, OwnerRef: "team:other", CPU: 8, MemoryMB: 8192},
	}
	for i := range rows {
		if err := st.Create(ctx, &rows[i]); err != nil {
			t.Fatal(err)
		}
	}
	got, err := st.TeamQuotaSandboxes(ctx, "team:risk")
	if err != nil {
		t.Fatal(err)
	}
	sort.Slice(got, func(i, j int) bool { return got[i].ID < got[j].ID })
	want := []QuotaSandbox{{ID: "sb-a", CPU: 1, MemoryMB: 512}, {ID: "sb-b", CPU: 2, MemoryMB: 1024}}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("quota sandboxes = %+v, want %+v", got, want)
	}
}

// Every quota call reports a database failure instead of a wrong answer: a
// quota that cannot be read must not read as "no limit".
func TestTeamQuotaStoreErrors(t *testing.T) {
	st := openEgressProfileStore(t)
	ctx := context.Background()
	_ = st.Close()
	if _, _, err := st.PutTeamQuota(ctx, "risk", models.TeamQuotaRequest{MaxSandboxes: 1}, time.Now()); err == nil {
		t.Fatal("put on a closed store")
	}
	if _, err := st.GetTeamQuota(ctx, "risk"); err == nil || errors.Is(err, models.ErrTeamQuotaNotFound) {
		t.Fatalf("get on a closed store = %v, want a real error, never not-found", err)
	}
	if _, err := st.ListTeamQuotas(ctx); err == nil {
		t.Fatal("list on a closed store")
	}
	if err := st.DeleteTeamQuota(ctx, "risk"); err == nil {
		t.Fatal("delete on a closed store")
	}
	if _, err := st.TeamQuotaSandboxes(ctx, "team:risk"); err == nil {
		t.Fatal("quota sandboxes on a closed store")
	}
}
