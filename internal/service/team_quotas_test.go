package service

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
)

func quotaTestService(t *testing.T) (*Service, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return New(config.Config{}, slog.New(slog.NewTextHandler(io.Discard, nil)), st, nil, nil, nil, nil, nil, nil), st
}

func TestTeamQuotaAdminValidation(t *testing.T) {
	svc, _ := quotaTestService(t)
	ctx := context.Background()
	cases := []struct {
		name string
		team string
		req  models.TeamQuotaRequest
	}{
		{name: "bad team", team: "Bad Team", req: models.TeamQuotaRequest{MaxSandboxes: 1}},
		{name: "negative", team: "risk", req: models.TeamQuotaRequest{MaxSandboxes: -1}},
		{name: "limits nothing", team: "risk"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := svc.PutTeamQuota(ctx, tc.team, tc.req); !errors.Is(err, models.ErrInvalidTeamQuota) {
				t.Fatalf("put = %v, want ErrInvalidTeamQuota", err)
			}
		})
	}
	if _, err := svc.GetTeamQuota(ctx, "Bad Team"); !errors.Is(err, models.ErrInvalidTeamQuota) {
		t.Fatalf("get with a bad team = %v", err)
	}
	if err := svc.DeleteTeamQuota(ctx, "Bad Team"); !errors.Is(err, models.ErrInvalidTeamQuota) {
		t.Fatalf("delete with a bad team = %v", err)
	}
}

// One node: PUT is idempotent, GET reports usage counted from the store,
// DELETE converges, and a team no longer limited is no longer tracked.
func TestTeamQuotaSingleNodeLifecycle(t *testing.T) {
	svc, st := quotaTestService(t)
	ctx := context.Background()
	for _, sb := range []models.Sandbox{
		{ID: "sb-1", Image: "a", Status: models.SandboxStatusStarted, OwnerRef: "team:risk", CPU: 1, MemoryMB: 512},
		{ID: "sb-2", Image: "a", Status: models.SandboxStatusStopped, OwnerRef: "team:risk", CPU: 0, MemoryMB: 0},
	} {
		sb := sb
		if err := st.Create(ctx, &sb); err != nil {
			t.Fatal(err)
		}
	}
	q, err := svc.PutTeamQuota(ctx, "risk", models.TeamQuotaRequest{MaxSandboxes: 5})
	if err != nil || q.Generation != 1 || q.Usage == nil || q.Usage.Sandboxes != 2 || q.Usage.CPU != 1+models.DefaultCPU {
		t.Fatalf("put = %+v %v", q, err)
	}
	q, err = svc.PutTeamQuota(ctx, "risk", models.TeamQuotaRequest{MaxSandboxes: 5})
	if err != nil || q.Generation != 1 {
		t.Fatalf("the same PUT twice must be a no-op: %+v %v", q, err)
	}
	got, err := svc.GetTeamQuota(ctx, "risk")
	if err != nil || got.MaxSandboxes != 5 || got.Usage.Sandboxes != 2 {
		t.Fatalf("get = %+v %v", got, err)
	}
	for range 2 {
		if err := svc.DeleteTeamQuota(ctx, "risk"); err != nil {
			t.Fatalf("delete = %v", err)
		}
	}
	if _, err := svc.GetTeamQuota(ctx, "risk"); !errors.Is(err, models.ErrTeamQuotaNotFound) {
		t.Fatalf("get after delete = %v", err)
	}
	// Usage of an unlimited team is still countable from the store.
	if u, err := svc.teamQuotas.usage(ctx, st, "risk"); err != nil || u.Sandboxes != 2 {
		t.Fatalf("usage of an unlimited team = %+v %v", u, err)
	}
}

// A destroy on a path that never told the ledger must not hold a slot
// forever: before refusing, the ledger recounts from the store.
func TestTeamQuotaLedgerRecountsBeforeRefusing(t *testing.T) {
	svc, st := quotaTestService(t)
	ctx := context.Background()
	if _, err := svc.PutTeamQuota(ctx, "risk", models.TeamQuotaRequest{MaxSandboxes: 1}); err != nil {
		t.Fatal(err)
	}
	ticket, err := svc.admitTeamQuotaCreate(ctx, "team:risk", models.CreateSandboxRequest{})
	if err != nil || ticket == nil {
		t.Fatalf("first admit = %v %v", ticket, err)
	}
	ticket.settle(&models.CreateSandboxResponse{Sandbox: models.Sandbox{ID: "sb-ghost"}}, nil)
	// sb-ghost is in the ledger but not in the store: a destroy the ledger
	// missed. The next admit recounts and passes.
	if _, err := svc.admitTeamQuotaCreate(ctx, "team:risk", models.CreateSandboxRequest{}); err != nil {
		t.Fatalf("admit after a missed destroy = %v", err)
	}
	// Now the pending claim is real: a third create is refused.
	if _, err := svc.admitTeamQuotaCreate(ctx, "team:risk", models.CreateSandboxRequest{}); !errors.Is(err, models.ErrTeamQuotaExceeded) {
		t.Fatalf("over the quota = %v", err)
	}
	// No team, or no quota for the team: no claim at all.
	if tk, err := svc.admitTeamQuotaCreate(ctx, "", models.CreateSandboxRequest{}); tk != nil || err != nil {
		t.Fatalf("operator create = %v %v", tk, err)
	}
	if tk, err := svc.admitTeamQuotaCreate(ctx, "team:other", models.CreateSandboxRequest{}); tk != nil || err != nil {
		t.Fatalf("unlimited team = %v %v", tk, err)
	}
	_ = st
}

func TestTeamQuotaLedgerEdges(t *testing.T) {
	svc, st := quotaTestService(t)
	ctx := context.Background()
	if _, err := svc.PutTeamQuota(ctx, "risk", models.TeamQuotaRequest{MaxCPU: 2}); err != nil {
		t.Fatal(err)
	}
	ticket, err := svc.admitTeamQuotaCreate(ctx, "team:risk", models.CreateSandboxRequest{CPU: 1})
	if err != nil {
		t.Fatal(err)
	}
	// A failed create gives the claim back.
	ticket.settle(nil, errors.New("boom"))
	_, usage, found, _ := svc.teamQuotas.status(ctx, st, "risk")
	if !found || usage.Sandboxes != 0 {
		t.Fatalf("after a failed create = %+v", usage)
	}
	// Resize of a sandbox the ledger never saw counts it whole; undo removes it.
	hold, err := svc.teamQuotas.beginResize(ctx, st, "risk", "sb-x", 1, 128)
	if err != nil {
		t.Fatal(err)
	}
	hold.undo()
	if _, usage, _, _ = svc.teamQuotas.status(ctx, st, "risk"); usage.Sandboxes != 0 {
		t.Fatalf("undo of an unseen sandbox = %+v", usage)
	}
	// Resize of a tracked sandbox; undo restores the old size.
	tk, _ := svc.admitTeamQuotaCreate(ctx, "team:risk", models.CreateSandboxRequest{CPU: 1})
	tk.settle(&models.CreateSandboxResponse{Sandbox: models.Sandbox{ID: "sb-y"}}, nil)
	hold, err = svc.teamQuotas.beginResize(ctx, st, "risk", "sb-y", 2, models.DefaultMemoryMB)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.teamQuotas.beginResize(ctx, st, "risk", "sb-y", 3, models.DefaultMemoryMB); !errors.Is(err, models.ErrTeamQuotaExceeded) {
		t.Fatalf("growth past the quota = %v", err)
	}
	hold.undo()
	if _, usage, _, _ = svc.teamQuotas.status(ctx, st, "risk"); usage.CPU != 1 {
		t.Fatalf("undo = %+v, want the old CPU 1", usage)
	}
	// release and settle after the quota is gone are harmless.
	svc.releaseTeamQuota(&models.Sandbox{ID: "sb-y", OwnerRef: "team:risk"})
	if _, usage, _, _ = svc.teamQuotas.status(ctx, st, "risk"); usage.Sandboxes != 0 {
		t.Fatalf("after release = %+v", usage)
	}
	tk, _ = svc.admitTeamQuotaCreate(ctx, "team:risk", models.CreateSandboxRequest{CPU: 1})
	if err := svc.DeleteTeamQuota(ctx, "risk"); err != nil {
		t.Fatal(err)
	}
	tk.settle(&models.CreateSandboxResponse{Sandbox: models.Sandbox{ID: "sb-z"}}, nil)
	hold.undo()
	hold.settle(1, 1)
	svc.releaseTeamQuota(&models.Sandbox{ID: "sb-z", OwnerRef: "team:risk"})
	svc.releaseTeamQuota(nil)
	var nilTicket *teamQuotaTicket
	nilTicket.settle(nil, nil)
	// A team with no quota, or a sandbox no team owns, takes no hold.
	if h, err := svc.admitTeamQuotaResize(ctx, &models.Sandbox{ID: "a", OwnerRef: "team:risk", CPU: 2, MemoryMB: 512}, models.ResizeSandboxRequest{CPU: 1, MemoryMB: 512}); err != nil || h != nil {
		t.Fatalf("resize with no quota = %v %v", h, err)
	}
	if h, err := svc.admitTeamQuotaResize(ctx, &models.Sandbox{ID: "a", CPU: 1}, models.ResizeSandboxRequest{CPU: 8, MemoryMB: 8192}); err != nil || h != nil {
		t.Fatalf("operator resize = %v %v", h, err)
	}
	var nilHold *teamQuotaResize
	nilHold.undo()
	nilHold.settle(1, 1)
	if nilHold.specHolds(models.ResizeSandboxRequest{CPU: 1}) {
		t.Fatal("a nil hold wrote nothing")
	}
	if err := svc.checkTeamQuotaForStart(ctx, &models.Sandbox{ID: "a"}); err != nil {
		t.Fatalf("operator start = %v", err)
	}
	if err := svc.checkTeamQuotaForStart(ctx, &models.Sandbox{ID: "a", OwnerRef: "team:risk"}); err != nil {
		t.Fatalf("start with no quota = %v", err)
	}
}

// quotaStubCluster is the replicated quota store a cluster node offers.
type quotaStubCluster struct {
	*cluster.Noop
	writes    []cluster.TeamQuotaWriteRequest
	writeErr  error
	read      cluster.TeamQuotaReadResponse
	readErr   error
	spec      *models.CreateSandboxRequest
	upserts   []models.CreateSandboxRequest
	upsertErr error
}

func (c *quotaStubCluster) WriteTeamQuota(_ context.Context, req cluster.TeamQuotaWriteRequest) (cluster.TeamQuotaWriteResponse, error) {
	c.writes = append(c.writes, req)
	if c.writeErr != nil {
		return cluster.TeamQuotaWriteResponse{}, c.writeErr
	}
	rec := req.Quota
	rec.Generation = 1
	rec.CreatedUnixNano, rec.UpdatedUnixNano = time.Unix(10, 0).UnixNano(), time.Unix(20, 0).UnixNano()
	return cluster.TeamQuotaWriteResponse{Quota: rec, Changed: true}, nil
}

func (c *quotaStubCluster) ReadTeamQuota(context.Context, cluster.TeamQuotaReadRequest) (cluster.TeamQuotaReadResponse, error) {
	return c.read, c.readErr
}

func (c *quotaStubCluster) SpecOf(string) *models.CreateSandboxRequest {
	if c.spec == nil {
		return nil
	}
	cp := *c.spec
	return &cp
}

func (c *quotaStubCluster) UpsertSpec(_ context.Context, _ string, spec *models.CreateSandboxRequest, _ cluster.PlacementSecrets) error {
	if c.upsertErr != nil {
		err := c.upsertErr
		c.upsertErr = nil
		return err
	}
	c.upserts = append(c.upserts, *spec)
	cp := *spec
	c.spec = &cp
	return nil
}

func clusterQuotaService(t *testing.T, stub *quotaStubCluster) *Service {
	t.Helper()
	svc := New(config.Config{EnableCluster: true, NodeRole: config.NodeRoleMixed}, slog.New(slog.NewTextHandler(io.Discard, nil)), nil, nil, nil, nil, nil, nil, nil)
	stub.Noop = cluster.NewNoop("node-a", "", "")
	svc.AttachCluster(stub)
	return svc
}

func TestTeamQuotaClusterAdmin(t *testing.T) {
	stub := &quotaStubCluster{read: cluster.TeamQuotaReadResponse{Found: true, Authoritative: true,
		Quota: cluster.TeamQuotaRecord{Team: "risk", MaxSandboxes: 4}, Usage: models.TeamQuotaUsage{Sandboxes: 2}}}
	svc := clusterQuotaService(t, stub)
	ctx := context.Background()
	q, err := svc.PutTeamQuota(ctx, "risk", models.TeamQuotaRequest{MaxSandboxes: 4})
	if err != nil || q.MaxSandboxes != 4 || q.Usage.Sandboxes != 2 || !q.CreatedAt.Equal(time.Unix(10, 0).UTC()) {
		t.Fatalf("put = %+v %v", q, err)
	}
	if len(stub.writes) != 1 || stub.writes[0].Delete || stub.writes[0].Quota.Team != "risk" {
		t.Fatalf("writes = %+v", stub.writes)
	}
	if got, err := svc.GetTeamQuota(ctx, "risk"); err != nil || got.Usage.Sandboxes != 2 {
		t.Fatalf("get = %+v %v", got, err)
	}
	if err := svc.DeleteTeamQuota(ctx, "risk"); err != nil || !stub.writes[1].Delete {
		t.Fatalf("delete = %v %+v", err, stub.writes)
	}
	stub.read.Found = false
	if _, err := svc.GetTeamQuota(ctx, "risk"); !errors.Is(err, models.ErrTeamQuotaNotFound) {
		t.Fatalf("get with no quota = %v", err)
	}
	stub.writeErr = cluster.ErrClusterVersion
	if _, err := svc.PutTeamQuota(ctx, "risk", models.TeamQuotaRequest{MaxSandboxes: 1}); !errors.Is(err, ErrTeamQuotaUnavailable) {
		t.Fatalf("put during upgrade = %v, want ErrTeamQuotaUnavailable", err)
	}
	if err := svc.DeleteTeamQuota(ctx, "risk"); !errors.Is(err, ErrTeamQuotaUnavailable) {
		t.Fatalf("delete during upgrade = %v", err)
	}
	stub.writeErr = nil
	stub.readErr = errors.New("leader gone")
	if _, err := svc.GetTeamQuota(ctx, "risk"); !errors.Is(err, ErrTeamQuotaUnavailable) {
		t.Fatalf("get with no leader = %v", err)
	}
	if _, err := svc.PutTeamQuota(ctx, "risk", models.TeamQuotaRequest{MaxSandboxes: 1}); !errors.Is(err, ErrTeamQuotaUnavailable) {
		t.Fatalf("put whose usage read fails = %v", err)
	}
	if !errors.Is(quotaClusterError(models.ErrTeamQuotaExceeded), models.ErrTeamQuotaExceeded) {
		t.Fatal("quotaClusterError must keep the quota sentinel")
	}

	// A cluster without a replicated quota store answers 503.
	plain := New(config.Config{EnableCluster: true}, slog.New(slog.NewTextHandler(io.Discard, nil)), nil, nil, nil, nil, nil, nil, nil)
	plain.AttachCluster(cluster.NewNoop("n", "", ""))
	if _, err := plain.PutTeamQuota(ctx, "risk", models.TeamQuotaRequest{MaxSandboxes: 1}); !errors.Is(err, ErrTeamQuotaUnavailable) {
		t.Fatalf("put without a quota store = %v", err)
	}
	if _, err := plain.GetTeamQuota(ctx, "risk"); !errors.Is(err, ErrTeamQuotaUnavailable) {
		t.Fatalf("get without a quota store = %v", err)
	}
	if err := plain.DeleteTeamQuota(ctx, "risk"); !errors.Is(err, ErrTeamQuotaUnavailable) {
		t.Fatalf("delete without a quota store = %v", err)
	}
	if err := plain.checkTeamQuotaForStart(ctx, &models.Sandbox{OwnerRef: "team:risk"}); err != nil {
		t.Fatalf("start check without a quota store = %v", err)
	}
	if _, err := plain.withTeamUsage(ctx, models.TeamQuota{Team: "risk"}); !errors.Is(err, ErrTeamQuotaUnavailable) {
		t.Fatalf("usage without a quota store = %v", err)
	}
}

// In a cluster a growing resize records its new size first, through the
// leader's quota admission, and writes the old size back when the resize
// then fails.
func TestTeamQuotaClusterResizeAndStart(t *testing.T) {
	stub := &quotaStubCluster{spec: &models.CreateSandboxRequest{Image: "a", CPU: 1, MemoryMB: 512}}
	svc := clusterQuotaService(t, stub)
	ctx := context.Background()
	sb := &models.Sandbox{ID: "sb-1", OwnerRef: "team:risk", CPU: 1, MemoryMB: 512}
	if tk, err := svc.admitTeamQuotaCreate(ctx, "team:risk", models.CreateSandboxRequest{}); tk != nil || err != nil {
		t.Fatalf("a cluster node never claims locally: %v %v", tk, err)
	}
	svc.releaseTeamQuota(sb) // a no-op in a cluster

	hold, err := svc.admitTeamQuotaResize(ctx, sb, models.ResizeSandboxRequest{CPU: 2, MemoryMB: 512})
	if err != nil || hold == nil || len(stub.upserts) != 1 || stub.upserts[0].CPU != 2 {
		t.Fatalf("grow = %v %v %+v", hold, err, stub.upserts)
	}
	if !hold.specHolds(models.ResizeSandboxRequest{CPU: 2}) || hold.specHolds(models.ResizeSandboxRequest{CPU: 2, DiskGB: 5}) {
		t.Fatal("specHolds: the admitted write holds a CPU-only resize, not one that also changes disk")
	}
	hold.undo()
	if len(stub.upserts) != 2 || stub.upserts[1].CPU != 1 {
		t.Fatalf("undo must write the old size back: %+v", stub.upserts)
	}
	// A shrink writes nothing up front: the write-through records it.
	if h, err := svc.admitTeamQuotaResize(ctx, sb, models.ResizeSandboxRequest{CPU: 0.5, MemoryMB: 512}); err != nil || h != nil || len(stub.upserts) != 2 {
		t.Fatalf("shrink = %v %v %+v", h, err, stub.upserts)
	}
	stub.upsertErr = models.ErrTeamQuotaExceeded
	if _, err := svc.admitTeamQuotaResize(ctx, sb, models.ResizeSandboxRequest{CPU: 4, MemoryMB: 512}); !errors.Is(err, models.ErrTeamQuotaExceeded) {
		t.Fatalf("grow past the quota = %v", err)
	}
	stub.upsertErr = errors.New("no leader")
	if _, err := svc.admitTeamQuotaResize(ctx, sb, models.ResizeSandboxRequest{CPU: 4, MemoryMB: 512}); !errors.Is(err, ErrTeamQuotaUnavailable) {
		t.Fatalf("grow with no leader = %v, want ErrTeamQuotaUnavailable (fail closed)", err)
	}
	stub.spec = nil
	if h, err := svc.admitTeamQuotaResize(ctx, sb, models.ResizeSandboxRequest{CPU: 4, MemoryMB: 512}); err != nil || h != nil {
		t.Fatalf("no replicated spec and no quota = %v %v", h, err)
	}

	// Start: refused only when the team is already over its quota.
	stub.read = cluster.TeamQuotaReadResponse{Found: true, Quota: cluster.TeamQuotaRecord{Team: "risk", MaxSandboxes: 1}, Usage: models.TeamQuotaUsage{Sandboxes: 2}}
	if err := svc.checkTeamQuotaForStart(ctx, sb); !errors.Is(err, models.ErrTeamQuotaExceeded) {
		t.Fatalf("start over the quota = %v", err)
	}
	stub.read.Usage.Sandboxes = 1
	if err := svc.checkTeamQuotaForStart(ctx, sb); err != nil {
		t.Fatalf("start at the quota = %v", err)
	}
	stub.readErr = errors.New("leader gone")
	if err := svc.checkTeamQuotaForStart(ctx, sb); err != nil {
		t.Fatalf("a failed read lets the start through: %v", err)
	}
}
