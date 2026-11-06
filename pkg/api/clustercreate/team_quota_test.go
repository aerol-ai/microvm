package clustercreate

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/models"
)

// Per-team quotas on one node (plan item P2), end to end through the real
// create path with a fake runtime: the race for a team's last slots, a failed
// create giving its slot back, destroy freeing room, resize growth refused,
// and a start refused once an admin lowered the quota.
func teamCtx(team string) context.Context {
	return controlplane.ContextWithAccess(context.Background(), controlplane.Access{
		Identity: controlplane.Identity{OwnerRef: controlplane.TeamOwnerRef(team)},
		Role:     controlplane.RoleRunner,
	})
}

func TestSingleNodeTeamQuotaConcurrentCreates(t *testing.T) {
	rt := newFakeRuntime()
	rt.createDelay = 20 * time.Millisecond // keep creates in flight together
	svc, _ := newCreateServiceWithRuntime(t, nil, rt, true)
	admin := context.Background()
	if _, err := svc.PutTeamQuota(admin, "risk", models.TeamQuotaRequest{MaxSandboxes: 3}); err != nil {
		t.Fatalf("PutTeamQuota: %v", err)
	}

	const n = 10
	var ok, refused atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	ids := make(chan string, n)
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			resp, err := svc.CreateSandbox(teamCtx("risk"), models.CreateSandboxRequest{Image: "alpine"})
			switch {
			case err == nil:
				ok.Add(1)
				ids <- resp.Sandbox.ID
			case errors.Is(err, models.ErrTeamQuotaExceeded):
				refused.Add(1)
			default:
				t.Errorf("create: %v", err)
			}
		}()
	}
	close(start)
	wg.Wait()
	close(ids)
	if ok.Load() != 3 || refused.Load() != n-3 {
		t.Fatalf("granted %d refused %d, want exactly 3 and %d", ok.Load(), refused.Load(), n-3)
	}
	q, err := svc.GetTeamQuota(admin, "risk")
	if err != nil || q.Usage == nil || q.Usage.Sandboxes != 3 {
		t.Fatalf("quota = %+v err=%v, want usage 3", q, err)
	}

	// Another team, and the operator, are not limited by risk's quota.
	if _, err := svc.CreateSandbox(teamCtx("other"), models.CreateSandboxRequest{Image: "alpine"}); err != nil {
		t.Fatalf("another team: %v", err)
	}
	if _, err := svc.CreateSandbox(admin, models.CreateSandboxRequest{Image: "alpine"}); err != nil {
		t.Fatalf("operator: %v", err)
	}

	// A destroy frees a slot.
	first := <-ids
	if err := svc.DestroySandbox(teamCtx("risk"), first); err != nil {
		t.Fatalf("destroy: %v", err)
	}
	if _, err := svc.CreateSandbox(teamCtx("risk"), models.CreateSandboxRequest{Image: "alpine"}); err != nil {
		t.Fatalf("create after destroy: %v", err)
	}
	// A failed create gives its claim back: with the quota full again, a
	// raise by one and a failing create still leaves that one slot free.
	if _, err := svc.PutTeamQuota(admin, "risk", models.TeamQuotaRequest{MaxSandboxes: 4}); err != nil {
		t.Fatal(err)
	}
	rt.mu.Lock()
	rt.failOnce = errors.New("runtime boom")
	rt.mu.Unlock()
	if _, err := svc.CreateSandbox(teamCtx("risk"), models.CreateSandboxRequest{Image: "alpine"}); err == nil || errors.Is(err, models.ErrTeamQuotaExceeded) {
		t.Fatalf("failing create = %v, want the runtime error", err)
	}
	if _, err := svc.CreateSandbox(teamCtx("risk"), models.CreateSandboxRequest{Image: "alpine"}); err != nil {
		t.Fatalf("the failed create kept its slot: %v", err)
	}
}

func TestSingleNodeTeamQuotaResizeAndStart(t *testing.T) {
	svc, _ := newCreateServiceWithRuntime(t, nil, newFakeRuntime(), true)
	admin := context.Background()
	if _, err := svc.PutTeamQuota(admin, "risk", models.TeamQuotaRequest{MaxCPU: 2, MaxMemoryMB: 4096}); err != nil {
		t.Fatal(err)
	}
	ctx := teamCtx("risk")
	resp, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{Image: "alpine", CPU: 1, MemoryMB: 1024})
	if err != nil {
		t.Fatal(err)
	}
	id := resp.Sandbox.ID
	// Resize used to re-admit against the host only.
	if _, err := svc.ResizeSandbox(ctx, id, models.ResizeSandboxRequest{CPU: 3}); !errors.Is(err, models.ErrTeamQuotaExceeded) {
		t.Fatalf("growing resize = %v, want ErrTeamQuotaExceeded", err)
	}
	if _, err := svc.ResizeSandbox(ctx, id, models.ResizeSandboxRequest{CPU: 2}); err != nil {
		t.Fatalf("resize within the quota: %v", err)
	}
	q, _ := svc.GetTeamQuota(admin, "risk")
	if q.Usage.CPU != 2 {
		t.Fatalf("usage after resize = %+v", q.Usage)
	}
	if _, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{Image: "alpine", CPU: 0.5}); !errors.Is(err, models.ErrTeamQuotaExceeded) {
		t.Fatalf("create past the CPU quota after a resize = %v", err)
	}
	if _, err := svc.ResizeSandbox(ctx, id, models.ResizeSandboxRequest{CPU: 1}); err != nil {
		t.Fatalf("shrinking resize: %v", err)
	}

	// A stopped sandbox still counts; lowering the quota below what the team
	// holds keeps it from being started again.
	if _, err := svc.StopSandbox(ctx, id); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if _, err := svc.PutTeamQuota(admin, "risk", models.TeamQuotaRequest{MaxCPU: 0.5}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.StartSandbox(ctx, id); !errors.Is(err, models.ErrTeamQuotaExceeded) {
		t.Fatalf("start over a lowered quota = %v, want ErrTeamQuotaExceeded", err)
	}
	if err := svc.DeleteTeamQuota(admin, "risk"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.StartSandbox(ctx, id); err != nil {
		t.Fatalf("start with no quota: %v", err)
	}
}
