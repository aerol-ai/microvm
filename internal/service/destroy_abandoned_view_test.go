package service

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/models"
)

// A Daytona DELETE or a Runloop shutdown of a sandbox left on a node an
// operator deleted (DestroyAbandonedSandbox). The server that takes it has
// no row, so the service deletes the placement and hands back the sandbox
// as the placement describes it, for the facade's answer.

// namedAbandonedServer is deletedNodeServer with the cluster's name index
// (OwnerOfName, keyed owner + name) and a hook that runs once after this
// node's own placement read: a change that lands between that read and the
// leader's.
type namedAbandonedServer struct {
	*deletedNodeServer
	names          map[string]string
	afterLocalRead func()
}

func (c *namedAbandonedServer) OwnerOfName(owner, name string) (string, cluster.OwnerInfo, error) {
	id, ok := c.names[owner+"/"+name]
	if !ok {
		return "", cluster.OwnerInfo{}, cluster.ErrUnknownSandbox
	}
	return id, cluster.OwnerInfo{}, nil
}

func (c *namedAbandonedServer) PlacementOf(id string) (cluster.Placement, bool) {
	p, ok := c.deletedNodeServer.PlacementOf(id)
	if hook := c.afterLocalRead; ok && hook != nil {
		c.afterLocalRead = nil
		hook()
	}
	return p, ok
}

func newAbandonedViewHarness(t *testing.T) (*Service, *namedAbandonedServer) {
	t.Helper()
	svc, _, c := newAbandonedHarness(t, true)
	nc := &namedAbandonedServer{deletedNodeServer: c.(*deletedNodeServer), names: map[string]string{}}
	svc.AttachCluster(nc)
	return svc, nc
}

func tenantCtx(owner string) context.Context {
	return controlplane.ContextWithAccess(context.Background(), controlplane.Access{Identity: controlplane.Identity{OwnerRef: owner}})
}

func TestDestroyAbandonedSandbox(t *testing.T) {
	const id = "sb-abandoned-view"
	cases := []struct {
		name   string
		owner  string
		edit   func(*cluster.Placement)
		ctx    context.Context
		ref    string
		byName bool
		want   error
		gone   bool
	}{
		{name: "by id, still named on the deleted node", owner: abandonedDeleted, gone: true},
		{name: "by id, orphaned from the deleted node", owner: abandonedDeleted, edit: orphanedFrom(abandonedDeleted), gone: true},
		{name: "by id, the tenant's own", owner: abandonedDeleted, ctx: tenantCtx("acct-a"), gone: true},
		{name: "by the tenant's name for it", owner: abandonedDeleted, ctx: tenantCtx("acct-a"), ref: "web", byName: true, gone: true},
		// What must keep its 404 and its placement.
		{name: "a name where only ids are taken", owner: abandonedDeleted, ctx: tenantCtx("acct-a"), ref: "web", want: store.ErrNotFound},
		{name: "another tenant's name", owner: abandonedDeleted, ctx: tenantCtx("acct-b"), ref: "web", byName: true, want: store.ErrNotFound},
		{name: "another tenant's id", owner: abandonedDeleted, ctx: tenantCtx("acct-b"), want: store.ErrNotFound},
		{name: "orphan of a node that only died", owner: abandonedDied, edit: orphanedFrom(abandonedDied), want: store.ErrNotFound},
		{name: "on a live node", owner: abandonedLive, want: store.ErrNotFound},
		{name: "a reservation on the deleted node", owner: abandonedDeleted, edit: func(p *cluster.Placement) { p.State = cluster.PlacementStateReserved }, want: store.ErrNotFound},
		{name: "an unknown id", owner: abandonedDeleted, ref: "sb-nobody", want: store.ErrNotFound},
		{name: "no id", owner: abandonedDeleted, ref: " ", want: store.ErrNotFound},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc, c := newAbandonedViewHarness(t)
			c.put(abandonedTestPlacement(id, tc.owner, tc.edit))
			c.names["acct-a/web"] = id
			ctx, ref := tc.ctx, tc.ref
			if ctx == nil {
				ctx = context.Background()
			}
			if ref == "" {
				ref = id
			}
			sb, _, err := svc.DestroyAbandonedSandbox(ctx, ref, tc.byName, models.FacadeDaytona)
			if !errors.Is(err, tc.want) {
				t.Fatalf("DestroyAbandonedSandbox = %v, want %v", err, tc.want)
			}
			_, found := c.get(id)
			if !tc.gone {
				if found != true || c.deleteCalls != 0 || c.reads != 0 {
					t.Fatalf("placement found=%v, deletes=%d, leader reads=%d: want it untouched and no leader read", found, c.deleteCalls, c.reads)
				}
				return
			}
			if found {
				t.Fatal("placement still there after the delete")
			}
			if sb == nil || sb.ID != id || sb.Status != models.SandboxStatusDestroyed {
				t.Fatalf("sandbox = %+v, want %s destroyed", sb, id)
			}
			// A retry finds nothing, and gets the normal 404.
			if _, _, err := svc.DestroyAbandonedSandbox(ctx, ref, tc.byName, models.FacadeDaytona); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("retry = %v, want ErrNotFound", err)
			}
		})
	}
}

// Only a server deletes another node's placement, and only in a cluster:
// anywhere else the facade's 404 stays, and nothing is read or written.
func TestDestroyAbandonedSandboxOnlyOnAServer(t *testing.T) {
	const id = "sb-abandoned-where"
	t.Run("a worker or gateway", func(t *testing.T) {
		svc, dc, _ := newAbandonedHarness(t, false)
		dc.put(abandonedTestPlacement(id, abandonedDeleted, nil))
		if _, _, err := svc.DestroyAbandonedSandbox(context.Background(), id, false, models.FacadeRunloop); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("on a worker = %v, want ErrNotFound", err)
		}
		if _, ok := dc.get(id); !ok || dc.deleteCalls != 0 {
			t.Fatal("a worker touched the placement")
		}
	})
	t.Run("cluster mode off", func(t *testing.T) {
		svc, c := newAbandonedViewHarness(t)
		svc.cfg.EnableCluster = false
		c.put(abandonedTestPlacement(id, abandonedDeleted, nil))
		if _, _, err := svc.DestroyAbandonedSandbox(context.Background(), id, false, models.FacadeRunloop); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("cluster off = %v, want ErrNotFound", err)
		}
		if _, ok := c.get(id); !ok || c.reads != 0 {
			t.Fatal("cluster off read or touched the placement")
		}
	})
	t.Run("a nil service", func(t *testing.T) {
		var svc *Service
		if _, _, err := svc.DestroyAbandonedSandbox(context.Background(), id, false, models.FacadeRunloop); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("nil service = %v, want ErrNotFound", err)
		}
	})
}

// The answer is built from the placement and its replicated spec: what the
// SDKs read back (name, size, labels, lifecycle, creation time) and the
// facade's own state when the spec carries it.
func TestDestroyAbandonedSandboxView(t *testing.T) {
	public := true
	created := time.Date(2026, 11, 20, 8, 30, 0, 0, time.UTC)
	p := abandonedTestPlacement("sb-view", abandonedDeleted, func(p *cluster.Placement) {
		p.Name = "web"
		p.CreatedUnix = created.Unix()
		p.UpdatedUnix = created.Add(time.Hour).Unix()
		p.Spec = &models.CreateSandboxRequest{
			Image: "alpine:3.20", CPU: 2, MemoryMB: 4096, DiskGB: 10, OSUser: "daytona",
			NetworkBlockAll: true, AllowPublicTraffic: &public, Runtime: "gvisor",
			GPUs: &models.GPURequest{Count: 1}, Tags: map[string]string{"team": "a"},
			Lifecycle:   &models.Lifecycle{StopIfIdleFor: 15 * time.Minute},
			CompatState: map[string]string{models.FacadeDaytona: `{"target":"us"}`},
		}
	})

	sb, state := abandonedSandboxView(p, models.FacadeDaytona)
	if sb.ID != "sb-view" || sb.Name != "web" || sb.OwnerRef != "acct-a" || sb.Status != models.SandboxStatusDestroyed {
		t.Fatalf("identity = %+v", sb)
	}
	if !sb.CreatedAt.Equal(created) || !sb.UpdatedAt.Equal(created.Add(time.Hour)) {
		t.Fatalf("times = %v / %v", sb.CreatedAt, sb.UpdatedAt)
	}
	if sb.Image != "alpine:3.20" || sb.CPU != 2 || sb.MemoryMB != 4096 || sb.DiskGB != 10 || sb.OSUser != "daytona" ||
		!sb.NetworkBlockAll || sb.AllowPublicTraffic == nil || !*sb.AllowPublicTraffic || sb.Runtime != "gvisor" ||
		sb.GPUs == nil || sb.GPUs.Count != 1 || sb.Lifecycle.StopIfIdleFor != 15*time.Minute || sb.Tags["team"] != "a" || sb.Env != nil {
		t.Fatalf("spec fields = %+v", sb)
	}
	if state == nil || state.SandboxID != "sb-view" || state.Facade != models.FacadeDaytona || state.StateJSON != `{"target":"us"}` {
		t.Fatalf("facade state = %+v", state)
	}
	// The view's labels are its own copy.
	sb.Tags["team"] = "changed"
	if p.Spec.Tags["team"] != "a" {
		t.Fatal("the view shares the spec's labels")
	}

	if _, state := abandonedSandboxView(p, models.FacadeRunloop); state != nil {
		t.Fatalf("another facade's state = %+v, want none", state)
	}
	if _, state := abandonedSandboxView(p, ""); state != nil {
		t.Fatalf("no facade: state = %+v, want none", state)
	}
	// The spec's name stands in for a row without the hot copy; no spec
	// leaves only what the placement itself holds.
	p.Name = ""
	p.Spec.Name = "from-spec"
	if sb, _ := abandonedSandboxView(p, models.FacadeDaytona); sb.Name != "from-spec" {
		t.Fatalf("name = %q, want the spec's", sb.Name)
	}
	p.Spec = nil
	p.CreatedUnix, p.UpdatedUnix = 0, 0
	sb, state = abandonedSandboxView(p, models.FacadeDaytona)
	if state != nil || sb.ID != "sb-view" || sb.CPU != 0 || !sb.CreatedAt.IsZero() {
		t.Fatalf("no spec: sandbox %+v, state %+v", sb, state)
	}
}

// What can change between this node's read and the leader's, and what a
// failed write leaves for the retry.
func TestDestroyAbandonedSandboxRaces(t *testing.T) {
	ctx := context.Background()
	const id = "sb-abandoned-race"

	t.Run("deleted by another call after this node read it", func(t *testing.T) {
		svc, c := newAbandonedViewHarness(t)
		c.put(abandonedTestPlacement(id, abandonedDeleted, orphanedFrom(abandonedDeleted)))
		c.afterLocalRead = func() {
			c.mu.Lock()
			delete(c.placements, id)
			c.mu.Unlock()
		}
		sb, _, err := svc.DestroyAbandonedSandbox(ctx, id, false, models.FacadeRunloop)
		if err != nil || sb == nil || sb.ID != id {
			t.Fatalf("= %+v, %v; want the deleted sandbox and no error", sb, err)
		}
		if c.deleteCalls != 0 {
			t.Fatalf("deletes = %d, want none: it was already gone", c.deleteCalls)
		}
	})

	t.Run("a new lifetime under the same id", func(t *testing.T) {
		svc, c := newAbandonedViewHarness(t)
		c.put(abandonedTestPlacement(id, abandonedDeleted, nil))
		c.afterLocalRead = func() {
			c.put(abandonedTestPlacement(id, abandonedLive, func(p *cluster.Placement) { p.IncarnationID = "inc-new" }))
		}
		if _, _, err := svc.DestroyAbandonedSandbox(ctx, id, false, models.FacadeRunloop); err != nil {
			t.Fatalf("= %v; want success: the lifetime it named is gone", err)
		}
		if p, ok := c.get(id); !ok || p.IncarnationID != "inc-new" || c.deleteCalls != 0 {
			t.Fatalf("new lifetime = %+v (found %v), deletes %d: want it untouched", p, ok, c.deleteCalls)
		}
	})

	t.Run("handed to a live node meanwhile", func(t *testing.T) {
		svc, c := newAbandonedViewHarness(t)
		c.put(abandonedTestPlacement(id, abandonedDeleted, nil))
		c.afterLocalRead = func() { c.reassign(id, abandonedLive) }
		if _, _, err := svc.DestroyAbandonedSandbox(ctx, id, false, models.FacadeRunloop); !errors.Is(err, ErrClusterFinalizationUnavailable) {
			t.Fatalf("= %v, want ErrClusterFinalizationUnavailable (503, retry)", err)
		}
		if p, ok := c.get(id); !ok || p.OwnerNodeID != abandonedLive || c.deleteCalls != 0 {
			t.Fatalf("placement = %+v (found %v), deletes %d: want it left on %s", p, ok, c.deleteCalls, abandonedLive)
		}
	})

	t.Run("no leader to read from", func(t *testing.T) {
		svc, c := newAbandonedViewHarness(t)
		c.put(abandonedTestPlacement(id, abandonedDeleted, nil))
		c.readErr = errors.New("cluster: no leader")
		if _, _, err := svc.DestroyAbandonedSandbox(ctx, id, false, models.FacadeRunloop); !errors.Is(err, ErrClusterFinalizationUnavailable) {
			t.Fatalf("= %v, want ErrClusterFinalizationUnavailable (503, retry)", err)
		}
		if _, ok := c.get(id); !ok {
			t.Fatal("a failed read lost the placement")
		}
	})

	t.Run("the write fails, the retry deletes", func(t *testing.T) {
		svc, c := newAbandonedViewHarness(t)
		c.put(abandonedTestPlacement(id, abandonedDeleted, deleting))
		c.deleteErrs = []error{errors.New("raft: leadership lost while committing log")}
		if _, _, err := svc.DestroyAbandonedSandbox(ctx, id, false, models.FacadeRunloop); !errors.Is(err, ErrClusterFinalizationUnavailable) {
			t.Fatalf("first = %v, want ErrClusterFinalizationUnavailable (503, retry)", err)
		}
		if _, ok := c.get(id); !ok {
			t.Fatal("a failed write lost the placement")
		}
		if _, _, err := svc.DestroyAbandonedSandbox(ctx, id, false, models.FacadeRunloop); err != nil {
			t.Fatalf("retry = %v", err)
		}
		if _, ok := c.get(id); ok {
			t.Fatal("placement still there after the retry")
		}
	})

	t.Run("concurrent duplicates", func(t *testing.T) {
		svc, c := newAbandonedViewHarness(t)
		c.put(abandonedTestPlacement(id, abandonedDeleted, orphanedFrom(abandonedDeleted)))
		var wg sync.WaitGroup
		errs := make(chan error, 8)
		for range 8 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, _, err := svc.DestroyAbandonedSandbox(ctx, id, false, models.FacadeRunloop)
				errs <- err
			}()
		}
		wg.Wait()
		close(errs)
		ok := 0
		for err := range errs {
			switch {
			case err == nil:
				ok++
			case errors.Is(err, store.ErrNotFound):
			default:
				t.Fatalf("duplicate = %v, want success or ErrNotFound", err)
			}
		}
		if ok == 0 {
			t.Fatal("no call succeeded")
		}
		if _, found := c.get(id); found {
			t.Fatal("placement still there")
		}
	})
}
