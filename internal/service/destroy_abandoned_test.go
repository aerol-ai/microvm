package service

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/models"
)

// A DELETE of a sandbox whose node an operator deleted
// (deleteAbandonedPlacement). No node holds its row, and the router sends
// the call to a server instead of forwarding it to the deleted node, so the
// server's no-row path must delete the placement itself, once, and only a
// placement that really is left on a deleted node.

// deletedNodeCluster is failoverWindowCluster plus a deny set, as a worker
// or gateway sees it: it knows which nodes were deleted, but may not delete
// another node's placement.
type deletedNodeCluster struct {
	*failoverWindowCluster
	denied map[string]bool
}

func (c *deletedNodeCluster) IsNodeDenied(id string) bool { return c.denied[id] }

// deletedNodeServer is a server: it also deletes abandoned placements, with
// the rule of cluster.(*Cluster).DeleteAbandonedPlacement (an exact delete,
// then a read, until the lifetime is gone or no longer abandoned).
type deletedNodeServer struct {
	*deletedNodeCluster
	deleteErrs []error
}

func (c *deletedNodeServer) DeleteAbandonedPlacement(ctx context.Context, p cluster.Placement) error {
	c.mu.Lock()
	if len(c.deleteErrs) > 0 {
		err := c.deleteErrs[0]
		c.deleteErrs = c.deleteErrs[1:]
		c.mu.Unlock()
		return err
	}
	c.mu.Unlock()
	for range 3 {
		if !cluster.PlacementAbandoned(c, p) {
			return cluster.ErrPlacementNotAbandoned
		}
		if err := c.DeletePlacementExact(ctx, p.SandboxID, p.OwnerNodeID, p.IncarnationID); err != nil {
			return err
		}
		cur, ok := c.get(p.SandboxID)
		if !ok || cur.IncarnationID != p.IncarnationID {
			return nil
		}
		p = cur
	}
	return cluster.ErrPlacementNotAbandoned
}

const (
	abandonedServer  = "node-s1"
	abandonedDeleted = "node-gone"
	abandonedDied    = "node-died"
	abandonedLive    = "node-w3"
)

func newAbandonedHarness(t *testing.T, server bool) (*Service, *deletedNodeCluster, cluster.Client) {
	t.Helper()
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableCluster = true
	dc := &deletedNodeCluster{failoverWindowCluster: newFailoverWindowCluster(abandonedServer), denied: map[string]bool{abandonedDeleted: true}}
	var c cluster.Client = dc
	if server {
		c = &deletedNodeServer{deletedNodeCluster: dc}
	}
	svc.AttachCluster(c)
	return svc, dc, c
}

func abandonedTestPlacement(id, owner string, edit func(*cluster.Placement)) cluster.Placement {
	p := cluster.Placement{
		SandboxID: id, OwnerNodeID: owner, OwnerAPIURL: "http://" + owner,
		IncarnationID: "inc-" + id, OwnerRef: "acct-a",
		Spec: &models.CreateSandboxRequest{Image: "alpine:3.20"},
	}
	if edit != nil {
		edit(&p)
	}
	return p
}

func orphanedFrom(node string) func(*cluster.Placement) {
	return func(p *cluster.Placement) {
		p.OwnerNodeID, p.OwnerAPIURL = "", ""
		p.OwnerState = cluster.PlacementOwnerStateOrphaned
		p.OrphanedOwnerNodeID = node
	}
}

func deleting(p *cluster.Placement) { p.State = cluster.PlacementStateDeleting }

func TestDestroySandboxOnADeletedNode(t *testing.T) {
	tenantA := controlplane.ContextWithAccess(context.Background(), controlplane.Access{Identity: controlplane.Identity{OwnerRef: "acct-a"}})
	tenantB := controlplane.ContextWithAccess(context.Background(), controlplane.Access{Identity: controlplane.Identity{OwnerRef: "acct-b"}})
	cases := []struct {
		name   string
		owner  string
		edit   func(*cluster.Placement)
		ctx    context.Context
		worker bool // the call reached a worker or gateway, not a server
		want   error
		gone   bool
	}{
		// The live case: the node went while its own delete was running.
		{name: "deleting on the deleted node", owner: abandonedDeleted, edit: deleting, gone: true},
		{name: "running, orphaned from the deleted node", owner: abandonedDeleted, edit: orphanedFrom(abandonedDeleted), gone: true},
		{name: "still named on the deleted node", owner: abandonedDeleted, gone: true},
		{name: "the tenant's own call", owner: abandonedDeleted, edit: orphanedFrom(abandonedDeleted), ctx: tenantA, gone: true},
		// What must keep its answer and its placement.
		{name: "orphan of a node that only died", owner: abandonedDied, edit: orphanedFrom(abandonedDied), want: store.ErrNotFound},
		{name: "another tenant's sandbox", owner: abandonedDeleted, edit: orphanedFrom(abandonedDeleted), ctx: tenantB, want: store.ErrNotFound},
		{name: "a reservation on the deleted node", owner: abandonedDeleted, edit: func(p *cluster.Placement) { p.State = cluster.PlacementStateReserved }, want: store.ErrNotFound},
		{name: "on a worker or gateway", owner: abandonedDeleted, edit: orphanedFrom(abandonedDeleted), worker: true, want: store.ErrNotFound},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc, dc, _ := newAbandonedHarness(t, !tc.worker)
			id := fmt.Sprintf("sb-abandoned-%d", i)
			dc.put(abandonedTestPlacement(id, tc.owner, tc.edit))
			ctx := tc.ctx
			if ctx == nil {
				ctx = context.Background()
			}
			if err := svc.DestroySandbox(ctx, id); !errors.Is(err, tc.want) {
				t.Fatalf("DestroySandbox = %v, want %v", err, tc.want)
			}
			_, found := dc.get(id)
			if tc.gone {
				if found {
					t.Fatal("placement still there after the DELETE")
				}
				// The retry (or a duplicate in flight) gets the normal answer.
				if err := svc.DestroySandbox(ctx, id); !errors.Is(err, store.ErrNotFound) {
					t.Fatalf("second DELETE = %v, want ErrNotFound", err)
				}
				return
			}
			if !found || dc.deleteCalls != 0 || dc.beginCalls != 0 {
				t.Fatalf("placement found=%v, deletes=%d, fences=%d: want it untouched", found, dc.deleteCalls, dc.beginCalls)
			}
		})
	}
}

// A failed write is a 503 the client retries, with the placement kept for
// that retry; a placement a recreate retry moved to a live node meanwhile is
// left there, and the client's retry is routed to it.
func TestDestroySandboxOnADeletedNodeRetries(t *testing.T) {
	ctx := context.Background()

	t.Run("leader lost the write", func(t *testing.T) {
		svc, dc, c := newAbandonedHarness(t, true)
		const id = "sb-abandoned-retry"
		dc.put(abandonedTestPlacement(id, abandonedDeleted, deleting))
		c.(*deletedNodeServer).deleteErrs = []error{errors.New("raft: leadership lost while committing log")}
		if err := svc.DestroySandbox(ctx, id); !errors.Is(err, ErrClusterFinalizationUnavailable) {
			t.Fatalf("first DELETE = %v, want ErrClusterFinalizationUnavailable (503, retry)", err)
		}
		if _, ok := dc.get(id); !ok {
			t.Fatal("a failed DELETE lost the placement")
		}
		if err := svc.DestroySandbox(ctx, id); err != nil {
			t.Fatalf("retried DELETE = %v", err)
		}
		if _, ok := dc.get(id); ok {
			t.Fatal("placement still there after the retry")
		}
	})

	t.Run("moved to a live node meanwhile", func(t *testing.T) {
		svc, dc, _ := newAbandonedHarness(t, true)
		const id = "sb-abandoned-moved"
		dc.put(abandonedTestPlacement(id, abandonedDeleted, orphanedFrom(abandonedDeleted)))
		dc.afterRead = func() {
			dc.put(abandonedTestPlacement(id, abandonedLive, nil))
		}
		if err := svc.DestroySandbox(ctx, id); !errors.Is(err, ErrClusterFinalizationUnavailable) {
			t.Fatalf("DELETE = %v, want ErrClusterFinalizationUnavailable (503, retry)", err)
		}
		if p, ok := dc.get(id); !ok || p.OwnerNodeID != abandonedLive {
			t.Fatalf("placement = %+v (found %v), want it left on %s", p, ok, abandonedLive)
		}
	})

	t.Run("concurrent duplicates", func(t *testing.T) {
		svc, dc, _ := newAbandonedHarness(t, true)
		const id = "sb-abandoned-dup"
		dc.put(abandonedTestPlacement(id, abandonedDeleted, deleting))
		var wg sync.WaitGroup
		errs := make(chan error, 8)
		for range 8 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				errs <- svc.DestroySandbox(ctx, id)
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
				t.Fatalf("duplicate DELETE = %v, want success or ErrNotFound", err)
			}
		}
		if ok == 0 {
			t.Fatal("no DELETE succeeded")
		}
		if _, found := dc.get(id); found {
			t.Fatal("placement still there")
		}
	})
}
