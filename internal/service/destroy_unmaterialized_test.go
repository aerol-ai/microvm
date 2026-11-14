package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/models"
)

// failoverWindowCluster is a stateful stand-in for the placement FSM. It keeps
// one row per sandbox and applies the reassign, begin-delete and delete
// commands with the FSM's exact owner and incarnation rules (fsm.go
// opReassign, opBeginDelete, opDelete), so a test can walk one sandbox
// through a failover and a delete and read what the cluster would hold.
type failoverWindowCluster struct {
	*cluster.Noop
	mu         sync.Mutex
	placements map[string]cluster.Placement

	// readErr fails every authoritative read: the control plane is
	// unreachable. deleteErrOnce fails the next final delete only.
	readErr       error
	deleteErrOnce error
	beginCalls    int
	deleteCalls   int
	reads         int
	// afterRead runs once, after the next authoritative read has answered:
	// a change that lands between a read and the write that follows it.
	afterRead func()
}

func newFailoverWindowCluster(self string) *failoverWindowCluster {
	return &failoverWindowCluster{
		Noop:       cluster.NewNoop(self, "http://"+self, ""),
		placements: map[string]cluster.Placement{},
	}
}

func (c *failoverWindowCluster) put(p cluster.Placement) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.placements[p.SandboxID] = p
}

func (c *failoverWindowCluster) get(id string) (cluster.Placement, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	p, ok := c.placements[id]
	return p, ok
}

// reassign is opReassign: the owner moves and the incarnation stays.
func (c *failoverWindowCluster) reassign(id, to string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	p := c.placements[id]
	p.OwnerNodeID = to
	p.OwnerAPIURL = "http://" + to
	c.placements[id] = p
}

func (c *failoverWindowCluster) PlacementOf(id string) (cluster.Placement, bool) {
	return c.get(id)
}

func (c *failoverWindowCluster) PlacementsByIDs(ids []string) map[string]cluster.Placement {
	out := make(map[string]cluster.Placement, len(ids))
	for _, id := range ids {
		if p, ok := c.get(id); ok {
			out[id] = p
		}
	}
	return out
}

func (c *failoverWindowCluster) AuthoritativePlacementsByIDs(_ context.Context, ids []string) (map[string]cluster.Placement, error) {
	c.mu.Lock()
	c.reads++
	err := c.readErr
	hook := c.afterRead
	c.afterRead = nil
	c.mu.Unlock()
	if err != nil {
		return nil, err
	}
	out := c.PlacementsByIDs(ids)
	if hook != nil {
		hook()
	}
	return out, nil
}

func (c *failoverWindowCluster) SpecOf(id string) *models.CreateSandboxRequest {
	p, _ := c.get(id)
	return p.Spec
}

func (c *failoverWindowCluster) BeginDeletePlacementExact(_ context.Context, id, owner, incarnation string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.beginCalls++
	p, ok := c.placements[id]
	if !ok {
		return cluster.ErrUnknownSandbox
	}
	if p.IncarnationID != incarnation {
		return fmt.Errorf("%w: begin delete", cluster.ErrIncarnationConflict)
	}
	if p.OwnerNodeID != owner || p.IsOrphaned() {
		return fmt.Errorf("%w: begin delete owner", cluster.ErrReservationConflict)
	}
	p.State = cluster.PlacementStateDeleting
	c.placements[id] = p
	return nil
}

func (c *failoverWindowCluster) DeletePlacementExact(_ context.Context, id, owner, incarnation string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.deleteCalls++
	if err := c.deleteErrOnce; err != nil {
		c.deleteErrOnce = nil
		return err
	}
	p, ok := c.placements[id]
	if !ok || p.IncarnationID != incarnation || p.OwnerNodeID != owner {
		// A stale delete ACKs without touching a newer lifecycle.
		return nil
	}
	delete(c.placements, id)
	return nil
}

// watcherSnapshot is what the owner watcher reads at the top of a tick: the
// self-owned placements whose spec wants a failover recreate, excluding
// placements already being deleted (cluster.placementWantsFailoverRecreate).
func (c *failoverWindowCluster) watcherSnapshot() []cluster.Placement {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []cluster.Placement
	for _, p := range c.placements {
		if p.OwnerNodeID != c.SelfNodeID() || p.IsDeleting() || p.Spec == nil || !p.Spec.ShouldRecreateOnFailover() {
			continue
		}
		out = append(out, p)
	}
	return out
}

// runOwnerWatcher hands each snapshot placement to the service the way
// cluster.recreateOwnedPlacement does. The snapshot may be stale: the real
// watcher reads its FSM view once per tick and recreates one sandbox after
// another, so a delete can land between the read and a recreate.
func runOwnerWatcher(t *testing.T, svc *Service, snapshot []cluster.Placement) {
	t.Helper()
	for _, p := range snapshot {
		_, err := svc.RecreateSandboxReport(context.Background(), p.SandboxID, *p.Spec, cluster.PlacementSecrets{
			OwnerRef: p.OwnerRef, IncarnationID: p.IncarnationID,
		}, cluster.ExposedPortRoutesForPlacement(p), p.OwnerSinceUnixNano)
		if err != nil {
			t.Logf("owner watcher recreate %s: %v", p.SandboxID, err)
		}
	}
}

// selfOwnedPlacementsFor answers an authoritative read the way the cluster
// does for sandboxes reassigned to self, with the "inc-<id>" lifetime the
// recreate tests pass: the only world the owner watcher calls a recreate in.
// The recreate confirms it under the create lease (failoverRecreateStillOwned).
func selfOwnedPlacementsFor(self string, ids []string) map[string]cluster.Placement {
	out := make(map[string]cluster.Placement, len(ids))
	for _, id := range ids {
		out[id] = cluster.Placement{SandboxID: id, OwnerNodeID: self, IncarnationID: "inc-" + id}
	}
	return out
}

// recreateOwnerCluster is a Noop that owns every placement it is asked about.
type recreateOwnerCluster struct{ *cluster.Noop }

func newRecreateOwnerCluster(self string) *recreateOwnerCluster {
	return &recreateOwnerCluster{Noop: cluster.NewNoop(self, "http://"+self, "")}
}

func (c *recreateOwnerCluster) AuthoritativePlacementsByIDs(_ context.Context, ids []string) (map[string]cluster.Placement, error) {
	return selfOwnedPlacementsFor(c.SelfNodeID(), ids), nil
}

// newFailoverWindowHarness is node-w2 in a cluster where sandbox id was
// created on node-w1 with failover.policy=recreate and has just been
// reassigned to node-w2, whose owner watcher has not recreated it yet.
func newFailoverWindowHarness(t *testing.T, id string) (*Service, *store.Store, *recordingRuntime, *failoverWindowCluster) {
	t.Helper()
	rt := &recordingRuntime{}
	svc, st, _ := newServiceRuntimeHarness(t, rt)
	svc.cfg.EnableCluster = true
	fc := newFailoverWindowCluster("node-w2")
	svc.AttachCluster(fc)
	fc.put(cluster.Placement{
		SandboxID: id, OwnerNodeID: "node-w1", OwnerAPIURL: "http://node-w1",
		IncarnationID: "inc-" + id, OwnerRef: "acct-a",
		Spec: &models.CreateSandboxRequest{
			Image:    "alpine:3.20",
			Failover: &models.Failover{Policy: models.FailoverPolicyRecreate},
		},
	})
	fc.reassign(id, "node-w2")
	return svc, st, rt, fc
}

// TestDestroyDuringFailoverWindowIsNotLost is plan item C3: a DELETE that
// reaches the new owner after the reassign and before its owner watcher has
// recreated the sandbox used to find no local row and answer 404, which every
// SDK reads as "deleted", and the watcher then brought the sandbox back a few
// seconds later. The delete must commit for the placement alone, and the
// watcher must then leave it deleted, even with the snapshot it read before
// the delete.
func TestDestroyDuringFailoverWindowIsNotLost(t *testing.T) {
	ctx := context.Background()
	const id = "sb-c3-failover-delete"
	svc, st, rt, fc := newFailoverWindowHarness(t, id)

	// The watcher's tick read the placement before the DELETE arrived.
	stale := fc.watcherSnapshot()
	if len(stale) != 1 {
		t.Fatalf("watcher snapshot = %d placements, want the reassigned one", len(stale))
	}

	// Errorf, not Fatalf, from here to the retry: on a build without the
	// fix the rest of the story (the recreate) is the evidence.
	if err := svc.DestroySandbox(ctx, id); err != nil {
		t.Errorf("DELETE during the failover window = %v, want success (a 404 here is read as deleted, and the watcher recreates it)", err)
	}
	if p, ok := fc.get(id); ok {
		t.Errorf("placement after DELETE = %+v, want it deleted", p)
	}

	// The watcher finishes the tick it started before the delete, then runs
	// another one.
	runOwnerWatcher(t, svc, stale)
	runOwnerWatcher(t, svc, fc.watcherSnapshot())

	if _, err := st.Get(ctx, id); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("local row after the owner watcher ran = %v, want ErrNotFound (deleted sandbox recreated)", err)
	}
	if rt.createCalls != 0 {
		t.Errorf("runtime creates = %d after the DELETE, want 0", rt.createCalls)
	}
	if _, ok := fc.get(id); ok {
		t.Error("placement still present after the owner watcher ran")
	}
	if t.Failed() {
		return
	}

	// A retry of the DELETE (the SDK timed out on the first answer) finds
	// nothing, exactly like a retry after an ordinary delete.
	if err := svc.DestroySandbox(ctx, id); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("retried DELETE = %v, want ErrNotFound", err)
	}
	if _, err := st.Get(ctx, id); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("local row after retried DELETE = %v, want ErrNotFound", err)
	}
}

// TestDestroyDuringFailoverWindowRetryFinishesAfterFenceOnly covers a DELETE
// that commits the delete fence and then loses the final delete (the leader
// stepped down). The fence alone already stops the watcher, and the retried
// DELETE finishes what the first one started.
func TestDestroyDuringFailoverWindowRetryFinishesAfterFenceOnly(t *testing.T) {
	ctx := context.Background()
	const id = "sb-c3-fence-only"
	svc, st, rt, fc := newFailoverWindowHarness(t, id)
	stale := fc.watcherSnapshot()
	fc.deleteErrOnce = errors.New("raft: leadership lost while committing log")

	err := svc.DestroySandbox(ctx, id)
	if err == nil || !errors.Is(err, ErrClusterFinalizationUnavailable) {
		t.Fatalf("DELETE with a failed final delete = %v, want ErrClusterFinalizationUnavailable (503, retry)", err)
	}
	p, ok := fc.get(id)
	if !ok || !p.IsDeleting() {
		t.Fatalf("placement after a fenced, unfinished delete = %+v (present %v), want deleting", p, ok)
	}

	runOwnerWatcher(t, svc, stale)
	runOwnerWatcher(t, svc, fc.watcherSnapshot())
	if rt.createCalls != 0 {
		t.Fatalf("runtime creates = %d with the delete fence committed, want 0", rt.createCalls)
	}

	if err := svc.DestroySandbox(ctx, id); err != nil {
		t.Fatalf("retried DELETE = %v, want success", err)
	}
	if _, ok := fc.get(id); ok {
		t.Fatal("placement still present after the retried DELETE")
	}
	if _, err := st.Get(ctx, id); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("local row = %v, want ErrNotFound", err)
	}
}

// TestDestroyWithoutLocalRowLeavesOtherPlacementsAlone pins what the new
// path must not touch: a placement this node does not own, a reservation (a
// create of the id is on its way here, and its own rollback cancels it), an
// orphan, and another tenant's sandbox all keep answering 404 and keep their
// placement.
func TestDestroyWithoutLocalRowLeavesOtherPlacementsAlone(t *testing.T) {
	ctx := context.Background()
	spec := &models.CreateSandboxRequest{Image: "alpine:3.20", Failover: &models.Failover{Policy: models.FailoverPolicyRecreate}}
	cases := []struct {
		name string
		p    cluster.Placement
		ctx  context.Context
	}{
		{name: "other owner", p: cluster.Placement{OwnerNodeID: "node-w1", Spec: spec}},
		{name: "reserved", p: cluster.Placement{OwnerNodeID: "node-w2", State: cluster.PlacementStateReserved, Spec: spec}},
		{name: "orphaned", p: cluster.Placement{OwnerNodeID: "node-w2", OwnerState: cluster.PlacementOwnerStateOrphaned, Spec: spec}},
		{name: "no incarnation", p: cluster.Placement{OwnerNodeID: "node-w2", Spec: spec}},
		{
			name: "other tenant",
			p:    cluster.Placement{OwnerNodeID: "node-w2", OwnerRef: "acct-b", Spec: spec},
			ctx: controlplane.ContextWithAccess(ctx, controlplane.Access{
				Identity: controlplane.Identity{OwnerRef: "acct-a"},
			}),
		},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rt := &recordingRuntime{}
			svc, _, _ := newServiceRuntimeHarness(t, rt)
			svc.cfg.EnableCluster = true
			fc := newFailoverWindowCluster("node-w2")
			svc.AttachCluster(fc)
			id := fmt.Sprintf("sb-c3-untouched-%d", i)
			p := tc.p
			p.SandboxID = id
			if tc.name != "no incarnation" {
				p.IncarnationID = "inc-" + id
			}
			fc.put(p)
			callCtx := tc.ctx
			if callCtx == nil {
				callCtx = ctx
			}
			if err := svc.DestroySandbox(callCtx, id); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("DestroySandbox = %v, want ErrNotFound", err)
			}
			got, ok := fc.get(id)
			if !ok || got.State != p.State {
				t.Fatalf("placement after DestroySandbox = %+v (present %v), want it unchanged", got, ok)
			}
			if fc.beginCalls != 0 || fc.deleteCalls != 0 {
				t.Fatalf("placement writes begin=%d delete=%d, want none", fc.beginCalls, fc.deleteCalls)
			}
		})
	}
}

// TestDestroyWithoutLocalRowFailsClosedWhenPlacementUnreadable: with the
// control plane unreachable the node cannot tell "never existed" from "mine,
// not recreated yet", so it must not answer 404.
func TestDestroyWithoutLocalRowFailsClosedWhenPlacementUnreadable(t *testing.T) {
	const id = "sb-c3-unreadable"
	svc, _, _, fc := newFailoverWindowHarness(t, id)
	fc.readErr = errors.New("no leader")
	err := svc.DestroySandbox(context.Background(), id)
	if !errors.Is(err, ErrClusterFinalizationUnavailable) {
		t.Fatalf("DestroySandbox = %v, want ErrClusterFinalizationUnavailable", err)
	}
	if !strings.Contains(err.Error(), "no leader") {
		t.Fatalf("error %q does not carry the read failure", err)
	}
}

// TestDestroyWithoutLocalRowRacesWithItsOwnWriters walks the moments between
// the placement read and the delete: a failover recreate running on this node
// (503, retry), a recreate that finished (the full destroy runs instead), and
// a placement deleted or moved by someone else (404, or 503 so the retry is
// routed to the new owner). None of them deletes what it should not.
func TestDestroyWithoutLocalRowRacesWithItsOwnWriters(t *testing.T) {
	ctx := context.Background()

	t.Run("recreate holds the create lease", func(t *testing.T) {
		const id = "sb-c3-lease-held"
		svc, _, _, fc := newFailoverWindowHarness(t, id)
		_, release, err := svc.beginCreateLease(ctx, id, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer release()
		if err := svc.DestroySandbox(ctx, id); !errors.Is(err, ErrCreateInProgress) {
			t.Fatalf("DestroySandbox while a create holds the lease = %v, want ErrCreateInProgress", err)
		}
		if fc.beginCalls != 0 {
			t.Fatalf("fence written while a create held the lease")
		}
	})

	t.Run("recreate finished before the lease", func(t *testing.T) {
		const id = "sb-c3-row-appeared"
		svc, st, rt, fc := newFailoverWindowHarness(t, id)
		fc.afterRead = func() {
			row := &models.Sandbox{
				ID: id, Image: "alpine:3.20", Status: models.SandboxStatusStarted, Runtime: models.RuntimeDocker,
				ContainerID: "ctr-" + id, AuditIncarnationID: "inc-" + id, OwnerRef: "acct-a",
			}
			if err := st.Create(ctx, row); err != nil {
				t.Errorf("seed recreated row: %v", err)
			}
		}
		if err := svc.DestroySandbox(ctx, id); err != nil {
			t.Fatalf("DestroySandbox = %v, want the full destroy of the recreated sandbox", err)
		}
		if _, err := st.Get(ctx, id); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("recreated row = %v, want destroyed", err)
		}
		if len(rt.destroyIDs) != 1 {
			t.Fatalf("runtime destroys = %v, want the recreated one", rt.destroyIDs)
		}
		if _, ok := fc.get(id); ok {
			t.Fatal("placement survived the full destroy")
		}
	})

	t.Run("placement deleted meanwhile", func(t *testing.T) {
		const id = "sb-c3-deleted-meanwhile"
		svc, _, _, fc := newFailoverWindowHarness(t, id)
		fc.afterRead = func() {
			fc.mu.Lock()
			delete(fc.placements, id)
			fc.mu.Unlock()
		}
		if err := svc.DestroySandbox(ctx, id); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("DestroySandbox = %v, want ErrNotFound", err)
		}
	})

	t.Run("placement moved meanwhile", func(t *testing.T) {
		const id = "sb-c3-moved-meanwhile"
		svc, _, _, fc := newFailoverWindowHarness(t, id)
		fc.afterRead = func() { fc.reassign(id, "node-w3") }
		if err := svc.DestroySandbox(ctx, id); !errors.Is(err, ErrClusterFinalizationUnavailable) {
			t.Fatalf("DestroySandbox = %v, want ErrClusterFinalizationUnavailable", err)
		}
		if p, ok := fc.get(id); !ok || p.OwnerNodeID != "node-w3" || p.IsDeleting() {
			t.Fatalf("placement = %+v (present %v), want it untouched on node-w3", p, ok)
		}
	})
}

// TestFailoverRecreateStillOwned covers every answer of the recreate-side
// check: create only a placement that still exists, is not being deleted, is
// still this node's, and is still the lifetime the watcher read.
func TestFailoverRecreateStillOwned(t *testing.T) {
	ctx := context.Background()
	const id = "sb-c3-still-owned"
	secrets := cluster.PlacementSecrets{IncarnationID: "inc-" + id}
	cases := []struct {
		name string
		edit func(*failoverWindowCluster)
		want bool
	}{
		{name: "owned", edit: func(*failoverWindowCluster) {}, want: true},
		{name: "deleted", edit: func(c *failoverWindowCluster) { delete(c.placements, id) }},
		{name: "deleting", edit: func(c *failoverWindowCluster) {
			p := c.placements[id]
			p.State = cluster.PlacementStateDeleting
			c.placements[id] = p
		}},
		{name: "moved", edit: func(c *failoverWindowCluster) {
			p := c.placements[id]
			p.OwnerNodeID = "node-w3"
			c.placements[id] = p
		}},
		{name: "orphaned", edit: func(c *failoverWindowCluster) {
			p := c.placements[id]
			p.OwnerState = cluster.PlacementOwnerStateOrphaned
			c.placements[id] = p
		}},
		{name: "new lifetime", edit: func(c *failoverWindowCluster) {
			p := c.placements[id]
			p.IncarnationID = "inc-reused"
			c.placements[id] = p
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc, _, _, fc := newFailoverWindowHarness(t, id)
			fc.mu.Lock()
			tc.edit(fc)
			fc.mu.Unlock()
			got, _, err := svc.failoverRecreateStillOwned(ctx, id, secrets)
			if err != nil || got != tc.want {
				t.Fatalf("failoverRecreateStillOwned = %v, %v; want %v", got, err, tc.want)
			}
		})
	}

	t.Run("unreadable", func(t *testing.T) {
		svc, _, rt, fc := newFailoverWindowHarness(t, id)
		fc.readErr = errors.New("no leader")
		if _, _, err := svc.failoverRecreateStillOwned(ctx, id, secrets); err == nil {
			t.Fatal("an unreadable placement was taken as owned")
		}
		// The watcher counts it as a failed attempt and retries next tick.
		attempted, err := svc.RecreateSandboxReport(ctx, id, models.CreateSandboxRequest{Image: "alpine:3.20"}, secrets, nil, 0)
		if err == nil || !attempted || rt.createCalls != 0 {
			t.Fatalf("recreate with an unreadable placement = attempted %v, err %v, creates %d", attempted, err, rt.createCalls)
		}
	})

	t.Run("single node", func(t *testing.T) {
		svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
		if got, _, err := svc.failoverRecreateStillOwned(ctx, id, secrets); err != nil || !got {
			t.Fatalf("single node = %v, %v; want true", got, err)
		}
		if err := svc.destroyUnmaterializedPlacement(ctx, id, store.ErrNotFound); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("single-node delete with no row = %v, want ErrNotFound", err)
		}
	})
}

// TestTryCreateLease: the non-waiting take answers at once, is re-entrant
// through the context, and gives the lease back.
func TestTryCreateLease(t *testing.T) {
	ctx := context.Background()
	svc := &Service{}
	held, release, err := svc.tryCreateLease(ctx, "sb-try")
	if err != nil || !holdsCreateLease(held, "sb-try") {
		t.Fatalf("first take = %v, holds %v", err, holdsCreateLease(held, "sb-try"))
	}
	if _, _, err := svc.tryCreateLease(ctx, "sb-try"); !errors.Is(err, ErrCreateInProgress) {
		t.Fatalf("second take = %v, want ErrCreateInProgress", err)
	}
	if _, inner, err := svc.tryCreateLease(held, "sb-try"); err != nil {
		t.Fatalf("re-entrant take = %v", err)
	} else {
		inner()
	}
	if _, _, err := svc.tryCreateLease(ctx, " "); err != nil {
		t.Fatalf("empty id = %v", err)
	}
	release()
	if _, again, err := svc.tryCreateLease(ctx, "sb-try"); err != nil {
		t.Fatalf("take after release = %v", err)
	} else {
		again()
	}
}
