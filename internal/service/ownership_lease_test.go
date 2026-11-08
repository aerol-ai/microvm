package service

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/runtime"
	storepkg "github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
)

// leaseCluster is a worker's view of the control plane for the ownership
// lease: an authoritative placement read that works (placements) or fails
// (err, the control plane is out of reach).
type leaseCluster struct {
	*cluster.Noop
	mu         sync.Mutex
	err        error
	placements map[string]cluster.Placement
	reads      int
	batchSizes []int
}

func newLeaseCluster() *leaseCluster {
	return &leaseCluster{Noop: cluster.NewNoop("worker-a", "http://worker-a", ""), placements: map[string]cluster.Placement{}}
}

func (c *leaseCluster) AuthoritativePlacementsByIDs(_ context.Context, ids []string) (map[string]cluster.Placement, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reads++
	c.batchSizes = append(c.batchSizes, len(ids))
	if c.err != nil {
		return nil, c.err
	}
	out := make(map[string]cluster.Placement, len(ids))
	for _, id := range ids {
		if p, ok := c.placements[id]; ok {
			out[id] = p
		}
	}
	return out, nil
}

func (c *leaseCluster) down() {
	c.mu.Lock()
	c.err = errors.New("cluster agent: no live server-role control-plane members")
	c.mu.Unlock()
}

func (c *leaseCluster) up(placements ...cluster.Placement) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.err = nil
	c.placements = map[string]cluster.Placement{}
	for _, p := range placements {
		c.placements[p.SandboxID] = p
	}
}

func (c *leaseCluster) readCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.reads
}

func selfPlacement(id string) cluster.Placement {
	return cluster.Placement{SandboxID: id, OwnerNodeID: "worker-a", IncarnationID: "inc-" + id, State: cluster.PlacementStatePlaced}
}

// freezeRuntime is a docker-like runtime that can freeze (runtime.Freezer).
type freezeRuntime struct {
	*fakeCapacityRuntime
	mu        sync.Mutex
	frozen    map[string]bool
	freezes   int
	thaws     int
	freezeErr error
	thawErr   error
}

func newFreezeRuntime() *freezeRuntime {
	return &freezeRuntime{fakeCapacityRuntime: &fakeCapacityRuntime{}, frozen: map[string]bool{}}
}

func (r *freezeRuntime) Freeze(_ context.Context, ref string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.freezes++
	if r.freezeErr != nil {
		return r.freezeErr
	}
	r.frozen[ref] = true
	return nil
}

func (r *freezeRuntime) Thaw(_ context.Context, ref string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.thaws++
	if r.thawErr != nil {
		return r.thawErr
	}
	delete(r.frozen, ref)
	return nil
}

func (r *freezeRuntime) isFrozen(ref string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.frozen[ref]
}

var _ runtime.Freezer = (*freezeRuntime)(nil)

// newLeaseService is a cluster worker with the default 30s dead-owner grace,
// so its ownership lease is 15s.
func newLeaseService(t *testing.T, rt runtime.Runtime) (*Service, *storepkg.Store, *leaseCluster) {
	t.Helper()
	svc, st, _ := newServiceRuntimeHarnessAtPath(t, filepath.Join(t.TempDir(), "state.db"), rt)
	svc.cfg.EnableCluster = true
	svc.cfg.ClusterDeadOwnerGrace = 30 * time.Second
	lc := newLeaseCluster()
	svc.AttachCluster(lc)
	return svc, st, lc
}

func seedLeaseRow(t *testing.T, st *storepkg.Store, id string, recreate bool, status models.SandboxStatus) {
	t.Helper()
	now := time.Now().UTC()
	sb := &models.Sandbox{
		ID: id, Image: "alpine:3.20", Status: status, Runtime: models.RuntimeDocker,
		ContainerID: "ctr-" + id, AuditIncarnationID: "inc-" + id,
		CPU: 1, MemoryMB: 256, DiskGB: 1, OSUser: "root",
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}
	if recreate {
		sb.Failover = &models.Failover{Policy: models.FailoverPolicyRecreate}
	}
	if err := st.Create(context.Background(), sb); err != nil {
		t.Fatalf("seed %s: %v", id, err)
	}
}

// TestOwnershipLeaseFencesAndResumes is the I1 regression. A worker cut off
// from the control plane kept running and serving its failover.policy=recreate
// sandboxes for as long as the cut lasted, while the leader, after
// SB_DEAD_OWNER_GRACE, recreated them on another node: two live copies. Now,
// past the lease (half the grace) without an authoritative read, the worker
// freezes them and refuses to start or serve them; once a read proves the
// placement is still its own, it thaws them.
func TestOwnershipLeaseFencesAndResumes(t *testing.T) {
	ctx := context.Background()
	rt := newFreezeRuntime()
	svc, st, lc := newLeaseService(t, rt)
	seedLeaseRow(t, st, "sb-ha", true, models.SandboxStatusStarted)
	seedLeaseRow(t, st, "sb-ha-stopped", true, models.SandboxStatusStopped)
	seedLeaseRow(t, st, "sb-plain", false, models.SandboxStatusStarted)
	lc.up(selfPlacement("sb-ha"), selfPlacement("sb-ha-stopped"), selfPlacement("sb-plain"))

	t0 := time.Unix(10_000, 0)
	svc.beginOwnershipLease(t0)
	if err := svc.confirmOwnership(ctx, t0); err != nil {
		t.Fatalf("confirm with the control plane up: %v", err)
	}

	lc.down()
	if err := svc.confirmOwnership(ctx, t0.Add(5*time.Second)); err == nil {
		t.Fatal("confirm succeeded with the control plane down")
	}
	svc.enforceOwnershipLease(ctx, t0.Add(15*time.Second))
	if svc.OwnershipFenced("sb-ha") || rt.isFrozen("ctr-sb-ha") {
		t.Fatal("fenced at exactly the lease; the lease is only over once it is exceeded")
	}

	svc.enforceOwnershipLease(ctx, t0.Add(15*time.Second+time.Millisecond))
	if !svc.OwnershipFenced("sb-ha") || !rt.isFrozen("ctr-sb-ha") {
		t.Fatalf("sb-ha fenced=%v frozen=%v 15.001s after the last authoritative read; want it frozen and refused, or it keeps running and serving while the leader moves it",
			svc.OwnershipFenced("sb-ha"), rt.isFrozen("ctr-sb-ha"))
	}
	if !svc.OwnershipFenced("sb-ha-stopped") || rt.isFrozen("ctr-sb-ha-stopped") {
		t.Fatal("a stopped recreate-policy sandbox must be fenced (no start) without a freeze (nothing runs)")
	}
	if svc.OwnershipFenced("sb-plain") || rt.isFrozen("ctr-sb-plain") {
		t.Fatal("a sandbox without failover.policy=recreate is never reassigned, so it must not be fenced")
	}
	if _, err := svc.StartSandbox(ctx, "sb-ha-stopped"); !errors.Is(err, ErrOwnershipFenced) {
		t.Fatalf("StartSandbox on a fenced sandbox = %v, want ErrOwnershipFenced", err)
	}
	svc.enforceOwnershipLease(ctx, t0.Add(20*time.Second))
	if rt.freezes != 1 {
		t.Fatalf("Freeze calls = %d, want 1: a frozen sandbox is not frozen again", rt.freezes)
	}
	if got := ownershipFencedSandboxes.Value(); got != 2 {
		t.Fatalf("fenced gauge = %d, want 2", got)
	}

	// The control plane answers again and the placements are still ours.
	thawsBefore := rt.thaws
	lc.up(selfPlacement("sb-ha"), selfPlacement("sb-ha-stopped"), selfPlacement("sb-plain"))
	if err := svc.confirmOwnership(ctx, t0.Add(25*time.Second)); err != nil {
		t.Fatalf("confirm after the control plane came back: %v", err)
	}
	if svc.OwnershipFenced("sb-ha") || svc.OwnershipFenced("sb-ha-stopped") || rt.isFrozen("ctr-sb-ha") {
		t.Fatal("a sandbox whose placement is still ours was not resumed")
	}
	if got := rt.thaws - thawsBefore; got != 1 {
		t.Fatalf("Thaw calls on resume = %d, want 1 (only the frozen one)", got)
	}
	if got := ownershipFencedSandboxes.Value(); got != 0 {
		t.Fatalf("fenced gauge = %d after resume, want 0", got)
	}
	svc.enforceOwnershipLease(ctx, t0.Add(30*time.Second))
	if svc.OwnershipFenced("sb-ha") {
		t.Fatal("fenced again inside a fresh lease")
	}
}

// Resuming needs proof: the placement exists, is placed (not reserved,
// deleting or orphaned), names this node, and is the same lifetime as the
// local row. Anything else stays frozen for the stale-ownership path or the
// orphan reclaim to settle.
func TestOwnershipLeaseResumesOnlyOnProof(t *testing.T) {
	moved := selfPlacement("sb-ha")
	moved.OwnerNodeID = "worker-b"
	orphaned := selfPlacement("sb-ha")
	orphaned.OwnerNodeID = ""
	deleting := selfPlacement("sb-ha")
	deleting.State = cluster.PlacementStateDeleting
	reserved := selfPlacement("sb-ha")
	reserved.State = cluster.PlacementStateReserved
	otherLife := selfPlacement("sb-ha")
	otherLife.IncarnationID = "inc-a-later-sandbox"
	for _, tc := range []struct {
		name   string
		answer []cluster.Placement
		resume bool
	}{
		{name: "moved to another node", answer: []cluster.Placement{moved}},
		{name: "orphaned", answer: []cluster.Placement{orphaned}},
		{name: "being deleted", answer: []cluster.Placement{deleting}},
		{name: "reserved", answer: []cluster.Placement{reserved}},
		{name: "another lifetime of the id", answer: []cluster.Placement{otherLife}},
		{name: "no placement", answer: nil},
		{name: "still ours", answer: []cluster.Placement{selfPlacement("sb-ha")}, resume: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			rt := newFreezeRuntime()
			svc, st, lc := newLeaseService(t, rt)
			seedLeaseRow(t, st, "sb-ha", true, models.SandboxStatusStarted)
			t0 := time.Unix(20_000, 0)
			svc.beginOwnershipLease(t0)
			lc.down()
			svc.enforceOwnershipLease(ctx, t0.Add(16*time.Second))
			if !svc.OwnershipFenced("sb-ha") {
				t.Fatal("precondition: sb-ha fenced")
			}
			lc.up(tc.answer...)
			if err := svc.confirmOwnership(ctx, t0.Add(20*time.Second)); err != nil {
				t.Fatal(err)
			}
			if got := !svc.OwnershipFenced("sb-ha") && !rt.isFrozen("ctr-sb-ha"); got != tc.resume {
				t.Fatalf("resumed = %v, want %v", got, tc.resume)
			}
		})
	}
}

// Single-node mode has no control plane to lose: nothing is ever fenced.
func TestOwnershipLeaseIsANoOpInSingleNodeMode(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rt := newFreezeRuntime()
	svc, st, _ := newServiceRuntimeHarnessAtPath(t, filepath.Join(t.TempDir(), "state.db"), rt)
	svc.AttachCluster(cluster.NewNoop("standalone", "", ""))
	seedLeaseRow(t, st, "sb-ha", true, models.SandboxStatusStarted)
	svc.StartOwnershipLease(ctx)
	svc.beginOwnershipLease(time.Unix(1, 0))
	svc.enforceOwnershipLease(ctx, time.Unix(1, 0).Add(24*time.Hour))
	if err := svc.confirmOwnership(ctx, time.Unix(2, 0)); err != nil {
		t.Fatalf("confirm in single-node mode = %v", err)
	}
	if svc.OwnershipFenced("sb-ha") || rt.freezes != 0 {
		t.Fatal("single-node mode fenced a sandbox")
	}
	var nilSvc *Service
	if nilSvc.OwnershipFenced("sb-ha") {
		t.Fatal("nil service fenced")
	}
}

// A worker with no recreate-policy sandbox has nothing two nodes could both
// run: it keeps its lease without a read (an empty read is no round trip), so
// the first such sandbox it gets starts with a whole lease.
func TestOwnershipLeaseWithoutRecreateSandboxesNeedsNoRead(t *testing.T) {
	ctx := context.Background()
	svc, st, lc := newLeaseService(t, newFreezeRuntime())
	seedLeaseRow(t, st, "sb-plain", false, models.SandboxStatusStarted)
	t0 := time.Unix(30_000, 0)
	svc.beginOwnershipLease(t0)
	lc.down()
	if err := svc.confirmOwnership(ctx, t0.Add(10*time.Second)); err != nil {
		t.Fatalf("confirm with nothing to confirm = %v", err)
	}
	if lc.readCount() != 0 {
		t.Fatalf("control-plane reads = %d, want 0", lc.readCount())
	}
	seedLeaseRow(t, st, "sb-ha", true, models.SandboxStatusStarted)
	svc.enforceOwnershipLease(ctx, t0.Add(20*time.Second))
	if svc.OwnershipFenced("sb-ha") {
		t.Fatal("fenced 10s into the lease that the empty confirm renewed")
	}
}

// A runtime that cannot freeze in place (Firecracker, WASM, isolate) still
// gets the fence (no start, no serve); its instance keeps running. A failed
// freeze is retried on the next check.
func TestOwnershipLeaseFreezeGapsAndRetries(t *testing.T) {
	ctx := context.Background()
	rt := newFreezeRuntime()
	rt.freezeErr = errors.New("cgroup freezer busy")
	svc, st, lc := newLeaseService(t, rt)
	svc.firecracker = &fakeCapacityRuntime{}
	seedLeaseRow(t, st, "sb-ha", true, models.SandboxStatusStarted)
	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID: "sb-fc", Image: "alpine:3.20", Status: models.SandboxStatusStarted, Runtime: models.RuntimeFirecracker,
		AuditIncarnationID: "inc-sb-fc", Failover: &models.Failover{Policy: models.FailoverPolicyRecreate},
		CPU: 1, MemoryMB: 256, DiskGB: 1, OSUser: "root", CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	t0 := time.Unix(40_000, 0)
	svc.beginOwnershipLease(t0)
	lc.down()
	svc.enforceOwnershipLease(ctx, t0.Add(16*time.Second))
	if !svc.OwnershipFenced("sb-fc") {
		t.Fatal("a sandbox on a runtime without Freezer must still be fenced")
	}
	if !svc.OwnershipFenced("sb-ha") || rt.isFrozen("ctr-sb-ha") {
		t.Fatal("a failed freeze must leave the sandbox fenced and unfrozen")
	}
	rt.mu.Lock()
	rt.freezeErr = nil
	rt.mu.Unlock()
	svc.enforceOwnershipLease(ctx, t0.Add(17*time.Second))
	if !rt.isFrozen("ctr-sb-ha") {
		t.Fatal("the failed freeze was not retried")
	}
}

// A process that restarts while its sandboxes are frozen loses the fence
// bookkeeping, but the freeze survives in the runtime. The first read that
// confirms ownership after start thaws them; later reads do not.
func TestOwnershipLeaseThawsWhatAPreviousProcessFroze(t *testing.T) {
	ctx := context.Background()
	rt := newFreezeRuntime()
	rt.frozen["ctr-sb-ha"] = true
	svc, st, lc := newLeaseService(t, rt)
	seedLeaseRow(t, st, "sb-ha", true, models.SandboxStatusStarted)
	seedLeaseRow(t, st, "sb-moved", true, models.SandboxStatusStarted)
	rt.frozen["ctr-sb-moved"] = true
	moved := selfPlacement("sb-moved")
	moved.OwnerNodeID = "worker-b"
	lc.up(selfPlacement("sb-ha"), moved)
	t0 := time.Unix(50_000, 0)
	svc.beginOwnershipLease(t0)
	if err := svc.confirmOwnership(ctx, t0.Add(5*time.Second)); err != nil {
		t.Fatal(err)
	}
	if rt.isFrozen("ctr-sb-ha") {
		t.Fatal("a confirmed sandbox frozen by the previous process stayed frozen")
	}
	if !rt.isFrozen("ctr-sb-moved") {
		t.Fatal("a sandbox whose placement moved was thawed; the stale-ownership path removes it")
	}
	if err := svc.confirmOwnership(ctx, t0.Add(10*time.Second)); err != nil {
		t.Fatal(err)
	}
	if rt.thaws != 1 {
		t.Fatalf("Thaw calls = %d, want 1: only the first confirm after start thaws", rt.thaws)
	}
}

// A fenced sandbox whose local row is gone (the stale-ownership path removed
// it) leaves the fence.
func TestOwnershipLeaseForgetsRemovedSandboxes(t *testing.T) {
	ctx := context.Background()
	svc, st, lc := newLeaseService(t, newFreezeRuntime())
	seedLeaseRow(t, st, "sb-ha", true, models.SandboxStatusStarted)
	t0 := time.Unix(60_000, 0)
	svc.beginOwnershipLease(t0)
	lc.down()
	svc.enforceOwnershipLease(ctx, t0.Add(16*time.Second))
	if !svc.OwnershipFenced("sb-ha") {
		t.Fatal("precondition: fenced")
	}
	if err := st.Delete(ctx, "sb-ha"); err != nil {
		t.Fatal(err)
	}
	seedLeaseRow(t, st, "sb-other", true, models.SandboxStatusStopped)
	lc.up(selfPlacement("sb-other"))
	if err := svc.confirmOwnership(ctx, t0.Add(20*time.Second)); err != nil {
		t.Fatal(err)
	}
	if svc.OwnershipFenced("sb-ha") {
		t.Fatal("a removed sandbox is still fenced")
	}
}

// A frozen sandbox's idle clock is not real, and stopping or destroying it
// needs ownership the node has not confirmed: the lifecycle sweep waits.
func TestLifecycleSweepLeavesFencedSandboxAlone(t *testing.T) {
	ctx := context.Background()
	svc, st, lc := newLeaseService(t, newFreezeRuntime())
	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID: "sb-old", Image: "alpine:3.20", Status: models.SandboxStatusStarted, Runtime: models.RuntimeDocker,
		ContainerID: "ctr-sb-old", AuditIncarnationID: "inc-sb-old", Failover: &models.Failover{Policy: models.FailoverPolicyRecreate},
		Lifecycle: models.Lifecycle{StopAtAge: time.Minute},
		CPU:       1, MemoryMB: 256, DiskGB: 1, OSUser: "root",
		CreatedAt: now.Add(-time.Hour), UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	t0 := time.Unix(70_000, 0)
	svc.beginOwnershipLease(t0)
	lc.down()
	svc.enforceOwnershipLease(ctx, t0.Add(16*time.Second))
	if err := svc.runLifecycleAction(ctx, "sb-old", now, 0, false); err != nil {
		t.Fatal(err)
	}
	got, err := st.Get(ctx, "sb-old")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != models.SandboxStatusStarted {
		t.Fatalf("status = %s; the lifecycle sweep acted on a fenced sandbox", got.Status)
	}
}

// Authoritative reads are sent in pages the control plane accepts.
func TestAuthoritativePlacementsForLeaseIsPaged(t *testing.T) {
	lc := newLeaseCluster()
	ids := make([]string, cluster.MaxPlacementPageLimit+3)
	for i := range ids {
		ids[i] = "sb-" + time.Duration(i).String()
	}
	if _, err := authoritativePlacementsForLease(context.Background(), lc, ids); err != nil {
		t.Fatal(err)
	}
	if len(lc.batchSizes) != 2 || lc.batchSizes[0] != cluster.MaxPlacementPageLimit || lc.batchSizes[1] != 3 {
		t.Fatalf("batches = %v, want [%d 3]", lc.batchSizes, cluster.MaxPlacementPageLimit)
	}
	lc.down()
	if _, err := authoritativePlacementsForLease(context.Background(), lc, ids); err == nil {
		t.Fatal("a failed page must fail the read")
	}
}

// The loops run the lease end to end: with the control plane down the
// sandbox is frozen within about one lease, and StartOwnershipLease is
// idempotent.
func TestStartOwnershipLeaseRunsTheLoops(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rt := newFreezeRuntime()
	svc, st, lc := newLeaseService(t, rt)
	svc.cfg.ClusterDeadOwnerGrace = 400 * time.Millisecond
	seedLeaseRow(t, st, "sb-ha", true, models.SandboxStatusStarted)
	lc.down()
	start := time.Now()
	svc.StartOwnershipLease(ctx)
	svc.StartOwnershipLease(ctx)
	deadline := start.Add(5 * time.Second)
	for !rt.isFrozen("ctr-sb-ha") {
		if time.Now().After(deadline) {
			t.Fatal("the lease loops never froze sb-ha with the control plane down")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if elapsed := time.Since(start); elapsed < 200*time.Millisecond {
		t.Fatalf("frozen after %s, before the 200ms lease ran out", elapsed)
	}
	lc.up(selfPlacement("sb-ha"))
	deadline = time.Now().Add(5 * time.Second)
	for rt.isFrozen("ctr-sb-ha") {
		if time.Now().After(deadline) {
			t.Fatal("the lease loops never thawed sb-ha after the control plane came back")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// The fence never loses a sandbox to a failure: a thaw that fails keeps it
// fenced for the next read, a sandbox whose row or runtime cannot be read is
// left for the next check, and a store that cannot list fails the read.
func TestOwnershipLeaseFailurePaths(t *testing.T) {
	ctx := context.Background()
	rt := newFreezeRuntime()
	svc, st, lc := newLeaseService(t, rt)
	seedLeaseRow(t, st, "sb-ha", true, models.SandboxStatusStarted)
	seedLeaseRow(t, st, "sb-gone", true, models.SandboxStatusDestroyed)
	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID: "sb-fc", Image: "alpine:3.20", Status: models.SandboxStatusStarted, Runtime: models.RuntimeFirecracker,
		AuditIncarnationID: "inc-sb-fc", Failover: &models.Failover{Policy: models.FailoverPolicyRecreate},
		CPU: 1, MemoryMB: 256, DiskGB: 1, OSUser: "root", CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	t0 := time.Unix(80_000, 0)
	svc.beginOwnershipLease(t0)
	lc.down()
	svc.enforceOwnershipLease(ctx, t0.Add(16*time.Second))
	if svc.OwnershipFenced("sb-gone") {
		t.Fatal("a destroyed row was fenced")
	}
	// No Firecracker driver on this node: the runtime lookup fails, the
	// sandbox stays fenced (refused) without a freeze.
	if !svc.OwnershipFenced("sb-fc") || !svc.OwnershipFenced("sb-ha") || !rt.isFrozen("ctr-sb-ha") {
		t.Fatal("precondition: sb-ha frozen, sb-fc fenced")
	}

	rt.mu.Lock()
	rt.thawErr = errors.New("cgroup freezer busy")
	rt.mu.Unlock()
	lc.up(selfPlacement("sb-ha"), selfPlacement("sb-fc"))
	if err := svc.confirmOwnership(ctx, t0.Add(20*time.Second)); err != nil {
		t.Fatal(err)
	}
	if !svc.OwnershipFenced("sb-ha") {
		t.Fatal("a failed thaw unfenced the sandbox")
	}
	if svc.OwnershipFenced("sb-fc") {
		t.Fatal("sb-fc was never frozen, so proof alone must unfence it")
	}
	rt.mu.Lock()
	rt.thawErr = nil
	rt.mu.Unlock()
	if err := svc.confirmOwnership(ctx, t0.Add(25*time.Second)); err != nil {
		t.Fatal(err)
	}
	if svc.OwnershipFenced("sb-ha") || rt.isFrozen("ctr-sb-ha") {
		t.Fatal("the failed thaw was not retried")
	}

	// Direct calls with a row or a lock that cannot be had leave nothing fenced.
	svc.fenceSandbox(ctx, "sb-missing")
	sb, err := st.Get(ctx, "sb-ha")
	if err != nil {
		t.Fatal(err)
	}
	// Someone else holds sb-ha's lifecycle boundary and the caller gives up.
	unlock, err := svc.lifecycleLocks.lockCtx(ctx, "sb-ha")
	if err != nil {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	svc.fenceSandbox(cancelled, "sb-ha")
	thawErr := svc.thawSandbox(cancelled, sb)
	unlock()
	if svc.OwnershipFenced("sb-missing") || svc.OwnershipFenced("sb-ha") {
		t.Fatal("fenced without a row or a lifecycle lock")
	}
	if thawErr == nil {
		t.Fatal("thaw without the lifecycle lock must fail")
	}
	fc, err := st.Get(ctx, "sb-fc")
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.thawSandbox(ctx, fc); err == nil {
		t.Fatal("thaw on a node without the sandbox's runtime must fail")
	}
	svc.firecracker = &fakeCapacityRuntime{}
	if err := svc.thawSandbox(ctx, fc); err != nil {
		t.Fatalf("thaw on a runtime that never freezes = %v, want nil", err)
	}

	svc.FenceOwnershipForTest("sb-test")
	if !svc.OwnershipFenced("sb-test") {
		t.Fatal("FenceOwnershipForTest did not fence")
	}

	// A store that cannot list fails the read and fences nothing new.
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	if err := svc.confirmOwnership(ctx, t0.Add(30*time.Second)); err == nil {
		t.Fatal("confirm with a closed store must fail")
	}
	svc.enforceOwnershipLease(ctx, t0.Add(time.Hour))
}
