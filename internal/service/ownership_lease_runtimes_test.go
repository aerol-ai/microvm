package service

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/runtime"
	storepkg "github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/models"
)

// fenceGroupRuntime is a Firecracker driver's stand-in: it freezes, and it
// names each VM's own group (runtime.FenceGrouper).
type fenceGroupRuntime struct {
	*freezeRuntime
}

func (r *fenceGroupRuntime) FenceGroup(sandboxID string) string { return "aerolvm-vmm/" + sandboxID }

// On a node that writes the lease file, a recreate-policy create is
// refused for a runtime the runtime supervisor cannot freeze alone (WASM
// and V8 isolates share their host processes; a Firecracker VM whose VMs'
// cgroup is not under the sandboxes' parent), so no such sandbox runs on
// after the cluster recreates it elsewhere (review N2). Anything else, and
// any node without the file, is unchanged.
func TestRefuseUnfencedRecreate(t *testing.T) {
	svc, _, _ := newLeaseService(t, newFreezeRuntime())
	recreate := &models.Failover{Policy: models.FailoverPolicyRecreate}
	for _, tc := range []struct {
		name     string
		file     bool
		failover *models.Failover
		runtime  string
		vmParent string
		refused  bool
	}{
		{"wasm, recreate", true, recreate, models.RuntimeWasm, "", true},
		{"isolate, recreate", true, recreate, models.RuntimeIsolate, "", true},
		{"wasm, no failover", true, nil, models.RuntimeWasm, "", false},
		{"wasm, no lease file", false, recreate, models.RuntimeWasm, "", false},
		{"gvisor, recreate", true, recreate, models.RuntimeGvisor, "", false},
		{"docker, recreate", true, recreate, models.RuntimeDocker, "", false},
		{"firecracker, default VMs' parent", true, recreate, models.RuntimeFirecracker, "", false},
		{"firecracker, the containerd parent", true, recreate, models.RuntimeFirecracker, "/pod/sandboxes", false},
		{"firecracker, another parent", true, recreate, models.RuntimeFirecracker, "/elsewhere", true},
	} {
		svc.cfg.OwnershipLeaseFile = ""
		if tc.file {
			svc.cfg.OwnershipLeaseFile = filepath.Join(t.TempDir(), "ownership-lease")
		}
		svc.cfg.ContainerdCgroupParent = "/pod/sandboxes"
		svc.cfg.HostProcessCgroupParent = tc.vmParent
		err := svc.refuseUnfencedRecreate(tc.failover, tc.runtime)
		if (err != nil) != tc.refused {
			t.Errorf("%s: err = %v, want refused %v", tc.name, err, tc.refused)
		}
		if err != nil && !strings.Contains(err.Error(), "failover.policy=recreate is not available for runtime \""+tc.runtime+"\"") {
			t.Errorf("%s: message %q", tc.name, err)
		}
	}
}

// The refusal is part of every create: before any work, with the create's
// own message.
func TestCreateRefusesAnUnfencedRecreate(t *testing.T) {
	svc, _, _ := newLeaseService(t, newFreezeRuntime())
	svc.cfg.OwnershipLeaseFile = filepath.Join(t.TempDir(), "ownership-lease")
	_, err := svc.CreateSandbox(context.Background(), models.CreateSandboxRequest{
		Image: "registry.example/mod:1", Runtime: models.RuntimeWasm,
		Failover: &models.Failover{Policy: models.FailoverPolicyRecreate},
	})
	if err == nil || !strings.Contains(err.Error(), "failover.policy=recreate is not available for runtime \"wasm\"") {
		t.Fatalf("create = %v, want the recreate refusal", err)
	}
}

// specLeaseCluster is leaseCluster that also holds the cluster's replicated
// specs. While down it reads no spec and takes no write; unread names
// sandboxes whose spec read fails while the rest of the cluster answers (a
// worker's SpecOf reports a failed lookup as no spec), and writeErr fails
// every spec write.
type specLeaseCluster struct {
	*leaseCluster
	specs    map[string]*models.CreateSandboxRequest
	unread   map[string]bool
	writeErr error
	writes   int
	// afterRead, when set, runs after each authoritative read: a test
	// moves a placement between a read and what follows it.
	afterRead func()
}

func (c *specLeaseCluster) AuthoritativePlacementsByIDs(ctx context.Context, ids []string) (map[string]cluster.Placement, error) {
	out, err := c.leaseCluster.AuthoritativePlacementsByIDs(ctx, ids)
	if c.afterRead != nil {
		c.afterRead()
	}
	return out, err
}

func newSpecLeaseCluster(lc *leaseCluster) *specLeaseCluster {
	return &specLeaseCluster{leaseCluster: lc, specs: map[string]*models.CreateSandboxRequest{}, unread: map[string]bool{}}
}

func (c *specLeaseCluster) SpecOf(id string) *models.CreateSandboxRequest {
	c.mu.Lock()
	defer c.mu.Unlock()
	spec, ok := c.specs[id]
	if c.err != nil || c.unread[id] || !ok {
		return nil
	}
	cp := *spec
	return &cp
}

func (c *specLeaseCluster) UpsertSpec(_ context.Context, id string, spec *models.CreateSandboxRequest, _ cluster.PlacementSecrets) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil {
		return c.err
	}
	if c.writeErr != nil {
		return c.writeErr
	}
	c.writes++
	cp := *spec
	c.specs[id] = &cp
	return nil
}

// AuditCallerWritesAllowed: every server takes records with a caller, so
// system action records are written in this cluster.
func (c *specLeaseCluster) AuditCallerWritesAllowed() bool { return true }

func (c *specLeaseCluster) specRecreates(id string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	spec, ok := c.specs[id]
	return ok && spec.ShouldRecreateOnFailover()
}

func (c *specLeaseCluster) writeCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.writes
}

// seedRuntimeRow stores a sandbox of runtime rt in status, with or without
// the recreate policy.
func seedRuntimeRow(t *testing.T, st interface {
	Create(context.Context, *models.Sandbox) error
}, id, rt string, status models.SandboxStatus, recreate bool) {
	t.Helper()
	now := time.Now().UTC()
	sb := &models.Sandbox{ID: id, Image: "alpine:3.20", Status: status, Runtime: rt,
		AuditIncarnationID: "inc-" + id, CPU: 1, MemoryMB: 256, DiskGB: 1, OSUser: "root",
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now}
	if recreate {
		sb.Failover = &models.Failover{Policy: models.FailoverPolicyRecreate}
	}
	if err := st.Create(context.Background(), sb); err != nil {
		t.Fatal(err)
	}
}

// The review's reproduction (V4): a WASM recreate-policy sandbox made
// before the refusal kept running with its policy after its node's lease
// ran out, since nothing can freeze it alone. Now, at the lease's start,
// its policy is turned off; it keeps running, and the cluster never
// recreates it elsewhere. The checks after the disarm, with the leader
// still reachable, prove the switch itself: a lease stop alone would also
// satisfy the review's last check (2f, #1299).
func TestReviewLegacyWasmRecreateCannotRemainUnfenced(t *testing.T) {
	ctx := context.Background()
	svc, st, lc := newLeaseService(t, newFreezeRuntime())
	svc.SetWasmRuntime(&fakeCapacityRuntime{})
	svc.cfg.OwnershipLeaseFile = filepath.Join(t.TempDir(), "lease")
	now := time.Now().UTC()
	sb := &models.Sandbox{ID: "sb-legacy-wasm", Name: "sb-legacy-wasm", Image: "module", Runtime: models.RuntimeWasm, Status: models.SandboxStatusStarted, AuditIncarnationID: "old-inc", Failover: &models.Failover{Policy: models.FailoverPolicyRecreate}, CreatedAt: now, UpdatedAt: now, LastActiveAt: now}
	if err := st.Create(ctx, sb); err != nil {
		t.Fatal(err)
	}
	svc.disarmUnfencedRecreate(ctx)
	switched, err := st.Get(ctx, sb.ID)
	if err != nil {
		t.Fatal(err)
	}
	if switched.Failover != nil && switched.Failover.ShouldRecreate() {
		t.Fatal("the disarm left the recreate policy on while the leader was reachable")
	}
	if switched.Status != models.SandboxStatusStarted {
		t.Fatalf("the disarm changed its status to %s; it must keep running", switched.Status)
	}
	svc.beginOwnershipLease(now)
	lc.down()
	svc.enforceOwnershipLease(ctx, now.Add(time.Minute))
	got, err := st.Get(ctx, sb.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status == models.SandboxStatusStarted && got.Failover != nil && got.Failover.ShouldRecreate() {
		t.Fatal("legacy WASM still executing with recreate policy after lease expiry; warning and request fencing do not stop its host process")
	}
	// Its policy is off, so the lease that ran out does not touch it.
	if got.Status != models.SandboxStatusStarted {
		t.Fatalf("a sandbox whose policy was turned off was stopped when the lease ran out: %s %q", got.Status, got.StatusReason)
	}
}

// At the lease's start every recreate-policy sandbox this node cannot
// freeze alone has its policy turned off: the cluster's spec first, then
// the row, its status reason (if running), one audit record and one log
// line each. Others are untouched; a sandbox placed on another node, or of
// another lifetime, is left to the stale-row paths. With the control plane
// out of reach nothing changes and the pass asks to be retried; a second
// pass, or a restart, repeats nothing.
func TestDisarmUnfencedRecreate(t *testing.T) {
	ctx := context.Background()
	svc, st, lc := newLeaseService(t, newFreezeRuntime())
	svc.SetWasmRuntime(&fakeCapacityRuntime{})
	svc.cfg.OwnershipLeaseFile = filepath.Join(t.TempDir(), "lease")
	sc := newSpecLeaseCluster(lc)
	svc.AttachCluster(sc)
	sink := captureAudit(svc)
	var logs bytes.Buffer
	svc.logger = slog.New(slog.NewTextHandler(&logs, nil))

	seedRuntimeRow(t, st, "wasm-run", models.RuntimeWasm, models.SandboxStatusStarted, true)
	seedRuntimeRow(t, st, "iso-stopped", models.RuntimeIsolate, models.SandboxStatusStopped, true)
	seedRuntimeRow(t, st, "wasm-elsewhere", models.RuntimeWasm, models.SandboxStatusStarted, true)
	seedRuntimeRow(t, st, "wasm-old-life", models.RuntimeWasm, models.SandboxStatusStarted, true)
	seedRuntimeRow(t, st, "wasm-unplaced", models.RuntimeWasm, models.SandboxStatusStarted, true)
	seedRuntimeRow(t, st, "gvisor", models.RuntimeGvisor, models.SandboxStatusStarted, true)
	seedRuntimeRow(t, st, "wasm-plain", models.RuntimeWasm, models.SandboxStatusStarted, false)
	if err := st.UpdateStatusWithReason(ctx, "iso-stopped", models.SandboxStatusStopped, "", models.StatusReasonUserStop, nil); err != nil {
		t.Fatal(err)
	}
	recreate := func() *models.CreateSandboxRequest {
		return &models.CreateSandboxRequest{Image: "alpine:3.20", Failover: &models.Failover{Policy: models.FailoverPolicyRecreate}}
	}
	elsewhere := selfPlacement("wasm-elsewhere")
	elsewhere.OwnerNodeID = "worker-b"
	oldLife := selfPlacement("wasm-old-life")
	oldLife.IncarnationID = "inc-new"
	placements := []cluster.Placement{selfPlacement("wasm-run"), selfPlacement("iso-stopped"), elsewhere, oldLife, selfPlacement("gvisor")}
	for _, p := range placements {
		sc.specs[p.SandboxID] = recreate()
	}

	// The control plane is out of reach: nothing changes, retry asked.
	lc.down()
	if svc.disarmUnfencedRecreate(ctx) {
		t.Fatal("a pass with the control plane down reported nothing left to do")
	}
	for _, id := range []string{"wasm-run", "iso-stopped", "wasm-unplaced"} {
		if got, _ := st.Get(ctx, id); got.Failover == nil || !got.Failover.ShouldRecreate() {
			t.Fatalf("%s changed with the control plane down", id)
		}
	}

	lc.up(placements...)
	if !svc.disarmUnfencedRecreate(ctx) {
		t.Fatal("a pass with the control plane up left work to retry")
	}
	for _, tc := range []struct {
		id         string
		specOff    bool
		rowOff     bool
		reason     string
		audited    bool
		specExists bool
	}{
		{"wasm-run", true, true, statusReasonFailoverDisabled, true, true},
		{"iso-stopped", true, true, models.StatusReasonUserStop, true, true},
		{"wasm-unplaced", false, true, statusReasonFailoverDisabled, true, false},
		{"wasm-elsewhere", false, false, "", false, true},
		{"wasm-old-life", false, false, "", false, true},
		{"gvisor", false, false, "", false, true},
		{"wasm-plain", false, false, "", false, false},
	} {
		got, err := st.Get(ctx, tc.id)
		if err != nil {
			t.Fatal(err)
		}
		rowRecreates := got.Failover != nil && got.Failover.ShouldRecreate()
		if tc.rowOff == rowRecreates && tc.id != "wasm-plain" {
			t.Errorf("%s: row recreate = %v", tc.id, rowRecreates)
		}
		if tc.specExists && sc.specRecreates(tc.id) == tc.specOff {
			t.Errorf("%s: spec recreate = %v, want %v", tc.id, sc.specRecreates(tc.id), !tc.specOff)
		}
		if got.StatusReason != tc.reason {
			t.Errorf("%s: status reason %q, want %q", tc.id, got.StatusReason, tc.reason)
		}
		if got.Status == models.SandboxStatusStopped && tc.id != "iso-stopped" {
			t.Errorf("%s: stopped", tc.id)
		}
		records := systemRecords(sink, tc.id)
		if tc.audited {
			wantRecords(t, records, auditRecord{ref: sys(systemActionFailoverDisabled), reason: records[0].reason, caller: "system:failover", result: "ok"})
			if !strings.Contains(records[0].reason, "cannot freeze it alone") {
				t.Errorf("%s: audit reason %q", tc.id, records[0].reason)
			}
		} else if len(records) != 0 {
			t.Errorf("%s: audited %+v", tc.id, records)
		}
	}
	if c := strings.Count(logs.String(), "failover.policy=recreate turned off"); c != 3 {
		t.Fatalf("logged %d switches, want 3: %s", c, logs.String())
	}

	// Again: nothing to do, nothing written, nothing recorded.
	writes := sc.writeCount()
	before := len(sink.Events())
	if !svc.disarmUnfencedRecreate(ctx) || sc.writeCount() != writes || len(sink.Events()) != before {
		t.Fatalf("a second pass changed something: writes %d -> %d, records %d -> %d", writes, sc.writeCount(), before, len(sink.Events()))
	}
}

// A restart after the cluster took the change but before the row did (or a
// row whose write failed) finishes the row without writing the spec again.
// A spec the worker could not read, a spec write that fails, and a
// placement between owners change nothing and ask to be retried.
func TestDisarmUnfencedRecreateRetries(t *testing.T) {
	ctx := context.Background()
	svc, st, lc := newLeaseService(t, newFreezeRuntime())
	svc.SetWasmRuntime(&fakeCapacityRuntime{})
	svc.cfg.OwnershipLeaseFile = filepath.Join(t.TempDir(), "lease")
	sc := newSpecLeaseCluster(lc)
	svc.AttachCluster(sc)
	seedRuntimeRow(t, st, "half", models.RuntimeWasm, models.SandboxStatusStarted, true)
	sc.specs["half"] = &models.CreateSandboxRequest{Image: "alpine:3.20", Failover: &models.Failover{Policy: models.FailoverPolicyNone}}
	lc.up(selfPlacement("half"))
	if !svc.disarmUnfencedRecreate(ctx) || sc.writeCount() != 0 {
		t.Fatalf("finishing a half-done switch wrote the spec %d times", sc.writeCount())
	}
	if got, _ := st.Get(ctx, "half"); got.Failover != nil && got.Failover.ShouldRecreate() {
		t.Fatal("the row kept its policy")
	}

	recreate := &models.CreateSandboxRequest{Image: "alpine:3.20", Failover: &models.Failover{Policy: models.FailoverPolicyRecreate}}
	for _, tc := range []struct {
		name  string
		setup func(id string) cluster.Placement
	}{
		{"unread spec", func(id string) cluster.Placement {
			sc.unread[id] = true
			return selfPlacement(id)
		}},
		{"failed spec write", func(id string) cluster.Placement {
			sc.writeErr = errors.New("leader lost")
			return selfPlacement(id)
		}},
		{"reserved placement", func(id string) cluster.Placement {
			p := selfPlacement(id)
			p.State = cluster.PlacementStateReserved
			return p
		}},
		{"orphaned placement of this node", func(id string) cluster.Placement {
			p := selfPlacement(id)
			p.OwnerNodeID = ""
			p.OrphanedOwnerNodeID = "worker-a"
			return p
		}},
	} {
		id := "retry-" + strings.ReplaceAll(tc.name, " ", "-")
		seedRuntimeRow(t, st, id, models.RuntimeWasm, models.SandboxStatusStarted, true)
		sc.specs[id] = recreate
		lc.up(tc.setup(id))
		if svc.disarmUnfencedRecreate(ctx) {
			t.Errorf("%s: reported nothing left to do", tc.name)
		}
		if got, _ := st.Get(ctx, id); got.Failover == nil || !got.Failover.ShouldRecreate() {
			t.Errorf("%s: the row changed", tc.name)
		}
		if !sc.specRecreates(id) {
			t.Errorf("%s: the spec changed", tc.name)
		}
		sc.writeErr = nil
		delete(sc.unread, id)
		if err := st.Delete(ctx, id); err != nil {
			t.Fatal(err)
		}
	}
}

// The loop runs at the lease's start in its own goroutine, and keeps
// retrying while the control plane is out of reach, then stops once a pass
// finds nothing left. A node without the lease file runs nothing.
func TestStartDisarmUnfencedRecreate(t *testing.T) {
	svc, st, lc := newLeaseService(t, newFreezeRuntime())
	svc.SetWasmRuntime(&fakeCapacityRuntime{})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	seedRuntimeRow(t, st, "wasm", models.RuntimeWasm, models.SandboxStatusStarted, true)
	svc.startDisarmUnfencedRecreate(ctx, 5*time.Millisecond)
	time.Sleep(30 * time.Millisecond)
	if got, _ := st.Get(ctx, "wasm"); got.Failover == nil || !got.Failover.ShouldRecreate() {
		t.Fatal("changed a row on a node without the lease file")
	}

	svc.cfg.OwnershipLeaseFile = filepath.Join(t.TempDir(), "lease")
	lc.down()
	svc.startDisarmUnfencedRecreate(ctx, 5*time.Millisecond)
	time.Sleep(30 * time.Millisecond)
	before := lc.readCount()
	if before < 2 {
		t.Fatalf("%d reads with the control plane down, want retries", before)
	}
	lc.up()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if got, _ := st.Get(ctx, "wasm"); got.Failover == nil || !got.Failover.ShouldRecreate() {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if got, _ := st.Get(ctx, "wasm"); got.Failover != nil && got.Failover.ShouldRecreate() {
		t.Fatal("the policy was never turned off once the control plane answered")
	}
	settled := lc.readCount()
	time.Sleep(30 * time.Millisecond)
	if lc.readCount() != settled {
		t.Fatalf("the loop kept reading after it finished: %d -> %d", settled, lc.readCount())
	}

	// A cancelled start runs one pass at most and ends.
	done, stop := context.WithCancel(context.Background())
	stop()
	svc.startDisarmUnfencedRecreate(done, time.Millisecond)
}

// If the lease runs out before the cluster took the change (its leader out
// of reach since this node started), a recreate-policy sandbox nothing can
// freeze is stopped: a stopped sandbox cannot run beside a recreated copy.
// Its policy stays; it is not started again by itself. Without the lease
// file, it is refused but left running, as before.
func TestLeaseStopsAnUnfenceableRecreateWhenItRunsOut(t *testing.T) {
	ctx := context.Background()
	svc, st, lc := newLeaseService(t, newFreezeRuntime())
	svc.SetWasmRuntime(&fakeCapacityRuntime{})
	svc.AttachCluster(newSpecLeaseCluster(lc))
	sink := captureAudit(svc)
	seedRuntimeRow(t, st, "no-file", models.RuntimeWasm, models.SandboxStatusStarted, true)
	t0 := time.Unix(60_000, 0)
	svc.beginOwnershipLease(t0)
	lc.down()
	svc.enforceOwnershipLease(ctx, t0.Add(16*time.Second))
	if got, _ := st.Get(ctx, "no-file"); got.Status != models.SandboxStatusStarted {
		t.Fatalf("without the lease file: %s, want left running", got.Status)
	}
	if err := st.Delete(ctx, "no-file"); err != nil {
		t.Fatal(err)
	}

	svc.cfg.OwnershipLeaseFile = filepath.Join(t.TempDir(), "lease")
	seedRuntimeRow(t, st, "wasm", models.RuntimeWasm, models.SandboxStatusStarted, true)
	svc.enforceOwnershipLease(ctx, t0.Add(17*time.Second))
	got, _ := st.Get(ctx, "wasm")
	if got.Status != models.SandboxStatusStopped || got.StatusReason != statusReasonOwnershipLeaseExpired {
		t.Fatalf("status %s reason %q, want stopped %q", got.Status, got.StatusReason, statusReasonOwnershipLeaseExpired)
	}
	if got.Failover == nil || !got.Failover.ShouldRecreate() {
		t.Fatal("the stop dropped the recreate policy")
	}
	records := systemRecords(sink, "wasm")
	if len(records) != 1 || records[0].ref != sys(systemActionLeaseStop) || records[0].caller != "system:failover" {
		t.Fatalf("records %+v", records)
	}
	// Settled: the next check does nothing more.
	svc.enforceOwnershipLease(ctx, t0.Add(18*time.Second))
	if n := len(systemRecords(sink, "wasm")); n != 1 {
		t.Fatalf("%d records after another check", n)
	}
}

// A placement can change owner between the pass's read and the spec write:
// the leader reassigns a sandbox whose node gossip calls dead even while
// that node's reads still reach it. The owner is read again under the spec
// lock, on each write attempt, so this node never turns off the recreate
// policy of a sandbox another node now owns (2f, #1299, point 3a).
func TestDisarmLeavesASpecThatMovedAfterTheRead(t *testing.T) {
	ctx := context.Background()
	svc, st, lc := newLeaseService(t, newFreezeRuntime())
	svc.SetWasmRuntime(&fakeCapacityRuntime{})
	svc.cfg.OwnershipLeaseFile = filepath.Join(t.TempDir(), "lease")
	sc := newSpecLeaseCluster(lc)
	svc.AttachCluster(sc)
	seedRuntimeRow(t, st, "wasm", models.RuntimeWasm, models.SandboxStatusStarted, true)
	sc.specs["wasm"] = &models.CreateSandboxRequest{Image: "alpine:3.20", Failover: &models.Failover{Policy: models.FailoverPolicyRecreate}}
	lc.up(selfPlacement("wasm"))
	moved := selfPlacement("wasm")
	moved.OwnerNodeID = "worker-b"
	reads := 0
	sc.afterRead = func() {
		reads++
		if reads == 1 {
			lc.up(moved)
		}
	}
	if !svc.disarmUnfencedRecreate(ctx) {
		t.Fatal("a sandbox that moved away is not this node's to retry")
	}
	if sc.writeCount() != 0 || !sc.specRecreates("wasm") {
		t.Fatalf("another node's spec was rewritten: %d writes, recreate %v", sc.writeCount(), sc.specRecreates("wasm"))
	}
	if got, _ := st.Get(ctx, "wasm"); got.Failover == nil || !got.Failover.ShouldRecreate() {
		t.Fatal("the stale local row changed; the stale-row paths own it")
	}
	if reads < 2 {
		t.Fatalf("the owner was read %d times; it must be read again under the spec lock", reads)
	}

	// Orphaned in that window, but this node's to claim back: retried.
	if err := st.Delete(ctx, "wasm"); err != nil {
		t.Fatal(err)
	}
	seedRuntimeRow(t, st, "wasm-o", models.RuntimeWasm, models.SandboxStatusStarted, true)
	sc.specs["wasm-o"] = &models.CreateSandboxRequest{Image: "alpine:3.20", Failover: &models.Failover{Policy: models.FailoverPolicyRecreate}}
	orphaned := selfPlacement("wasm-o")
	orphaned.OwnerNodeID, orphaned.OrphanedOwnerNodeID = "", "worker-a"
	reads = 0
	sc.afterRead = func() {
		reads++
		if reads == 1 {
			lc.up(orphaned)
		}
	}
	lc.up(selfPlacement("wasm-o"))
	if svc.disarmUnfencedRecreate(ctx) {
		t.Fatal("a placement this node can claim back must be retried")
	}
	if sc.writeCount() != 0 || !sc.specRecreates("wasm-o") {
		t.Fatal("the spec of a placement between owners was rewritten")
	}

	// The second read fails: retried, nothing written. The placement is
	// gone by the second read: left alone, nothing written.
	for _, tc := range []struct {
		name  string
		after func()
		done  bool
	}{
		{"the owner read fails", lc.down, false},
		{"the placement is gone", func() { lc.up() }, true},
	} {
		reads = 0
		sc.afterRead = func() {
			reads++
			if reads == 1 {
				tc.after()
			}
		}
		lc.up(selfPlacement("wasm-o"))
		if got := svc.disarmUnfencedRecreate(ctx); got != tc.done {
			t.Errorf("%s: done = %v, want %v", tc.name, got, tc.done)
		}
		if sc.writeCount() != 0 || !sc.specRecreates("wasm-o") {
			t.Errorf("%s: the spec was rewritten", tc.name)
		}
	}
}

// 2f's race in #1299's review: enforceOwnershipLease lists the recreate
// rows, then fences each one under its lifecycle lock. A disarm that turned
// a sandbox's policy off in between left the fence acting on its stale
// listing: it stopped a sandbox whose policy was already none, with reason
// ownership_lease_expired, the opposite of "it keeps running". The fence
// now reads the row again and fences only a row that still has the policy.
func TestFenceSkipsARowDisarmedAfterTheListing(t *testing.T) {
	ctx := context.Background()
	svc, st, lc := newLeaseService(t, newFreezeRuntime())
	svc.SetWasmRuntime(&fakeCapacityRuntime{})
	svc.AttachCluster(newSpecLeaseCluster(lc))
	svc.cfg.OwnershipLeaseFile = filepath.Join(t.TempDir(), "lease")
	seedRuntimeRow(t, st, "wasm", models.RuntimeWasm, models.SandboxStatusStarted, true)
	svc.beginOwnershipLease(time.Unix(80_000, 0))

	// The listing enforceOwnershipLease makes once the lease ran out.
	rows, err := svc.localRecreateSandboxes(ctx)
	if err != nil || len(rows) != 1 {
		t.Fatalf("listing: %v %v", rows, err)
	}
	// The disarm lands in between.
	lc.up()
	if !svc.disarmUnfencedRecreate(ctx) {
		t.Fatal("disarm left work to retry")
	}
	lc.down()
	// The fence, from that listing.
	svc.fenceSandbox(ctx, rows[0].ID)

	got, err := st.Get(ctx, "wasm")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != models.SandboxStatusStarted || got.StatusReason == statusReasonOwnershipLeaseExpired {
		t.Fatalf("a sandbox whose policy was already off was stopped: status %s reason %q", got.Status, got.StatusReason)
	}
	if got.Failover != nil && got.Failover.ShouldRecreate() {
		t.Fatal("the policy came back")
	}
	if svc.OwnershipFenced("wasm") {
		t.Fatal("a sandbox without the recreate policy was fenced")
	}
}

// stopErrRuntime is a runtime whose stop fails.
type stopErrRuntime struct {
	*fakeCapacityRuntime
	err error
}

func (r *stopErrRuntime) Stop(context.Context, string) error { return r.err }

// The fence's stop is tried again while it fails; a sandbox that cannot be
// frozen where it runs (ErrCannotFreeze, a VM with no group of its own) is
// stopped the same way on a node that writes the lease file; a sandbox not
// running is not stopped.
func TestStopUnfenceableEdges(t *testing.T) {
	ctx := context.Background()
	svc, st, lc := newLeaseService(t, newFreezeRuntime())
	bad := &stopErrRuntime{fakeCapacityRuntime: &fakeCapacityRuntime{}, err: errors.New("host process gone")}
	svc.SetWasmRuntime(bad)
	svc.AttachCluster(newSpecLeaseCluster(lc))
	svc.cfg.OwnershipLeaseFile = filepath.Join(t.TempDir(), "lease")
	var logs bytes.Buffer
	svc.logger = slog.New(slog.NewTextHandler(&logs, nil))
	seedRuntimeRow(t, st, "wasm", models.RuntimeWasm, models.SandboxStatusStarted, true)
	t0 := time.Unix(70_000, 0)
	svc.beginOwnershipLease(t0)
	lc.down()
	svc.enforceOwnershipLease(ctx, t0.Add(16*time.Second))
	if got, _ := st.Get(ctx, "wasm"); got.Status != models.SandboxStatusStarted {
		t.Fatalf("a failed stop left status %s", got.Status)
	}
	if !strings.Contains(logs.String(), "could not stop a sandbox the ownership lease no longer covers") {
		t.Fatalf("no warning: %s", logs.String())
	}
	bad.err = nil
	svc.enforceOwnershipLease(ctx, t0.Add(17*time.Second))
	if got, _ := st.Get(ctx, "wasm"); got.Status != models.SandboxStatusStopped {
		t.Fatalf("the stop was not tried again: %s", got.Status)
	}
	if svc.stopUnfenceable(ctx, &models.Sandbox{ID: "x", Status: models.SandboxStatusStopped}, &fencedSandbox{}) {
		t.Fatal("stopped a sandbox that was not running")
	}

	rt := newFreezeRuntime()
	rt.freezeErr = fmt.Errorf("vm has no group of its own: %w", runtime.ErrCannotFreeze)
	svc2, st2, lc2 := newLeaseService(t, rt)
	svc2.AttachCluster(newSpecLeaseCluster(lc2))
	svc2.cfg.OwnershipLeaseFile = filepath.Join(t.TempDir(), "lease")
	seedLeaseRow(t, st2, "ctr", true, models.SandboxStatusStarted)
	svc2.beginOwnershipLease(t0)
	lc2.down()
	svc2.enforceOwnershipLease(ctx, t0.Add(16*time.Second))
	got, _ := st2.Get(ctx, "ctr")
	if got.Status != models.SandboxStatusStopped || got.StatusReason != statusReasonOwnershipLeaseExpired {
		t.Fatalf("status %s reason %q, want stopped %q", got.Status, got.StatusReason, statusReasonOwnershipLeaseExpired)
	}
}

// A stop that keeps failing is tried at every check (lease/15, 1 s by
// default), but writes one audit record and one log line for the whole
// run of failures, not one per check; the stop that finally works writes
// its own record (2f, #1299, point 3b).
func TestFailingLeaseStopRecordsOncePerRun(t *testing.T) {
	ctx := context.Background()
	svc, st, lc := newLeaseService(t, newFreezeRuntime())
	bad := &stopErrRuntime{fakeCapacityRuntime: &fakeCapacityRuntime{}, err: errors.New("host process gone")}
	svc.SetWasmRuntime(bad)
	svc.AttachCluster(newSpecLeaseCluster(lc))
	sink := captureAudit(svc)
	var logs bytes.Buffer
	svc.logger = slog.New(slog.NewTextHandler(&logs, nil))
	svc.cfg.OwnershipLeaseFile = filepath.Join(t.TempDir(), "lease")
	seedRuntimeRow(t, st, "wasm", models.RuntimeWasm, models.SandboxStatusStarted, true)
	t0 := time.Unix(90_000, 0)
	svc.beginOwnershipLease(t0)
	lc.down()
	for i := range 5 {
		svc.enforceOwnershipLease(ctx, t0.Add(time.Duration(16+i)*time.Second))
	}
	records := systemRecords(sink, "wasm")
	if len(records) != 1 || records[0].ref != sys(systemActionLeaseStop) || records[0].result == "ok" {
		t.Fatalf("5 failed stops wrote %+v, want one failure record", records)
	}
	if c := strings.Count(logs.String(), "could not stop a sandbox the ownership lease no longer covers"); c != 1 {
		t.Fatalf("logged the failure %d times, want once", c)
	}
	bad.err = nil
	svc.enforceOwnershipLease(ctx, t0.Add(22*time.Second))
	records = systemRecords(sink, "wasm")
	if len(records) != 2 || records[1].result != "ok" {
		t.Fatalf("the stop that worked: %+v", records)
	}
	if got, _ := st.Get(ctx, "wasm"); got.Status != models.SandboxStatusStopped {
		t.Fatalf("status %s", got.Status)
	}
}

// The pass's edges: nothing to do without the lease file or without a
// sandbox it cannot freeze; a row gone, changed, or placed as another
// node's orphan by the time the lock is held is left alone; a cancelled
// pass changes nothing.
func TestDisarmUnfencedRecreateEdges(t *testing.T) {
	ctx := context.Background()
	svc, st, lc := newLeaseService(t, newFreezeRuntime())
	svc.SetWasmRuntime(&fakeCapacityRuntime{})
	sc := newSpecLeaseCluster(lc)
	svc.AttachCluster(sc)
	seedRuntimeRow(t, st, "wasm", models.RuntimeWasm, models.SandboxStatusStarted, true)
	if !svc.disarmUnfencedRecreate(ctx) {
		t.Fatal("without the lease file there is nothing to do")
	}
	svc.cfg.OwnershipLeaseFile = filepath.Join(t.TempDir(), "lease")
	if err := st.Delete(ctx, "wasm"); err != nil {
		t.Fatal(err)
	}
	seedLeaseRow(t, st, "ctr", true, models.SandboxStatusStarted)
	if !svc.disarmUnfencedRecreate(ctx) {
		t.Fatal("only freezable sandboxes: nothing to do")
	}

	self := "worker-a"
	if err := svc.disarmRecreate(ctx, sc, "gone", cluster.Placement{}, false, self); err != nil {
		t.Fatalf("a row gone: %v", err)
	}
	if err := svc.disarmRecreate(ctx, sc, "ctr", cluster.Placement{}, false, self); err != nil {
		t.Fatalf("a freezable row: %v", err)
	}
	if got, _ := st.Get(ctx, "ctr"); got.Failover == nil || !got.Failover.ShouldRecreate() {
		t.Fatal("a freezable row lost its policy")
	}
	seedRuntimeRow(t, st, "wasm-2", models.RuntimeWasm, models.SandboxStatusStarted, true)
	orphan := cluster.Placement{SandboxID: "wasm-2", IncarnationID: "inc-wasm-2", OrphanedOwnerNodeID: "worker-b"}
	if err := svc.disarmRecreate(ctx, sc, "wasm-2", orphan, true, self); err != nil {
		t.Fatalf("another node's orphan: %v", err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if err := svc.disarmRecreate(cancelled, sc, "wasm-2", cluster.Placement{}, false, self); err == nil {
		t.Fatal("a cancelled pass took the lock")
	}
	if got, _ := st.Get(ctx, "wasm-2"); got.Failover == nil || !got.Failover.ShouldRecreate() {
		t.Fatal("the row changed")
	}
	if err := svc.writeFailoverNoneSpec(cancelled, sc, &models.Sandbox{ID: "wasm-2"}, self); err == nil {
		t.Fatal("a cancelled spec write took the spec lock")
	}
	if svc.disarmUnfencedRecreate(cancelled) {
		t.Fatal("a cancelled pass reported nothing left to do")
	}

	// The check itself: no policy, no row, a runtime this node lacks.
	if svc.unfenceableRecreate(nil) || svc.unfenceableRecreate(&models.Sandbox{Runtime: models.RuntimeWasm}) {
		t.Fatal("a sandbox without the recreate policy counted")
	}
	svc.firecracker = nil
	if err := svc.recreateFenceReady(&models.Sandbox{ID: "fc", Runtime: models.RuntimeFirecracker, Failover: &models.Failover{Policy: models.FailoverPolicyRecreate}}); err != nil {
		t.Fatalf("no Firecracker driver: %v", err)
	}
}

// fenceCheckRuntime is a Firecracker driver's stand-in that reports where
// each VM runs (runtime.FenceChecker): err for every VM.
type fenceCheckRuntime struct {
	*fenceGroupRuntime
	err   error
	stops int
}

func (r *fenceCheckRuntime) FenceReady(string) error { return r.err }

func (r *fenceCheckRuntime) Stop(ctx context.Context, ref string) error {
	r.stops++
	return r.fenceGroupRuntime.Stop(ctx, ref)
}

// A failover.policy=recreate Firecracker VM that did not reach its own
// group, on a node that writes the lease file, does not run: its create is
// refused before its row exists, and its start stops it again and marks it
// in error. A VM in its group, one with no recreate policy, and any node
// without the lease file are unchanged.
func TestRecreateVMOutsideItsGroupDoesNotRun(t *testing.T) {
	ctx := context.Background()
	svc, st, lc := newLeaseService(t, newFreezeRuntime())
	// Each create's reservation names this node, as a real create's does:
	// a recreate-policy create reads it before its row is written (V3).
	lc.up(reservedFor("fc-nofile", "worker-a", ""), reservedFor("fc-out", "worker-a", ""), reservedFor("fc-in", "worker-a", ""))
	fc := &fenceCheckRuntime{fenceGroupRuntime: &fenceGroupRuntime{newFreezeRuntime()}, err: errors.New("firecracker VM runs in the VMs' shared cgroup")}
	svc.firecracker = fc
	svc.admitter = capacity.New(capacity.HostInfo{CPUCores: 8, MemoryTotalMB: 16384, SupportedRuntimes: []string{models.RuntimeDocker, models.RuntimeFirecracker}},
		capacity.Limits{CPUReservationRatio: 1, MemoryReservationRatio: 1}, nil)
	now := time.Now().UTC()
	row := func(id string, recreate bool) *models.Sandbox {
		sb := &models.Sandbox{ID: id, Image: "alpine:3.20", Status: models.SandboxStatusStarted, Runtime: models.RuntimeFirecracker,
			CPU: 1, MemoryMB: 256, DiskGB: 1, OSUser: "root", CreatedAt: now, UpdatedAt: now, LastActiveAt: now}
		if recreate {
			sb.Failover = &models.Failover{Policy: models.FailoverPolicyRecreate}
		}
		return sb
	}

	// No lease file: the VM's group does not matter.
	if err := svc.persistSandboxCreate(ctx, row("fc-nofile", true)); err != nil {
		t.Fatalf("no lease file: %v", err)
	}
	svc.cfg.OwnershipLeaseFile = filepath.Join(t.TempDir(), "lease")
	if err := svc.persistSandboxCreate(ctx, row("fc-none", false)); err != nil {
		t.Fatalf("no recreate policy: %v", err)
	}
	err := svc.persistSandboxCreate(ctx, row("fc-out", true))
	if err == nil || !strings.Contains(err.Error(), "failover.policy=recreate cannot run here") || !strings.Contains(err.Error(), "shared cgroup") {
		t.Fatalf("create of a VM outside its group = %v", err)
	}
	if _, err := st.Get(ctx, "fc-out"); !errors.Is(err, storepkg.ErrNotFound) {
		t.Fatalf("its row exists: %v", err)
	}
	fc.err = nil
	if err := svc.persistSandboxCreate(ctx, row("fc-in", true)); err != nil {
		t.Fatalf("VM in its group: %v", err)
	}

	// A start: the VM comes up outside its group and is stopped again.
	fc.err = errors.New("firecracker VM runs outside the VMs' cgroup")
	fc.startResult = &models.SandboxRuntimeState{ContainerID: "fc-in", Status: models.SandboxStatusStarted}
	if err := st.UpdateStatus(ctx, "fc-in", models.SandboxStatusStopped, ""); err != nil {
		t.Fatal(err)
	}
	stops := fc.stops
	if _, err := svc.StartSandbox(ctx, "fc-in"); err == nil || !strings.Contains(err.Error(), "outside the VMs' cgroup") {
		t.Fatalf("start = %v", err)
	}
	if fc.stops != stops+1 {
		t.Fatalf("stops %d -> %d, want one", stops, fc.stops)
	}
	if got, _ := st.Get(ctx, "fc-in"); got.Status != models.SandboxStatusError {
		t.Fatalf("status %s, want error", got.Status)
	}
	fc.err = nil
	if err := st.UpdateStatus(ctx, "fc-in", models.SandboxStatusStopped, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.StartSandbox(ctx, "fc-in"); err != nil {
		t.Fatalf("start in its group: %v", err)
	}
}

// A running recreate-policy VM an older release left in the VMs' shared
// group, whose move into its own group failed at adoption, is treated like
// a legacy WASM sandbox: its policy is turned off and it keeps running. A
// stopped one is left alone (its next start checks its group).
func TestDisarmTurnsOffAnAdoptedVMOutsideItsGroup(t *testing.T) {
	ctx := context.Background()
	svc, st, lc := newLeaseService(t, newFreezeRuntime())
	fc := &fenceCheckRuntime{fenceGroupRuntime: &fenceGroupRuntime{newFreezeRuntime()}, err: errors.New("firecracker VM runs in the VMs' shared cgroup")}
	svc.firecracker = fc
	svc.cfg.OwnershipLeaseFile = filepath.Join(t.TempDir(), "lease")
	seedRuntimeRow(t, st, "vm-run", models.RuntimeFirecracker, models.SandboxStatusStarted, true)
	seedRuntimeRow(t, st, "vm-stopped", models.RuntimeFirecracker, models.SandboxStatusStopped, true)
	lc.up()
	if !svc.disarmUnfencedRecreate(ctx) {
		t.Fatal("left work to retry")
	}
	if got, _ := st.Get(ctx, "vm-run"); got.Failover != nil && got.Failover.ShouldRecreate() {
		t.Fatal("a running VM outside its group kept its recreate policy")
	} else if got.Status != models.SandboxStatusStarted || got.StatusReason != statusReasonFailoverDisabled {
		t.Fatalf("status %s reason %q", got.Status, got.StatusReason)
	}
	if got, _ := st.Get(ctx, "vm-stopped"); got.Failover == nil || !got.Failover.ShouldRecreate() {
		t.Fatal("a stopped VM lost its policy")
	}
	if why := svc.unfenceableWhy(&models.Sandbox{ID: "vm-run", Runtime: models.RuntimeFirecracker, Failover: &models.Failover{Policy: models.FailoverPolicyRecreate}}); why != "its VM is not in a group of its own" {
		t.Fatalf("why = %q", why)
	}
	svc.cfg.HostProcessCgroupParent = "/elsewhere"
	if why := svc.unfenceableWhy(&models.Sandbox{Runtime: models.RuntimeFirecracker}); why != "its VMs' cgroup is not under the sandboxes' cgroup parent" {
		t.Fatalf("why = %q", why)
	}
	svc.cfg.HostProcessCgroupParent = ""
	fc.err = nil
	if why := svc.unfenceableWhy(&models.Sandbox{Runtime: models.RuntimeFirecracker, Failover: &models.Failover{Policy: models.FailoverPolicyRecreate}}); why != "its runtime cannot freeze it" {
		t.Fatalf("why = %q", why)
	}
}

// The lease file names a Firecracker VM by its own group,
// aerolvm-vmm/<sandbox>, which the runtime supervisor freezes; a container
// still by its container ref. Before, the VM's entry was its sandbox ID, a
// group that did not exist, and nothing froze it (review N2).
func TestLeaseFileNamesAFirecrackerVMsOwnGroup(t *testing.T) {
	ctx := context.Background()
	svc, st, lc := newLeaseService(t, newFreezeRuntime())
	svc.firecracker = &fenceGroupRuntime{newFreezeRuntime()}
	path := filepath.Join(t.TempDir(), "ownership-lease")
	svc.cfg.OwnershipLeaseFile = path
	seedLeaseRow(t, st, "a", true, models.SandboxStatusStarted)
	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID: "fc", Image: "alpine:3.20", Status: models.SandboxStatusStarted, Runtime: models.RuntimeFirecracker,
		AuditIncarnationID: "inc-fc", Failover: &models.Failover{Policy: models.FailoverPolicyRecreate},
		CPU: 1, MemoryMB: 256, DiskGB: 1, OSUser: "root", CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	lc.up(selfPlacement("a"), selfPlacement("fc"))
	if err := svc.confirmOwnership(ctx, time.Now()); err != nil {
		t.Fatal(err)
	}
	l := readLeaseFile(t, path)
	slices.Sort(l.Fence)
	slices.Sort(l.Owned)
	want := []string{"aerolvm-vmm/fc", "ctr-a"}
	if !slices.Equal(l.Fence, want) || !slices.Equal(l.Owned, want) {
		t.Fatalf("fence %v owned %v, want %v in both", l.Fence, l.Owned, want)
	}
	// A Firecracker driver that is not registered: the sandbox ID, as
	// before (nothing names a group for it).
	svc.firecracker = nil
	if ref := svc.fenceRef(&models.Sandbox{ID: "fc", Runtime: models.RuntimeFirecracker}); ref != "fc" {
		t.Fatalf("fenceRef without a driver = %q", ref)
	}
}

// A sandbox the runtime cannot freeze where it runs (a Firecracker VM with
// no group of its own) is fenced and left running, like a runtime with no
// Freezer: tried once, not on every check.
func TestFenceSettlesASandboxThatCannotBeFrozen(t *testing.T) {
	ctx := context.Background()
	rt := newFreezeRuntime()
	rt.freezeErr = fmt.Errorf("vm sb-ha has no group of its own: %w", runtime.ErrCannotFreeze)
	svc, st, lc := newLeaseService(t, rt)
	seedLeaseRow(t, st, "sb-ha", true, models.SandboxStatusStarted)
	t0 := time.Unix(50_000, 0)
	svc.beginOwnershipLease(t0)
	lc.down()
	svc.enforceOwnershipLease(ctx, t0.Add(16*time.Second))
	svc.enforceOwnershipLease(ctx, t0.Add(17*time.Second))
	if !svc.OwnershipFenced("sb-ha") || rt.isFrozen("ctr-sb-ha") {
		t.Fatal("a sandbox that cannot be frozen must be fenced and left unfrozen")
	}
	rt.mu.Lock()
	freezes := rt.freezes
	rt.mu.Unlock()
	if freezes != 1 {
		t.Fatalf("Freeze called %d times, want once", freezes)
	}
}
