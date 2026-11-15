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
// recreates it elsewhere.
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
	svc, st, _ := newLeaseService(t, newFreezeRuntime())
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
