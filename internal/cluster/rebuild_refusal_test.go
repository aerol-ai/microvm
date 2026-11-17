package cluster

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/volumes"
)

// platformMount is the mount a platform volume named name of ownerRef's
// becomes in a replicated spec, on an S3 backend.
func platformMount(ownerRef, name string) models.MountSpec {
	return models.MountSpec{Type: models.MountTypeS3, Source: "vols/pfx/" + volumes.TenantForOwnerRef(ownerRef) + "/" + name, Target: "/data"}
}

// What the leader can tell, with no node's volume or module configuration,
// rules a sandbox out of a rebuild on another node.
func TestHostOnlySettings(t *testing.T) {
	const owner = "team:payments"
	opScope := models.MountSpec{Type: models.MountTypeNFS, Source: "nfs.local:/exports/op-1234abcd/data", Target: "/d"}
	for _, tc := range []struct {
		name  string
		owner string
		spec  *models.CreateSandboxRequest
		want  string
	}{
		{"no spec", owner, nil, ""},
		{"nothing host-only", owner, &models.CreateSandboxRequest{Image: "alpine"}, ""},
		{"the owner's platform volume", owner, &models.CreateSandboxRequest{Mounts: []models.MountSpec{platformMount(owner, "data")}}, ""},
		{"an nfs platform volume on a root export", owner, &models.CreateSandboxRequest{Mounts: []models.MountSpec{{Type: models.MountTypeNFS, Source: "nfs.local:/" + volumes.TenantForOwnerRef(owner) + "/data", Target: "/d"}}}, ""},
		{"an operator volume of an operator sandbox", "", &models.CreateSandboxRequest{Mounts: []models.MountSpec{opScope}}, ""},
		{"an operator volume in a team's sandbox", owner, &models.CreateSandboxRequest{Mounts: []models.MountSpec{opScope}}, "mounts"},
		{"another team's volume", owner, &models.CreateSandboxRequest{Mounts: []models.MountSpec{platformMount("team:other", "data")}}, "mounts"},
		{"a raw s3 mount", owner, &models.CreateSandboxRequest{Mounts: []models.MountSpec{{Type: models.MountTypeS3, Source: "s3://some-bucket", Target: "/x"}}}, "mounts"},
		{"a raw s3 bucket root", owner, &models.CreateSandboxRequest{Mounts: []models.MountSpec{{Type: models.MountTypeS3, Source: "some-bucket", Target: "/x"}}}, "mounts"},
		{"an sshfs mount", owner, &models.CreateSandboxRequest{Mounts: []models.MountSpec{{Type: "sshfs", Source: "h:/" + volumes.TenantForOwnerRef(owner) + "/data", Target: "/x"}}}, "mounts"},
		{"a source that is not clean", owner, &models.CreateSandboxRequest{Mounts: []models.MountSpec{{Type: models.MountTypeS3, Source: "b/../" + volumes.TenantForOwnerRef(owner) + "/data", Target: "/x"}}}, "mounts"},
		{"unresolved platform volumes", owner, &models.CreateSandboxRequest{PlatformVolumes: []models.PlatformVolumeMount{{Name: "data", Path: "/d"}}}, "platform_volumes"},
		{"a wasm module from a file", owner, &models.CreateSandboxRequest{Runtime: models.RuntimeWasm, ModuleRef: "file:///opt/m.wasm"}, "module_ref"},
		{"a wasm module at an absolute path", owner, &models.CreateSandboxRequest{Runtime: models.RuntimeWasm, ModuleRef: "/etc/m.wasm"}, "module_ref"},
		{"a wasm module at a relative path", owner, &models.CreateSandboxRequest{Runtime: models.RuntimeWasm, ModuleRef: "sub/m.wasm"}, "module_ref"},
		{"a wasm module from a registry", owner, &models.CreateSandboxRequest{Runtime: models.RuntimeWasm, ModuleRef: "oci://r.example/m:1"}, ""},
		{"a wasm keyword", owner, &models.CreateSandboxRequest{Runtime: models.RuntimeWasm, ModuleRef: "python"}, ""},
		{"a js bundle from a file", owner, &models.CreateSandboxRequest{Runtime: models.RuntimeIsolate, ModuleRef: "file:///srv/w.js"}, "module_ref"},
		{"a js bundle by digest", owner, &models.CreateSandboxRequest{Runtime: models.RuntimeIsolate, ModuleRef: "sha256:abc"}, ""},
	} {
		got := strings.Join(HostOnlySettings(Placement{OwnerRef: tc.owner, Spec: tc.spec}), ",")
		if got != tc.want {
			t.Errorf("%s: %q, want %q", tc.name, got, tc.want)
		}
	}
	if err := hostOnlyRefusal(Placement{Spec: &models.CreateSandboxRequest{Image: "alpine"}}); err != nil {
		t.Fatalf("no host-only settings: %v", err)
	}
	if err := hostOnlyRefusal(Placement{Spec: &models.CreateSandboxRequest{Mounts: []models.MountSpec{{Type: models.MountTypeS3, Source: "s3://b", Target: "/x"}}}}); !errors.Is(err, ErrHostOnlySpec) || !strings.Contains(err.Error(), "mounts") {
		t.Fatalf("refusal = %v", err)
	}
}

// A worker places a sandbox on itself with a raw mount and failover on,
// then asks the leader to move it as stuck: the leader does not move it,
// because no other node would rebuild it. A sandbox whose mounts are its
// owner's platform volumes still moves.
func TestStuckReassignKeepsHostOnlySandbox(t *testing.T) {
	c, cleanup := newTestClusterWithRole(t, "srv-hr", config.NodeRoleServer, true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)
	seedGossipView(t, c, []Member{
		recreateCandidate("wkr-9", config.NodeRoleWorker, 100),
		recreateCandidate("wkr-other", config.NodeRoleWorker, 10),
	})
	place := func(id string, mount models.MountSpec) string {
		inc, _ := MintIncarnationID()
		raw, _ := encodeCommand(command{Op: opPlace, SandboxID: id, OwnerNodeID: "wkr-9",
			OwnerAPIURL: "http://wkr-9", IncarnationID: inc, OwnerRef: "team:payments",
			Spec: &models.CreateSandboxRequest{
				Image:    "alpine",
				Failover: &models.Failover{Policy: models.FailoverPolicyRecreate},
				Mounts:   []models.MountSpec{mount},
			}})
		if err := c.ApplyEncoded(workerApplyCtx("wkr-9"), raw); err != nil {
			t.Fatalf("worker's own placement %s: %v", id, err)
		}
		return inc
	}
	inc := place("sb-host", models.MountSpec{Type: models.MountTypeS3, Source: "s3://host-role-bucket", Target: "/data"})
	if err := c.ReassignStuckPlacement(context.Background(), "wkr-9", "sb-host", inc, false); !errors.Is(err, ErrNoReassignTarget) {
		t.Fatalf("reassign of a host-only sandbox = %v, want ErrNoReassignTarget", err)
	}
	if p, ok := c.fsm.get("sb-host"); !ok || p.OwnerNodeID != "wkr-9" {
		t.Fatalf("host-only sandbox moved: %+v", p)
	}

	inc = place("sb-vol", platformMount("team:payments", "data"))
	if err := c.ReassignStuckPlacement(context.Background(), "wkr-9", "sb-vol", inc, false); err != nil {
		t.Fatalf("reassign of a platform-volume sandbox: %v", err)
	}
	if p, ok := c.fsm.get("sb-vol"); !ok || p.OwnerNodeID != "wkr-other" {
		t.Fatalf("platform-volume sandbox not moved: %+v", p)
	}
}

// A dead owner's host-only sandbox is orphaned, not handed to another
// node, and the refusal is counted; its platform-volume neighbour moves.
func TestDeadOwnerOrphansHostOnlySandbox(t *testing.T) {
	c, cleanup := newTestCluster(t, "ldr-hr-dead", true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)
	seedGossipView(t, c, []Member{recreateCandidate("wkr-b", config.NodeRoleWorker, 100)})
	for id, mount := range map[string]models.MountSpec{
		"sb-host": {Type: models.MountTypeS3, Source: "s3://host-role-bucket", Target: "/data"},
		"sb-vol":  platformMount("team:payments", "data"),
	} {
		raw, _ := encodeCommand(command{Op: opPlace, SandboxID: id, OwnerNodeID: "wkr-dead", IncarnationID: "inc-" + id,
			OwnerRef: "team:payments", Spec: &models.CreateSandboxRequest{Image: "alpine",
				Failover: &models.Failover{Policy: models.FailoverPolicyRecreate}, Mounts: []models.MountSpec{mount}}})
		if err := c.raft.raft.Apply(raw, 2*time.Second).Error(); err != nil {
			t.Fatal(err)
		}
	}
	before := clusterFailoverRefused.Get(FailoverRefusalReasonHostOnly)
	reassigned, orphaned, err := c.evictOwnerPlacements(context.Background(), "wkr-dead")
	if err != nil || reassigned != 1 || orphaned != 1 {
		t.Fatalf("evict = %d reassigned, %d orphaned, %v", reassigned, orphaned, err)
	}
	if p, _ := c.fsm.get("sb-host"); !p.IsOrphaned() || p.OrphanedOwnerNodeID != "wkr-dead" {
		t.Fatalf("host-only sandbox = %+v, want orphaned from wkr-dead", p)
	}
	if p, _ := c.fsm.get("sb-vol"); p.OwnerNodeID != "wkr-b" {
		t.Fatalf("platform-volume sandbox = %+v, want moved to wkr-b", p)
	}
	if after := clusterFailoverRefused.Get(FailoverRefusalReasonHostOnly); after == nil || before != nil && after.String() == before.String() {
		t.Fatalf("refusal not counted: %v -> %v", before, after)
	}
	// Nor is the orphan moved later.
	if moved, _ := c.retryOrphan(context.Background(), "sb-host", time.Now().Add(time.Hour)); moved {
		t.Fatal("orphan retry moved the host-only sandbox")
	}
}

// A decommission refuses a host-only sandbox up front, by name, and does
// not release it.
func TestEvacuateNodeRefusesHostOnlySandbox(t *testing.T) {
	c, cleanup := newTestClusterWithCfg(t, "ldr-hr-ev", true, nil, func(cfg *config.Config) {
		cfg.NodeRole = config.NodeRoleMixed
	})
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)
	moves := &fakeMoves{}
	c.AttachMoveHandler(moves)
	self, _ := c.gossip.lookupMember(c.nodeID)
	self.Role = config.NodeRoleMixed
	seedGossipView(t, c, []Member{self, recreateCandidate("wkr-b", config.NodeRoleWorker, 100)})
	raw, _ := encodeCommand(command{Op: opPlace, SandboxID: "sb-host", OwnerNodeID: c.nodeID, IncarnationID: "inc-h",
		Spec: &models.CreateSandboxRequest{Image: "alpine", Failover: &models.Failover{Policy: models.FailoverPolicyRecreate},
			Mounts: []models.MountSpec{{Type: models.MountTypeNFS, Source: "files:/srv", Target: "/x"}}}})
	if err := c.raft.raft.Apply(raw, 2*time.Second).Error(); err != nil {
		t.Fatal(err)
	}
	applyDrain(t, c, c.nodeID)
	res, err := c.EvacuateNode(context.Background(), c.nodeID, EvacuateRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(res.Failed["sb-host"], "not moved: ") || len(res.Moved) != 0 || res.RemainingMovable != 0 || res.Remaining != 1 {
		t.Fatalf("pass = %+v", res)
	}
	if len(moves.released) != 0 {
		t.Fatalf("released %v", moves.released)
	}
}

// rebuildRefusalRecorder records the refusal side of a recreator and the run
// states a refused rebuild reports.
type rebuildRefusalRecorder struct {
	*recordingRecreator
	rmu      sync.Mutex
	refusals []FailoverRefusal
	reports  []RunStateReport
}

func (r *rebuildRefusalRecorder) RecordFailoverRefused(f FailoverRefusal) {
	r.rmu.Lock()
	defer r.rmu.Unlock()
	r.refusals = append(r.refusals, f)
}

func (r *rebuildRefusalRecorder) SetRunStates(_ context.Context, reports []RunStateReport) (int, error) {
	r.rmu.Lock()
	defer r.rmu.Unlock()
	r.reports = append(r.reports, reports...)
	return len(reports), nil
}

// A node that refuses to rebuild a host-only sandbox is never asked again,
// never moves it on, and reports the refusal once: the run state shows it
// failed, with the reason, and it is audited.
func TestOwnerWatcherStopsAtHostOnlyRefusal(t *testing.T) {
	rec := &rebuildRefusalRecorder{recordingRecreator: newRecordingRecreator()}
	refusal := errors.New("mounts")
	rec.setOutcome(true, errors.Join(ErrHostOnlySpec, refusal))
	escalated := 0
	failures := &recreateFailureTracker{counts: map[string]int{}, permanent: map[string]struct{}{}}
	deps := ownerRecreateDeps{
		recreator: rec,
		failures:  failures,
		escalate:  func(context.Context, string, Placement, error) { escalated++ },
		refused:   rebuildRefusalReport{selfNodeID: "wkr-b", recreator: rec, runStates: rec}.report,
	}
	p := Placement{SandboxID: "sb-host", OwnerNodeID: "wkr-b", IncarnationID: "inc-1", OwnerRef: "team:payments",
		Spec: &models.CreateSandboxRequest{Image: "alpine", Failover: &models.Failover{Policy: models.FailoverPolicyRecreate}}}
	for i := 0; i < maxRecreateFailuresBeforeReassign+2; i++ {
		recreateOwnedPlacement(context.Background(), deps, "sb-host", p)
	}
	if !failures.isPermanent("sb-host") || escalated != 0 {
		t.Fatalf("permanent=%v escalated=%d", failures.isPermanent("sb-host"), escalated)
	}
	if len(rec.calls) != 1 {
		t.Fatalf("rebuild attempted %d times", len(rec.calls))
	}
	if len(rec.reports) != 1 || rec.reports[0].State != RunStateFailed || rec.reports[0].IncarnationID != "inc-1" ||
		rec.reports[0].OwnerNodeID != "wkr-b" || !strings.Contains(rec.reports[0].Reason, "host-only") {
		t.Fatalf("run states %+v", rec.reports)
	}
	if len(rec.refusals) != 1 || rec.refusals[0].Reason != FailoverRefusalReasonHostOnly || rec.refusals[0].OwnerRef != "team:payments" {
		t.Fatalf("refusals %+v", rec.refusals)
	}
}
