package service

import (
	"context"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/runtime"
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
