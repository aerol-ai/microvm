package service

import (
	"context"
	"errors"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
)

// Isolate was the one registered runtime the orphan sweep never visited:
// removeOrphans was called by hand per driver (docker, containerd,
// firecracker, wasm) and the isolate arm was simply absent. That matters more
// for isolate than for a container engine — a jailed workerd group owns a
// cgroup and a uid-owned chroot tree under SB_ISOLATE_JAIL_CHROOT_BASE, so a
// missed sweep strands host state, not just a PID.
//
// finalizeStaleLocalSandbox deletes the store row BEFORE runtime Destroy on
// purpose and names this sweep as its only retry anchor, so a single transient
// Destroy failure leaked the group permanently.
func TestReconcileSweepsOrphanIsolateInstances(t *testing.T) {
	ctx := context.Background()
	dockerRT := &recordingRuntime{}
	isolateRT := &recordingRuntime{managed: map[string]*models.SandboxRuntimeState{
		"sb-isolate-orphan": {SandboxID: "sb-isolate-orphan", ContainerID: "grp-orphan", Status: models.SandboxStatusStarted},
		// Warm blank hosts are intentional inventory with no sandbox row and
		// must survive the sweep, same as every other runtime's pool.
		"park-isolate-1": {SandboxID: "park-isolate-1", ContainerID: "grp-park", Status: models.SandboxStatusStarted},
	}}
	svc, _, _ := newServiceRuntimeHarness(t, dockerRT)
	svc.SetIsolateRuntime(isolateRT)

	if err := svc.Reconcile(ctx); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if len(isolateRT.destroyIDs) != 1 || isolateRT.destroyIDs[0] != "sb-isolate-orphan" {
		t.Fatalf("isolate orphan destroys = %v, want [sb-isolate-orphan] (warm-pool park-* must be spared)", isolateRT.destroyIDs)
	}
	if len(dockerRT.destroyIDs) != 0 {
		t.Fatalf("docker driver was asked to destroy an isolate group: %v", dockerRT.destroyIDs)
	}
}

// The sweep must retry a Destroy that failed once, which is the whole reason
// finalizeStaleLocalSandbox is allowed to drop the row first.
func TestIsolateDestroyFailureIsRetriedByOrphanSweep(t *testing.T) {
	ctx := context.Background()
	dockerRT := &recordingRuntime{}
	const sandboxID = "sb-isolate-stale"
	isolateRT := &recordingRuntime{
		destroyErr: errors.New("isolate: transient group teardown failure"),
		managed: map[string]*models.SandboxRuntimeState{
			sandboxID: {SandboxID: sandboxID, ContainerID: "grp-" + sandboxID, Status: models.SandboxStatusStarted},
		},
	}
	svc, _, _ := newServiceRuntimeHarness(t, dockerRT)
	svc.SetIsolateRuntime(isolateRT)

	if err := svc.Reconcile(ctx); err != nil {
		t.Fatalf("Reconcile (failing destroy): %v", err)
	}
	if len(isolateRT.destroyIDs) != 1 {
		t.Fatalf("first sweep destroys = %v, want one failed attempt", isolateRT.destroyIDs)
	}

	// A failed Destroy must not drop the instance from the sweep's view, or
	// the retry anchor is useless.
	isolateRT.destroyErr = nil
	if err := svc.Reconcile(ctx); err != nil {
		t.Fatalf("Reconcile (retry): %v", err)
	}
	if len(isolateRT.destroyIDs) != 2 || isolateRT.destroyIDs[1] != sandboxID {
		t.Fatalf("orphan sweep did not retry the isolate destroy: %v", isolateRT.destroyIDs)
	}
}

// A nil isolate driver is the default (SB_ENABLE_ISOLATE is off by default),
// so the new arm must not disturb reconcile where the runtime is absent.
func TestReconcileWithoutIsolateRuntimeIsUnchanged(t *testing.T) {
	ctx := context.Background()
	dockerRT := &recordingRuntime{managed: map[string]*models.SandboxRuntimeState{
		"sb-docker-orphan": {SandboxID: "sb-docker-orphan", ContainerID: "ctr-orphan", Status: models.SandboxStatusStarted},
	}}
	svc, _, _ := newServiceRuntimeHarness(t, dockerRT)

	if err := svc.Reconcile(ctx); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if len(dockerRT.destroyIDs) != 1 || dockerRT.destroyIDs[0] != "sb-docker-orphan" {
		t.Fatalf("docker orphan destroys = %v, want [sb-docker-orphan]", dockerRT.destroyIDs)
	}
}
