package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/pkg/models"
)

// The orphan-runtime sweep is the only retry anchor for a stale-ownership
// teardown: finalizeStaleLocalSandbox deletes the row before runtime Destroy
// on purpose (so the resulting engine event cannot enter the lifecycle-wide
// finalizer), and relies on the sweep to finish the job if Destroy fails.
// containerd is the default engine on clusters, so a containerd instance the
// sweep never visits stays resident forever after one transient failure.
func TestReconcileSweepsOrphanContainerdInstances(t *testing.T) {
	ctx := context.Background()
	dockerRT := &recordingRuntime{}
	ctrdRT := &recordingRuntime{managed: map[string]*models.SandboxRuntimeState{
		"sb-ctrd-orphan": {SandboxID: "sb-ctrd-orphan", ContainerID: "ctr-orphan", ContainerIP: "10.0.0.9", Status: models.SandboxStatusStarted},
		"park-warm-1":    {SandboxID: "park-warm-1", ContainerID: "ctr-park", Status: models.SandboxStatusStarted},
	}}
	svc, _, _ := newServiceRuntimeHarness(t, dockerRT)
	svc.SetContainerdRuntime(ctrdRT)

	if err := svc.Reconcile(ctx); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if len(ctrdRT.destroyIDs) != 1 || ctrdRT.destroyIDs[0] != "sb-ctrd-orphan" {
		t.Fatalf("containerd orphan destroys = %v, want [sb-ctrd-orphan] (warm-pool park-* must be spared)", ctrdRT.destroyIDs)
	}
	if len(dockerRT.destroyIDs) != 0 {
		t.Fatalf("docker driver was asked to destroy a containerd instance: %v", dockerRT.destroyIDs)
	}
}

// End-to-end shape of the reported defect: a containerd sandbox whose
// ownership moved to another node fails its first Destroy; the row is already
// gone, so only the next reconcile's orphan sweep can retry.
func TestStaleContainerdTeardownIsRetriedByOrphanSweep(t *testing.T) {
	ctx := context.Background()
	dockerRT := &recordingRuntime{}
	const sandboxID = "sb-ctrd-stale"
	ctrdRT := &recordingRuntime{
		destroyErr: errors.New("containerd: transient task kill failure"),
		managed: map[string]*models.SandboxRuntimeState{
			sandboxID: {SandboxID: sandboxID, ContainerID: "ctr-" + sandboxID, ContainerIP: "10.0.0.5", Status: models.SandboxStatusStarted},
		},
	}
	svc, st, _ := newServiceRuntimeHarness(t, dockerRT)
	svc.SetContainerdRuntime(ctrdRT)
	svc.cfg.EnableCluster = true
	svc.AttachCluster(&stubStaleCluster{
		Noop: cluster.NewNoop("self", "http://self", ""), otherNode: "node-b", otherURL: "http://node-b",
	})
	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID: sandboxID, Image: "alpine", Status: models.SandboxStatusStarted,
		Runtime: models.RuntimeDocker, Engine: models.ContainerEngineContainerd, ContainerID: "ctr-" + sandboxID,
		AuditIncarnationID: "inc-" + sandboxID, CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	svc.reconcileStaleOwnership(ctx)
	if _, err := st.Get(ctx, sandboxID); err == nil {
		t.Fatal("stale row survived teardown; the sweep would never be needed")
	}
	if len(ctrdRT.destroyIDs) != 1 {
		t.Fatalf("first teardown destroys = %v, want one failed attempt", ctrdRT.destroyIDs)
	}

	// The transient failure clears; the instance is still resident and has no row.
	ctrdRT.destroyErr = nil
	if err := svc.Reconcile(ctx); err != nil {
		t.Fatalf("Reconcile after failed stale teardown: %v", err)
	}
	if len(ctrdRT.destroyIDs) != 2 || ctrdRT.destroyIDs[1] != sandboxID {
		t.Fatalf("orphan sweep did not retry the containerd destroy: %v", ctrdRT.destroyIDs)
	}
}
