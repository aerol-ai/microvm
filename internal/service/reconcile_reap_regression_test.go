package service

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/caddy"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts"
)

// Regression tests for UC-320 (bank fork-bomb test, cluster-3-mixed-gvisor):
// reconcile deleted a healthy gVisor sandbox whose runtime could not be read
// for a moment, and the crashed bomb sandbox whose row should have stayed
// stopped. Reconcile's reap deletes the row, its host ports and its cluster
// placement, so it must run only when the runtime says the sandbox does not
// exist.

// reapProbeCluster is a one-node cluster that owns every seeded sandbox and
// records placement deletes, so a test can tell a reap from a kept sandbox.
type reapProbeCluster struct {
	*cb96Cluster
	placementDeletes []string
}

func (c *reapProbeCluster) BeginDeletePlacementExact(_ context.Context, id, _, _ string) error {
	c.placementDeletes = append(c.placementDeletes, "begin:"+id)
	return nil
}

func (c *reapProbeCluster) DeletePlacementExact(_ context.Context, id, _, _ string) error {
	c.placementDeletes = append(c.placementDeletes, "delete:"+id)
	return nil
}

type reapHarness struct {
	svc      *Service
	st       *store.Store
	admitter *capacity.Admitter
	cluster  *reapProbeCluster
	docker   *fakeReconcileRuntime
}

func newReapHarness(t *testing.T) *reapHarness {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	mgr, err := mounts.New(slog.New(slog.NewTextHandler(io.Discard, nil)), mounts.Config{
		RootDir:     filepath.Join(t.TempDir(), "mounts"),
		CredDir:     filepath.Join(t.TempDir(), "cred"),
		WaitTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("mounts.New: %v", err)
	}
	t.Cleanup(mgr.Close)
	h := &reapHarness{
		st: st,
		admitter: capacity.New(
			capacity.HostInfo{CPUCores: 8, MemoryTotalMB: 16384},
			capacity.Limits{CPUReservationRatio: 1, MemoryReservationRatio: 1},
			nil,
		),
		cluster: &reapProbeCluster{cb96Cluster: &cb96Cluster{
			Noop:       cluster.NewNoop("self", "http://self", ""),
			placements: map[string]cluster.Placement{},
		}},
		docker: &fakeReconcileRuntime{managed: map[string]*models.SandboxRuntimeState{}},
	}
	h.svc = &Service{
		cfg:      config.Config{EnableCluster: true, ImageBuildGCEnabled: true},
		logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		store:    st,
		docker:   h.docker,
		caddy:    caddy.New(config.Config{EnableCaddy: false, HTTPClientTimeout: time.Second}),
		mounts:   mgr,
		admitter: h.admitter,
	}
	h.svc.AttachCluster(h.cluster)
	return h
}

// seed stores a started sandbox this node owns, with a TCP host port and a
// capacity reservation: the three things a reap releases.
func (h *reapHarness) seed(t *testing.T, sb *models.Sandbox, hostPort int) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()
	sb.Image = "ubuntu:22.04"
	sb.CPU, sb.MemoryMB = 1, 512
	sb.AuditIncarnationID = "inc-" + sb.ID
	sb.CreatedAt, sb.UpdatedAt, sb.LastActiveAt = now, now, now
	if err := h.st.Create(ctx, sb); err != nil {
		t.Fatalf("seed %s: %v", sb.ID, err)
	}
	if hostPort > 0 {
		res, err := h.st.TryReserveHostPort(ctx, sb.ID, 5432, hostPort, models.ExposedPortProtocolTCP, "", now)
		if err != nil || !res.Reserved {
			t.Fatalf("seed host port %d: res=%+v err=%v", hostPort, res, err)
		}
	}
	h.admitter.Reserve(sb.ID, capacity.Request{CPU: 1, MemoryMB: 512})
	h.cluster.placements[sb.ID] = cluster.Placement{SandboxID: sb.ID, OwnerNodeID: "self", IncarnationID: sb.AuditIncarnationID}
}

// hostPortHeld reports whether some sandbox still holds hostPort.
func (h *reapHarness) hostPortHeld(t *testing.T, hostPort int) bool {
	t.Helper()
	p, err := h.st.GetPortByHostPort(context.Background(), hostPort)
	if errors.Is(err, store.ErrNotFound) {
		return false
	}
	if err != nil {
		t.Fatalf("look up host port %d: %v", hostPort, err)
	}
	return p != nil
}

// Case (a): the runtime could not answer. Before: the row, its host port, its
// capacity reservation and its cluster placement were deleted. Now nothing is.
func TestReconcileKeepsSandboxWhenRuntimeCannotAnswer(t *testing.T) {
	cases := []struct {
		name    string
		sandbox models.Sandbox
		wire    func(*reapHarness, *fakeReconcileRuntime)
	}{
		{
			name:    "docker daemon timed out",
			sandbox: models.Sandbox{Runtime: models.RuntimeDocker},
			wire:    func(h *reapHarness, rt *fakeReconcileRuntime) { h.svc.docker = rt },
		},
		{
			name:    "containerd unreachable",
			sandbox: models.Sandbox{Runtime: models.RuntimeDocker, Engine: models.ContainerEngineContainerd},
			wire:    func(h *reapHarness, rt *fakeReconcileRuntime) { h.svc.containerd = rt },
		},
		{
			// The UC-320 neighbour: gVisor sandbox, task status unreadable.
			name:    "gvisor task status unreadable",
			sandbox: models.Sandbox{Runtime: models.RuntimeGvisor, Engine: models.ContainerEngineContainerd},
			wire:    func(h *reapHarness, rt *fakeReconcileRuntime) { h.svc.containerd = rt },
		},
		{
			// The reap destroys a firecracker VM; the fake panics on Destroy.
			name:    "firecracker API socket blipped",
			sandbox: models.Sandbox{Runtime: models.RuntimeFirecracker},
			wire:    func(h *reapHarness, rt *fakeReconcileRuntime) { h.svc.firecracker = rt },
		},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			h := newReapHarness(t)
			rt := &fakeReconcileRuntime{
				managed:    map[string]*models.SandboxRuntimeState{},
				inspectErr: errors.New("context deadline exceeded"),
			}
			tc.wire(h, rt)
			sb := tc.sandbox
			sb.ID = "sb-unanswered"
			sb.Status = models.SandboxStatusStarted
			sb.ContainerID = "ctr-unanswered"
			sb.ContainerIP = "10.88.0.30"
			hostPort := 22600 + i
			h.seed(t, &sb, hostPort)

			for pass := 1; pass <= 2; pass++ {
				if err := h.svc.Reconcile(ctx); err != nil {
					t.Fatalf("Reconcile pass %d: %v", pass, err)
				}
			}

			if len(rt.inspectRefs) == 0 {
				t.Fatal("reconcile never asked the runtime about the missing sandbox")
			}
			got, err := h.st.Get(ctx, sb.ID)
			if err != nil {
				t.Fatalf("row deleted although the runtime never said the sandbox was gone: %v", err)
			}
			if got.Status != models.SandboxStatusStarted || got.ContainerIP != "10.88.0.30" {
				t.Fatalf("row changed on an unknown answer: status=%q ip=%q", got.Status, got.ContainerIP)
			}
			if !h.hostPortHeld(t, hostPort) {
				t.Fatalf("host port %d freed for a sandbox that may be running", hostPort)
			}
			if snap := h.admitter.Snapshot(); snap.SandboxesActive != 1 {
				t.Fatalf("capacity reservation released: %+v", snap)
			}
			if len(h.cluster.placementDeletes) != 0 {
				t.Fatalf("cluster placement deleted: %v", h.cluster.placementDeletes)
			}
		})
	}
}

// Case (b): a definitive not-found still reaps, so `docker rm` / `ctr rm`
// behind sandboxd's back is still cleaned up on the next pass.
func TestReconcileReapsOnDefinitiveNotFound(t *testing.T) {
	cases := []struct {
		name        string
		sandbox     models.Sandbox
		rt          *fakeReconcileRuntime
		wire        func(*reapHarness, *fakeReconcileRuntime)
		wantRef     string
		wantDestroy bool
	}{
		{
			name:    "docker rm (404)",
			sandbox: models.Sandbox{Runtime: models.RuntimeDocker, ContainerID: "ctr-removed"},
			rt:      &fakeReconcileRuntime{},
			wire:    func(h *reapHarness, rt *fakeReconcileRuntime) { h.svc.docker = rt },
			wantRef: "ctr-removed",
		},
		{
			name:    "ctr rm (NotFound)",
			sandbox: models.Sandbox{Runtime: models.RuntimeGvisor, Engine: models.ContainerEngineContainerd, ContainerID: "ctr-removed"},
			rt:      &fakeReconcileRuntime{},
			wire:    func(h *reapHarness, rt *fakeReconcileRuntime) { h.svc.containerd = rt },
			wantRef: "ctr-removed",
		},
		{
			// No container id recorded: the sandbox id is the container's
			// name, so its not-found is still definitive.
			name:    "row without a container id",
			sandbox: models.Sandbox{Runtime: models.RuntimeDocker},
			rt:      &fakeReconcileRuntime{},
			wire:    func(h *reapHarness, rt *fakeReconcileRuntime) { h.svc.docker = rt },
			wantRef: "sb-removed",
		},
		{
			// firecracker's registry miss is its not-found; the reap still
			// destroys the VM's host state.
			name:        "firecracker VM not in the driver's registry",
			sandbox:     models.Sandbox{Runtime: models.RuntimeFirecracker, ContainerID: "/run/fc/sb-removed.sock"},
			rt:          &fakeReconcileRuntime{registryMiss: true, allowDestroy: true},
			wire:        func(h *reapHarness, rt *fakeReconcileRuntime) { h.svc.firecracker = rt },
			wantRef:     "sb-removed",
			wantDestroy: true,
		},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			h := newReapHarness(t)
			tc.rt.managed = map[string]*models.SandboxRuntimeState{}
			tc.wire(h, tc.rt)
			sb := tc.sandbox
			sb.ID = "sb-removed"
			sb.Status = models.SandboxStatusStarted
			sb.ContainerIP = "10.88.0.31"
			hostPort := 22700 + i
			h.seed(t, &sb, hostPort)

			if err := h.svc.Reconcile(ctx); err != nil {
				t.Fatalf("Reconcile: %v", err)
			}

			if len(tc.rt.inspectRefs) != 1 || tc.rt.inspectRefs[0] != tc.wantRef {
				t.Fatalf("Inspect refs = %v, want [%s]", tc.rt.inspectRefs, tc.wantRef)
			}
			if _, err := h.st.Get(ctx, sb.ID); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("a sandbox the runtime says is gone must be reaped, got err=%v", err)
			}
			if h.hostPortHeld(t, hostPort) {
				t.Fatalf("host port %d still held after the reap", hostPort)
			}
			if snap := h.admitter.Snapshot(); snap.SandboxesActive != 0 {
				t.Fatalf("capacity reservation kept after the reap: %+v", snap)
			}
			if len(h.cluster.placementDeletes) != 2 {
				t.Fatalf("cluster placement deletes = %v, want begin+delete", h.cluster.placementDeletes)
			}
			if tc.wantDestroy != (len(tc.rt.destroyIDs) == 1) {
				t.Fatalf("runtime Destroy calls = %v, want destroy=%v", tc.rt.destroyIDs, tc.wantDestroy)
			}
		})
	}
}

// Case (d): the UC-320 bomb. Its gVisor task died (exit status unavailable),
// the die event stopped the row, and the container is still there. The row
// must stay, stopped, with the reason the die event recorded. A missed die
// event still ends stopped, not deleted.
func TestReconcileKeepsDeadTaskRowStopped(t *testing.T) {
	cases := []struct {
		name      string
		rowStatus models.SandboxStatus
		lastError string
	}{
		{name: "die event already stopped the row", rowStatus: models.SandboxStatusStopped, lastError: "container exited with code 128"},
		{name: "die event missed", rowStatus: models.SandboxStatusStarted},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			h := newReapHarness(t)
			const id = "sb-bomb"
			rt := &fakeReconcileRuntime{managed: map[string]*models.SandboxRuntimeState{
				// What the containerd driver now lists for a dead task.
				id: {SandboxID: id, ContainerID: id, Status: models.SandboxStatusStopped},
			}}
			h.svc.containerd = rt
			sb := models.Sandbox{
				ID: id, Runtime: models.RuntimeGvisor, Engine: models.ContainerEngineContainerd,
				Status: tc.rowStatus, ContainerID: id, ContainerIP: "10.88.0.32", LastError: tc.lastError,
			}
			hostPort := 22800 + i
			h.seed(t, &sb, hostPort)

			for pass := 1; pass <= 2; pass++ {
				if err := h.svc.Reconcile(ctx); err != nil {
					t.Fatalf("Reconcile pass %d: %v", pass, err)
				}
			}

			got, err := h.st.Get(ctx, id)
			if err != nil {
				t.Fatalf("a stopped sandbox whose container still exists was deleted: %v", err)
			}
			if got.Status != models.SandboxStatusStopped {
				t.Fatalf("status = %q, want stopped", got.Status)
			}
			if got.LastError != tc.lastError {
				t.Fatalf("last_error = %q, want the die event's %q", got.LastError, tc.lastError)
			}
			if !h.hostPortHeld(t, hostPort) {
				t.Fatalf("host port %d freed for a stopped sandbox that can be started again", hostPort)
			}
			if len(h.cluster.placementDeletes) != 0 {
				t.Fatalf("cluster placement deleted: %v", h.cluster.placementDeletes)
			}
		})
	}
}

// A started sandbox listed without an address has not moved; the runtime
// just did not say. Before, reconcile blanked the row's address, so routes,
// egress rules and the toolbox target lost it: containerd when its netns
// probe failed, firecracker on every pass (its listing never carries one).
func TestReconcileKeepsAddressWhenRuntimeOmitsIt(t *testing.T) {
	cases := []struct {
		name    string
		sandbox models.Sandbox
		listed  models.SandboxRuntimeState
		wire    func(*reapHarness, *fakeReconcileRuntime)
	}{
		{
			name:    "containerd netns probe failed",
			sandbox: models.Sandbox{Runtime: models.RuntimeGvisor, Engine: models.ContainerEngineContainerd, ContainerID: "sb-addr", NetworkBlockAll: true},
			listed:  models.SandboxRuntimeState{ContainerID: "sb-addr", Status: models.SandboxStatusStarted},
			wire:    func(h *reapHarness, rt *fakeReconcileRuntime) { h.svc.containerd = rt },
		},
		{
			name:    "firecracker listing carries no address or id",
			sandbox: models.Sandbox{Runtime: models.RuntimeFirecracker, ContainerID: "/run/fc/sb-addr.sock", NetworkBlockAll: true},
			listed:  models.SandboxRuntimeState{Status: models.SandboxStatusStarted},
			wire:    func(h *reapHarness, rt *fakeReconcileRuntime) { h.svc.firecracker = rt },
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			h := newReapHarness(t)
			const id = "sb-addr"
			listed := tc.listed
			listed.SandboxID = id
			rt := &fakeReconcileRuntime{
				managed:               map[string]*models.SandboxRuntimeState{id: &listed},
				allowPushAllowedPorts: true,
			}
			tc.wire(h, rt)
			sb := tc.sandbox
			sb.ID = id
			sb.Status = models.SandboxStatusStarted
			sb.ContainerIP = "10.88.0.33"
			wantContainerID := sb.ContainerID
			h.seed(t, &sb, 0)

			if err := h.svc.Reconcile(ctx); err != nil {
				t.Fatalf("Reconcile: %v", err)
			}

			got, err := h.st.Get(ctx, id)
			if err != nil {
				t.Fatalf("get: %v", err)
			}
			if got.ContainerIP != "10.88.0.33" || got.ContainerID != wantContainerID {
				t.Fatalf("row = ip %q id %q, want the kept ip 10.88.0.33 id %q", got.ContainerIP, got.ContainerID, wantContainerID)
			}
			if len(rt.networkBlockAllCalls) != 1 || rt.networkBlockAllCalls[0] != "10.88.0.33" {
				t.Fatalf("egress block reapplied at %v, want the sandbox's address [10.88.0.33]", rt.networkBlockAllCalls)
			}
		})
	}
}

// Isolate states carry no container id, and reconcile used to read an empty
// id as "gone": every live isolate sandbox was reaped on the first pass.
func TestReconcileSparesLiveIsolateSandbox(t *testing.T) {
	ctx := context.Background()
	h := newReapHarness(t)
	const id = "sb-isolate-live"
	h.svc.SetIsolateRuntime(&recordingRuntime{
		managed: map[string]*models.SandboxRuntimeState{
			id: {SandboxID: id, Status: models.SandboxStatusStarted, ContainerIP: "127.0.0.1"},
		},
		inspect: map[string]*models.SandboxRuntimeState{
			id: {SandboxID: id, Status: models.SandboxStatusStarted, ContainerIP: "127.0.0.1"},
		},
	})
	h.seed(t, &models.Sandbox{ID: id, Runtime: models.RuntimeIsolate, Status: models.SandboxStatusStarted, ContainerIP: "127.0.0.1"}, 0)

	if err := h.svc.Reconcile(ctx); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if _, err := h.st.Get(ctx, id); err != nil {
		t.Fatalf("live isolate sandbox reaped: %v", err)
	}
	if len(h.cluster.placementDeletes) != 0 {
		t.Fatalf("cluster placement deleted: %v", h.cluster.placementDeletes)
	}
}
