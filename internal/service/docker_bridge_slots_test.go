package service

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/models"
)

// Regression for the 2026-11-02 single-node-fc density run (m5zn.metal,
// docker engine): 1,023 docker sandboxes started, then creates failed with
// dockerd's "failed to set up container networking" because the sandbox
// bridge was full, and none was refused for capacity.

func dockerBridgeLimit(total int) capacity.SlotLimit {
	return capacity.SlotLimit{Name: capacity.SlotPoolDockerBridge, Pool: capacity.DockerBridgePool, Runtimes: []string{models.RuntimeDocker, models.RuntimeGvisor}, Total: total}
}

// exfullStartErr is what pkg/docker returns when dockerd cannot attach one
// more veth to the bridge (the driver has already removed the container).
var exfullStartErr = errors.New(`start container: docker API POST /containers/c1/start failed with status 500: {"message":"failed to set up container networking: adding interface veth5f0e1a2 to bridge docker0 failed: exchange full"}`)

func smallCreate(name string) models.CreateSandboxRequest {
	return models.CreateSandboxRequest{Image: "alpine", Name: name, CPU: 0.25, MemoryMB: 128}
}

// The pool fills, the next create is refused before the runtime is called,
// /v1/capacity (and so the cluster heartbeat) says the bridge is full, and a
// destroy gives the slot back.
func TestCreateSandboxOnAFullDockerBridgeIsACleanCapacityRefusal(t *testing.T) {
	ctx := context.Background()
	rt := &recordingRuntime{}
	svc, st, admitter := newServiceRuntimeHarnessAtPath(t, filepath.Join(t.TempDir(), "state.db"), rt)
	admitter.SetSlotLimit(dockerBridgeLimit(2))

	var ids []string
	for i := 0; i < 2; i++ {
		resp, err := svc.CreateSandbox(ctx, smallCreate(fmt.Sprintf("sb-%d", i)))
		if err != nil {
			t.Fatalf("create %d: %v", i, err)
		}
		ids = append(ids, resp.Sandbox.ID)
	}
	_, err := svc.CreateSandbox(ctx, smallCreate("sb-over"))
	if pool, ok := capacity.SlotPoolExhausted(err); !ok || pool != capacity.DockerBridgePool || !errors.Is(err, capacity.ErrCapacityExceeded) {
		t.Fatalf("create on a full bridge = %v, want the docker bridge pool's capacity refusal", err)
	}
	if rt.createCalls != 2 {
		t.Fatalf("runtime create called %d times, want 2 (the refusal comes before dockerd)", rt.createCalls)
	}
	rows, err := st.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("%d rows after the refusal, want 2", len(rows))
	}
	pools := svc.Capacity().SlotPools
	if len(pools) != 1 || pools[0].Name != capacity.SlotPoolDockerBridge || pools[0].Total != 2 || pools[0].Free != 0 {
		t.Fatalf("capacity report slot_pools = %+v, want docker_bridge 0 of 2 free", pools)
	}

	if err := svc.DestroySandbox(ctx, ids[0]); err != nil {
		t.Fatalf("destroy: %v", err)
	}
	if _, err := svc.CreateSandbox(ctx, smallCreate("sb-after-destroy")); err != nil {
		t.Fatalf("create after a destroy freed a slot: %v", err)
	}
}

// Stop releases the slot (dockerd tears the veth down) and start takes one
// again, through the same admission.
func TestStopAndStartMoveTheDockerBridgeSlot(t *testing.T) {
	ctx := context.Background()
	rt := &recordingRuntime{}
	svc, _, admitter := newServiceRuntimeHarnessAtPath(t, filepath.Join(t.TempDir(), "state.db"), rt)
	admitter.SetSlotLimit(dockerBridgeLimit(1))
	resp, err := svc.CreateSandbox(ctx, smallCreate("sb-a"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.StopSandbox(ctx, resp.Sandbox.ID); err != nil {
		t.Fatalf("stop: %v", err)
	}
	other, err := svc.CreateSandbox(ctx, smallCreate("sb-b"))
	if err != nil {
		t.Fatalf("create while the first is stopped: %v", err)
	}
	if _, err := svc.StartSandbox(ctx, resp.Sandbox.ID); !errors.Is(err, capacity.ErrCapacityExceeded) {
		t.Fatalf("start on a full bridge = %v, want a capacity refusal", err)
	}
	if err := svc.DestroySandbox(ctx, other.Sandbox.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.StartSandbox(ctx, resp.Sandbox.ID); err != nil {
		t.Fatalf("start after a slot came back: %v", err)
	}
}

// Defence in depth: a start that dockerd refuses because the bridge (or the
// subnet) is full — something without a reservation took the last port —
// is a capacity refusal, gives its admission back and leaves no row; the
// driver already removed the half-created container. Any other start
// failure is unchanged.
func TestCreateSandboxNetworkExhaustionIsACapacityRefusal(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name     string
		engine   string
		err      error
		wantPool string
	}{
		{"docker bridge full", models.ContainerEngineDocker, exfullStartErr, capacity.DockerBridgePool},
		{"docker ipam full", "", errors.New("start container: docker API POST /containers/c1/start failed with status 500: no available IPv4 addresses on this network's address pools: bridge (8c1f)"), capacity.DockerBridgePool},
		{"containerd bridge full", models.ContainerEngineContainerd, errors.New(`provision netns: cni add: failed to connect "veth9" to bridge aerolvm0: exchange full`), "container netns pool"},
		{"other failure", models.ContainerEngineDocker, errors.New("start container: OCI runtime create failed"), ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rt := &recordingRuntime{createErr: tc.err}
			svc, st, admitter := newServiceRuntimeHarnessAtPath(t, filepath.Join(t.TempDir(), "state.db"), rt)
			svc.cfg.ContainerEngine = tc.engine
			if tc.engine == models.ContainerEngineContainerd {
				svc.containerd = rt
			}
			_, err := svc.CreateSandbox(ctx, smallCreate("sb-x"))
			if !errors.Is(err, tc.err) {
				t.Fatalf("create = %v, want it to keep the runtime's error", err)
			}
			pool, ok := capacity.SlotPoolExhausted(err)
			if tc.wantPool == "" {
				if ok || errors.Is(err, capacity.ErrCapacityExceeded) {
					t.Fatalf("a non-network failure became a capacity refusal: %v", err)
				}
			} else if !ok || pool != tc.wantPool || !errors.Is(err, capacity.ErrCapacityExceeded) {
				t.Fatalf("create = %v (pool %q), want the %s capacity refusal", err, pool, tc.wantPool)
			}
			if got := admitter.Snapshot().SandboxesActive; got != 0 {
				t.Fatalf("admitter still holds %d reservations", got)
			}
			if rows, _ := st.List(ctx); len(rows) != 0 {
				t.Fatalf("failed create left %d rows", len(rows))
			}
		})
	}
}

// A start that the full bridge refuses leaves the sandbox stopped (a retry
// can start it), not in error, and gives the admission back.
func TestStartSandboxOnAFullBridgeStaysStopped(t *testing.T) {
	ctx := context.Background()
	rt := &recordingRuntime{}
	svc, st, admitter := newServiceRuntimeHarnessAtPath(t, filepath.Join(t.TempDir(), "state.db"), rt)
	resp, err := svc.CreateSandbox(ctx, smallCreate("sb-a"))
	if err != nil {
		t.Fatal(err)
	}
	id := resp.Sandbox.ID
	if _, err := svc.StopSandbox(ctx, id); err != nil {
		t.Fatal(err)
	}
	rt.startErr = exfullStartErr
	_, err = svc.StartSandbox(ctx, id)
	if pool, ok := capacity.SlotPoolExhausted(err); !ok || pool != capacity.DockerBridgePool {
		t.Fatalf("start on a full bridge = %v, want the docker bridge pool's refusal", err)
	}
	got, err := st.Get(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != models.SandboxStatusStopped {
		t.Fatalf("status %s after a refused start, want stopped", got.Status)
	}
	if n := admitter.Snapshot().SandboxesActive; n != 0 {
		t.Fatalf("admitter holds %d after the refused start", n)
	}
	// Any other start failure still marks the sandbox error, as before.
	rt.startErr = errors.New("start container: OCI runtime create failed")
	if _, err := svc.StartSandbox(ctx, id); err == nil || errors.Is(err, capacity.ErrCapacityExceeded) {
		t.Fatalf("start = %v, want the plain runtime error", err)
	}
	if got, _ := st.Get(ctx, id); got.Status != models.SandboxStatusError {
		t.Fatalf("status %s after a runtime fault, want error", got.Status)
	}
}

// A daemon restart with the bridge full must not reset the count:
// ReplayReservations rebuilds it from the store (every row but stopped and
// destroyed ones, which hold no veth), so the first create after the
// restart is refused.
func TestReplayReservationsRefillsTheDockerBridgePool(t *testing.T) {
	ctx := context.Background()
	rt := &recordingRuntime{}
	svc, st, admitter := newServiceRuntimeHarnessAtPath(t, filepath.Join(t.TempDir(), "state.db"), rt)
	now := time.Now().UTC()
	add := func(id, runtime string, status models.SandboxStatus) {
		t.Helper()
		if err := st.Create(ctx, &models.Sandbox{ID: id, Image: "alpine", Status: status, Runtime: runtime, CPU: 0.25, MemoryMB: 128, CreatedAt: now, UpdatedAt: now}); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 3; i++ {
		add(fmt.Sprintf("sb-run-%d", i), models.RuntimeDocker, models.SandboxStatusStarted)
	}
	add("sb-gv", models.RuntimeGvisor, models.SandboxStatusStarted)
	add("sb-creating", models.RuntimeDocker, models.SandboxStatusCreating)
	add("sb-stopped", models.RuntimeDocker, models.SandboxStatusStopped)
	add("sb-fc", models.RuntimeFirecracker, models.SandboxStatusStarted)

	admitter.SetSlotLimit(dockerBridgeLimit(5))
	svc.ReplayReservations(ctx)
	if p, ok := admitter.SlotPool(); !ok || p.Free != 0 {
		t.Fatalf("after replay pool = %+v, want 5 of 5 held (3 runc + 1 gVisor + 1 creating)", p)
	}
	if _, err := svc.CreateSandbox(ctx, smallCreate("sb-new")); !errors.Is(err, capacity.ErrCapacityExceeded) {
		t.Fatalf("first create after the restart = %v, want a capacity refusal", err)
	}
}

func TestLocalSlotPoolsReportsTheDockerBridge(t *testing.T) {
	svc, _ := newSlotPoolService(t, config.Config{ContainerEngine: models.ContainerEngineDocker})
	svc.admitter = capacity.New(capacity.HostInfo{CPUCores: 8, MemoryTotalMB: 16384}, capacity.Limits{}, nil)
	if got := svc.LocalSlotPools(context.Background()); len(got) != 0 {
		t.Fatalf("no limit set: pools = %+v", got)
	}
	expireSlotPoolCache(svc)
	svc.admitter.SetSlotLimit(dockerBridgeLimit(1000))
	svc.admitter.Reserve("sb-1", capacity.Request{CPU: 0.25, MemoryMB: 128, Runtime: models.RuntimeGvisor})
	got := svc.LocalSlotPools(context.Background())
	if len(got) != 1 || got[0].Name != capacity.SlotPoolDockerBridge || got[0].Total != 1000 || got[0].Free != 999 || !got[0].Serves(models.RuntimeDocker) || !got[0].Serves(models.RuntimeGvisor) {
		t.Fatalf("pools = %+v, want docker_bridge 999 of 1000 free for docker and gvisor", got)
	}
}

// The containerd netns pool is one veth per slot on aerolvm0, so a pool
// seeded past the bridge's 1,023 ports advertises only what the bridge can
// still take.
func TestContainerNetnsSlotPoolIsHeldToTheBridge(t *testing.T) {
	cases := []struct {
		name      string
		stats     store.ContainerNetnsPoolStats
		wantTotal int
		wantFree  int
	}{
		{"default size", store.ContainerNetnsPoolStats{Total: 256, Free: 200, Pooled: 4}, 256, 204},
		{"at the bridge limit", store.ContainerNetnsPoolStats{Total: 1023, Free: 1, Pooled: 2}, 1023, 3},
		{"past the limit, bridge has room", store.ContainerNetnsPoolStats{Total: 2000, Free: 1500, Pooled: 4}, 1023, 4 + 523},
		{"past the limit, bridge full", store.ContainerNetnsPoolStats{Total: 2000, Free: 977, Pooled: 4}, 1023, 4},
		{"past the limit, more held than the bridge", store.ContainerNetnsPoolStats{Total: 2000, Free: 900}, 1023, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := containerNetnsSlotPool(tc.stats)
			if p.Total != tc.wantTotal || p.Free != tc.wantFree || p.Name != capacity.SlotPoolContainerNetns {
				t.Fatalf("pool = %+v, want %d of %d free", p, tc.wantFree, tc.wantTotal)
			}
		})
	}
}
