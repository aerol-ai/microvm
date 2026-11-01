package service

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/models"
)

// countingWasmRuntime is a WASM driver stand-in with the cheap live count.
type countingWasmRuntime struct {
	noContainerRuntime
	n int
}

func (r countingWasmRuntime) ManagedCount() int { return r.n }

func newSlotPoolService(t *testing.T, cfg config.Config) (*Service, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return &Service{cfg: cfg, store: st, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}, st
}

func expireSlotPoolCache(svc *Service) {
	svc.slotPools.mu.Lock()
	svc.slotPools.expires = time.Time{}
	svc.slotPools.mu.Unlock()
}

func TestLocalSlotPoolsReportsEachPool(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	cases := []struct {
		name  string
		cfg   config.Config
		wasm  countingWasmRuntime
		seed  func(t *testing.T, st *store.Store)
		want  []capacity.SlotPool
		wantN int
	}{
		{
			name: "containerd netns pool counts free and prewarmed rows",
			cfg:  config.Config{ContainerEngine: models.ContainerEngineContainerd, ContainerdNativeNetnsPoolEnabled: true},
			seed: func(t *testing.T, st *store.Store) {
				for _, id := range []string{"aerol-netns-0", "aerol-netns-1", "aerol-netns-2", "aerol-netns-3"} {
					if err := st.SeedContainerNetnsSlot(ctx, id, now); err != nil {
						t.Fatal(err)
					}
				}
				if _, err := st.ReserveContainerNetnsSlot(ctx, "sb-a", now); err != nil {
					t.Fatal(err)
				}
				slot, err := st.BeginPrewarmContainerNetnsSlot(ctx, now)
				if err != nil {
					t.Fatal(err)
				}
				if err := st.FinishPrewarmContainerNetnsSlot(ctx, slot.SlotID, "/run/netns/x", "10.88.0.9", now); err != nil {
					t.Fatal(err)
				}
			},
			want: []capacity.SlotPool{{Name: capacity.SlotPoolContainerNetns, Runtimes: []string{"docker", "gvisor"}, Total: 4, Free: 3}},
		},
		{
			name: "firecracker tap pool",
			cfg:  config.Config{EnableFirecracker: true},
			seed: func(t *testing.T, st *store.Store) {
				for i, name := range []string{"fctap0", "fctap1"} {
					if err := st.SeedFirecrackerTapSlot(ctx, store.FirecrackerTapSlot{TapName: name, CIDR: "172.16.0.0/30", HostIP: "172.16.0.1", GuestIP: "172.16.0.2", VsockCID: uint32(3 + i)}, now); err != nil {
						t.Fatal(err)
					}
				}
				if err := st.Create(ctx, &models.Sandbox{ID: "sb-fc", Image: "img", Status: models.SandboxStatusStarted, CreatedAt: now, UpdatedAt: now}); err != nil {
					t.Fatal(err)
				}
				if _, err := st.AllocateFirecrackerTapSlot(ctx, "sb-fc", now); err != nil {
					t.Fatal(err)
				}
			},
			want: []capacity.SlotPool{{Name: capacity.SlotPoolFirecrackerTap, Runtimes: []string{"firecracker"}, Total: 2, Free: 1}},
		},
		{
			name: "wasm instance cap",
			cfg:  config.Config{EnableWasm: true, WasmMaxInstances: 3},
			wasm: countingWasmRuntime{n: 2},
			want: []capacity.SlotPool{{Name: capacity.SlotPoolWasmInstances, Runtimes: []string{"wasm"}, Total: 3, Free: 1}},
		},
		{
			name: "wasm over its cap never reports negative room",
			cfg:  config.Config{EnableWasm: true, WasmMaxInstances: 3},
			wasm: countingWasmRuntime{n: 5},
			want: []capacity.SlotPool{{Name: capacity.SlotPoolWasmInstances, Runtimes: []string{"wasm"}, Total: 3, Free: 0}},
		},
		{
			name: "docker engine has no bounded pool",
			cfg:  config.Config{ContainerEngine: models.ContainerEngineDocker},
		},
		{
			name: "an unseeded pool is not advertised",
			cfg:  config.Config{ContainerEngine: models.ContainerEngineContainerd, ContainerdNativeNetnsPoolEnabled: true, EnableFirecracker: true},
		},
		{
			name: "an uncapped wasm host has no pool",
			cfg:  config.Config{EnableWasm: true},
			wasm: countingWasmRuntime{n: 2},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc, st := newSlotPoolService(t, tc.cfg)
			if tc.cfg.EnableWasm {
				svc.wasm = tc.wasm
			}
			if tc.seed != nil {
				tc.seed(t, st)
			}
			got := svc.LocalSlotPools(ctx)
			if len(got) != len(tc.want) {
				t.Fatalf("pools = %+v, want %+v", got, tc.want)
			}
			for i := range tc.want {
				g, w := got[i], tc.want[i]
				if g.Name != w.Name || g.Total != w.Total || g.Free != w.Free || len(g.Runtimes) != len(w.Runtimes) {
					t.Fatalf("pool[%d] = %+v, want %+v", i, g, w)
				}
				for j := range w.Runtimes {
					if g.Runtimes[j] != w.Runtimes[j] {
						t.Fatalf("pool[%d].Runtimes = %v, want %v", i, g.Runtimes, w.Runtimes)
					}
				}
			}
			// /v1/capacity and the cluster lease carry the same answer.
			if snap := svc.Capacity(); len(snap.SlotPools) != len(tc.want) {
				t.Fatalf("Capacity().SlotPools = %+v, want %+v", snap.SlotPools, tc.want)
			}
		})
	}
}

// The cache keeps the per-create self refresh off SQLite; an expired cache
// rereads, and a failed reread keeps advertising the last good reading.
func TestLocalSlotPoolsCachesAndSurvivesStoreErrors(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	svc, st := newSlotPoolService(t, config.Config{ContainerEngine: models.ContainerEngineContainerd, ContainerdNativeNetnsPoolEnabled: true})
	for _, id := range []string{"aerol-netns-0", "aerol-netns-1"} {
		if err := st.SeedContainerNetnsSlot(ctx, id, now); err != nil {
			t.Fatal(err)
		}
	}
	if got := svc.LocalSlotPools(ctx); len(got) != 1 || got[0].Free != 2 {
		t.Fatalf("first read = %+v, want 2 free", got)
	}
	if _, err := st.ReserveContainerNetnsSlot(ctx, "sb-a", now); err != nil {
		t.Fatal(err)
	}
	cached := svc.LocalSlotPools(ctx)
	if cached[0].Free != 2 {
		t.Fatalf("within the TTL the cached reading must be served, got %+v", cached)
	}
	// The caller's copy is its own.
	cached[0].Free = 99
	if again := svc.LocalSlotPools(ctx); again[0].Free != 2 {
		t.Fatalf("a caller's mutation reached the cache: %+v", again)
	}
	expireSlotPoolCache(svc)
	if got := svc.LocalSlotPools(ctx); got[0].Free != 1 {
		t.Fatalf("after expiry = %+v, want the new reading (1 free)", got)
	}
	expireSlotPoolCache(svc)
	_ = st.Close()
	if got := svc.LocalSlotPools(ctx); len(got) != 1 || got[0].Free != 1 {
		t.Fatalf("on a store error = %+v, want the last good reading", got)
	}
	if (*Service)(nil).LocalSlotPools(ctx) != nil {
		t.Fatal("nil service reports pools")
	}
}

func TestLocalSlotPoolsFirecrackerStoreError(t *testing.T) {
	svc, st := newSlotPoolService(t, config.Config{EnableFirecracker: true})
	_ = st.Close()
	if got := svc.LocalSlotPools(context.Background()); got != nil {
		t.Fatalf("no good reading yet: got %+v, want nil", got)
	}
}

// Single node: a create that finds its runtime's pool full returns the pool's
// capacity refusal as-is (the API answers 503 + Retry-After), gives its
// admission back and leaves no row, so the node is not left looking fuller
// than it is.
func TestCreateSandboxSlotExhaustionIsACleanCapacityRefusal(t *testing.T) {
	for name, poolErr := range map[string]error{
		"containerd netns": fmt.Errorf("provision netns: %w", store.ErrNoFreeContainerNetnsSlot),
		"firecracker tap":  fmt.Errorf("firecracker runtime: tap allocate: %w", store.ErrNoFreeFirecrackerTapSlot),
	} {
		t.Run(name, func(t *testing.T) {
			rt := &recordingRuntime{createErr: poolErr}
			svc, st, admitter := newServiceRuntimeHarnessAtPath(t, filepath.Join(t.TempDir(), "state.db"), rt)
			_, err := svc.CreateSandbox(context.Background(), models.CreateSandboxRequest{Image: "alpine", CPU: 0.25, MemoryMB: 128})
			if !errors.Is(err, capacity.ErrCapacityExceeded) || !errors.Is(err, poolErr) {
				t.Fatalf("create on a full pool = %v, want the pool's capacity refusal", err)
			}
			if rt.createCalls != 1 {
				t.Fatalf("runtime create called %d times, want 1 (no retry inside the node)", rt.createCalls)
			}
			if got := admitter.Snapshot().SandboxesActive; got != 0 {
				t.Fatalf("admitter still holds %d reservations after the refusal", got)
			}
			rows, err := st.List(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if len(rows) != 0 {
				t.Fatalf("refused create left %d rows", len(rows))
			}
		})
	}
}
