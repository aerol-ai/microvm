package daemon

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/network/tap"
	fcruntime "github.com/aerol-ai/microvm/internal/runtime/firecracker"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
)

func TestGuardedReconcilersNoopPaths(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// These calls are expected to return immediately on guard conditions.
	startAutoImportReconciler(ctx, logger, config.Config{AutoImportEnabled: false}, nil, nil)
	startSnapshotPushReconciler(ctx, logger, config.Config{SnapshotPushEnabled: false}, nil, nil, nil)
	startTemplateRotationReconciler(ctx, logger, config.Config{EnableFirecracker: false}, nil, nil)
	startTemplateRotationReconciler(ctx, logger, config.Config{
		EnableFirecracker:                   true,
		FirecrackerTemplateRotationInterval: time.Second,
		FirecrackerTemplateMaxAge:           0,
	}, nil, nil)
	attachTemplateArtifactPuller(logger, config.Config{EnableFirecracker: false}, nil, nil)
	attachTemplateArtifactPuller(logger, config.Config{EnableFirecracker: true, FirecrackerTemplatesDir: ""}, nil, nil)
}

func TestAdaptTapSlot(t *testing.T) {
	if adaptTapSlot(nil) != nil {
		t.Fatalf("adaptTapSlot(nil) should return nil")
	}
	raw := &tap.Slot{TapName: "fctap0", CIDR: "172.16.0.0/30", HostIP: "172.16.0.1", GuestIP: "172.16.0.2", VsockCID: 42}
	got := adaptTapSlot(raw)
	if got == nil || got.TapName != raw.TapName || got.CIDR != raw.CIDR || got.HostIP != raw.HostIP || got.GuestIP != raw.GuestIP || got.VsockCID != raw.VsockCID {
		t.Fatalf("adapted slot mismatch: got %+v, want %+v", got, raw)
	}
}

func TestFirecrackerPoolAdapterAllocateGetRelease(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	pool := tap.New(st)
	if err := pool.Seed(ctx, tap.SeedConfig{BaseCIDR: "172.16.0.0/24", PoolSize: 2}, time.Now()); err != nil {
		t.Fatalf("pool.Seed: %v", err)
	}
	adapter := &firecrackerPoolAdapter{inner: pool}

	slot, err := adapter.Allocate(ctx, "sb-1", time.Now())
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	if slot == nil || slot.TapName == "" || slot.VsockCID < 3 {
		t.Fatalf("unexpected allocated slot: %+v", slot)
	}

	got, err := adapter.Get(ctx, "sb-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got == nil || got.TapName != slot.TapName {
		t.Fatalf("Get mismatch: got %+v, want tap %s", got, slot.TapName)
	}

	if err := adapter.Release(ctx, "sb-1"); err != nil {
		t.Fatalf("Release: %v", err)
	}
	got, err = adapter.Get(ctx, "sb-1")
	if err != nil {
		t.Fatalf("Get after release: %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil slot after release, got %+v", got)
	}
}

func TestFirecrackerCIDAllocatorAdapter(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	pool := tap.New(st)
	if err := pool.Seed(ctx, tap.SeedConfig{BaseCIDR: "172.16.1.0/24", PoolSize: 4}, time.Now()); err != nil {
		t.Fatalf("pool.Seed: %v", err)
	}

	alloc := &firecrackerCIDAllocatorAdapter{pool: pool}
	cid1, err := alloc.AllocateForTemplate(ctx, "tpl-a")
	if err != nil {
		t.Fatalf("AllocateForTemplate: %v", err)
	}
	cid2, err := alloc.AllocateForTemplate(ctx, "tpl-a")
	if err != nil {
		t.Fatalf("AllocateForTemplate second call: %v", err)
	}
	if cid1 != cid2 {
		t.Fatalf("idempotent allocation mismatch: first=%d second=%d", cid1, cid2)
	}
	if err := alloc.ReleaseForTemplate(ctx, "tpl-a"); err != nil {
		t.Fatalf("ReleaseForTemplate: %v", err)
	}
}

func TestTemplateResolverAdapterResolve(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	svc := service.New(config.Config{}, slog.New(slog.NewTextHandler(io.Discard, nil)), st, nil, nil, nil, nil, nil, nil)
	adapter := &templateResolverAdapter{svc: svc}

	now := time.Now().UTC()
	if err := st.CreateTemplate(ctx, &models.Template{
		ID:                 "tpl-ready",
		Image:              "alpine",
		Status:             models.TemplateStatusReady,
		RootfsPath:         "/tmp/tpl-ready/rootfs.ext4",
		CreatedAt:          now,
		UpdatedAt:          now,
		HasSnapshot:        true,
		SnapshotMemoryPath: "/tmp/tpl-ready/mem.snap",
		SnapshotStatePath:  "/tmp/tpl-ready/state.snap",
		SnapshotChecksum:   "abc",
		SnapshotVsockCID:   101,
	}); err != nil {
		t.Fatalf("CreateTemplate ready: %v", err)
	}

	res, err := adapter.Resolve(ctx, "tpl-ready")
	if err != nil {
		t.Fatalf("Resolve ready: %v", err)
	}
	if res.RootfsPath != "/tmp/tpl-ready/rootfs.ext4" || !res.HasSnapshot || res.SnapshotVsockCID != 101 {
		t.Fatalf("unexpected resolution: %+v", res)
	}

	if err := st.CreateTemplate(ctx, &models.Template{
		ID:         "tpl-building",
		Image:      "alpine",
		Status:     models.TemplateStatusBuildingRootfs,
		RootfsPath: "/tmp/tpl-building/rootfs.ext4",
		CreatedAt:  now,
		UpdatedAt:  now,
	}); err != nil {
		t.Fatalf("CreateTemplate building: %v", err)
	}
	if _, err := adapter.Resolve(ctx, "tpl-building"); err == nil || !strings.Contains(err.Error(), "not ready") {
		t.Fatalf("expected not-ready error, got %v", err)
	}

	if err := st.CreateTemplate(ctx, &models.Template{
		ID:         "tpl-no-rootfs",
		Image:      "alpine",
		Status:     models.TemplateStatusReady,
		RootfsPath: "",
		CreatedAt:  now,
		UpdatedAt:  now,
	}); err != nil {
		t.Fatalf("CreateTemplate no-rootfs: %v", err)
	}
	if _, err := adapter.Resolve(ctx, "tpl-no-rootfs"); err == nil || !strings.Contains(err.Error(), "has no rootfs path") {
		t.Fatalf("expected missing-rootfs error, got %v", err)
	}
}

func TestVMMTemplateListerAdapterFiltersWarmable(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	svc := service.New(config.Config{}, slog.New(slog.NewTextHandler(io.Discard, nil)), st, nil, nil, nil, nil, nil, nil)
	lister := &vmmTemplateListerAdapter{svc: svc}
	now := time.Now().UTC()

	seed := []*models.Template{
		{ID: "tpl-ok", Image: "alpine", Status: models.TemplateStatusReady, HasSnapshot: true, SnapshotMemoryPath: "/tmp/mem", SnapshotStatePath: "/tmp/state", SnapshotChecksum: "sum", SnapshotVsockCID: 200, CreatedAt: now, UpdatedAt: now},
		{ID: "tpl-no-snap", Image: "alpine", Status: models.TemplateStatusReady, HasSnapshot: false, SnapshotMemoryPath: "/tmp/mem", SnapshotStatePath: "/tmp/state", CreatedAt: now, UpdatedAt: now},
		{ID: "tpl-no-path", Image: "alpine", Status: models.TemplateStatusReady, HasSnapshot: true, SnapshotMemoryPath: "", SnapshotStatePath: "/tmp/state", CreatedAt: now, UpdatedAt: now},
		{ID: "tpl-pending", Image: "alpine", Status: models.TemplateStatusPending, HasSnapshot: true, SnapshotMemoryPath: "/tmp/mem", SnapshotStatePath: "/tmp/state", CreatedAt: now, UpdatedAt: now},
	}
	for _, tpl := range seed {
		if err := st.CreateTemplate(ctx, tpl); err != nil {
			t.Fatalf("CreateTemplate(%s): %v", tpl.ID, err)
		}
	}

	inputs, err := lister.ListWarmableTemplates(ctx)
	if err != nil {
		t.Fatalf("ListWarmableTemplates: %v", err)
	}
	if len(inputs) != 1 {
		t.Fatalf("warmable templates = %d, want 1", len(inputs))
	}
	if inputs[0].TemplateID != "tpl-ok" || inputs[0].SnapshotMemoryPath == "" || inputs[0].SnapshotStatePath == "" {
		t.Fatalf("unexpected warmable input: %+v", inputs[0])
	}
}

func TestAutoImportSpecResolverGetSandboxSpec(t *testing.T) {
	svc := service.New(config.Config{}, slog.New(slog.NewTextHandler(io.Discard, nil)), nil, nil, nil, nil, nil, nil, nil)
	clusterStub := &specStubCluster{
		Noop: cluster.NewNoop("node-a", "http://node-a", ""),
		specByID: map[string]*models.CreateSandboxRequest{
			"sb-1": {Image: "alpine"},
		},
	}
	svc.AttachCluster(clusterStub)

	resolver := autoImportSpecResolver{svc: svc}
	spec, ok := resolver.GetSandboxSpec("sb-1")
	if !ok || spec == nil || spec.Image != "alpine" {
		t.Fatalf("GetSandboxSpec hit = (%v, %+v), want true + alpine spec", ok, spec)
	}
	spec, ok = resolver.GetSandboxSpec("missing")
	if ok || spec != nil {
		t.Fatalf("GetSandboxSpec miss = (%v, %+v), want false + nil", ok, spec)
	}
}

type specStubCluster struct {
	*cluster.Noop
	specByID map[string]*models.CreateSandboxRequest
}

func (s *specStubCluster) SpecOf(sandboxID string) *models.CreateSandboxRequest {
	if s.specByID == nil {
		return nil
	}
	return s.specByID[sandboxID]
}

var _ cluster.Client = (*specStubCluster)(nil)

func TestAdaptTapSlotTypeRoundTrip(t *testing.T) {
	raw := &tap.Slot{TapName: "fctap99", CIDR: "10.0.0.0/30", HostIP: "10.0.0.1", GuestIP: "10.0.0.2", VsockCID: 99}
	got := adaptTapSlot(raw)
	if got == nil {
		t.Fatalf("adaptTapSlot returned nil")
	}
	want := &fcruntime.TapSlot{TapName: raw.TapName, CIDR: raw.CIDR, HostIP: raw.HostIP, GuestIP: raw.GuestIP, VsockCID: raw.VsockCID}
	if *got != *want {
		t.Fatalf("adaptTapSlot mismatch: got %+v, want %+v", *got, *want)
	}
}
