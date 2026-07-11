package daemon

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/network/tap"
	vmmpool "github.com/aerol-ai/microvm/internal/pool/vmm"
	fcruntime "github.com/aerol-ai/microvm/internal/runtime/firecracker"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/oci"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func openTestStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

type specStubCluster struct {
	*cluster.Noop
	specs map[string]*models.CreateSandboxRequest
}

func (s *specStubCluster) SpecOf(id string) *models.CreateSandboxRequest {
	return s.specs[id]
}

func TestDaemonReconcilerGuards_NoPanic(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	logger := testLogger()

	// All of these should short-circuit cleanly under disabled/guard configs.
	startAutoImportReconciler(ctx, logger, config.Config{AutoImportEnabled: false}, nil, nil)
	startSnapshotPushReconciler(ctx, logger, config.Config{SnapshotPushEnabled: false}, nil, nil, nil)
	startTemplateRotationReconciler(ctx, logger, config.Config{EnableFirecracker: false}, nil, nil)
	startTemplateRotationReconciler(ctx, logger, config.Config{EnableFirecracker: true, FirecrackerTemplateRotationInterval: time.Second, FirecrackerTemplateMaxAge: 0}, nil, nil)
	attachTemplateArtifactPuller(logger, config.Config{EnableFirecracker: false}, nil, nil)
	attachTemplateArtifactPuller(logger, config.Config{EnableFirecracker: true, FirecrackerTemplatesDir: ""}, nil, nil)
	startTemplateArtifactPushReconciler(ctx, logger, config.Config{EnableFirecracker: false, SnapshotPushEnabled: true}, nil, nil, nil)
	startTemplateArtifactPushReconciler(ctx, logger, config.Config{EnableFirecracker: true, SnapshotPushEnabled: false}, nil, nil, nil)
}

func TestConfigureAOCRPullAuthGuard_NoPanic(t *testing.T) {
	logger := testLogger()

	// Empty config: must short-circuit before touching the client.
	configureAOCRPullAuth(logger, config.Config{}, &docker.Client{})

	// Fully configured: writes node-local pull auth onto the client. The
	// behavior of the resolver itself is covered in pkg/docker; here we only
	// assert the daemon wiring path runs cleanly.
	patPath := filepath.Join(t.TempDir(), "cluster-pat")
	if err := os.WriteFile(patPath, []byte("tok"), 0o600); err != nil {
		t.Fatalf("write pat: %v", err)
	}
	configureAOCRPullAuth(logger, config.Config{
		AutoImportClusterID:       "prod-aerolvm-us-east-1",
		AutoImportClusterPATPath:  patPath,
		MirrorPushHost:            "aocr.aerol.ai",
		ImageDistributionAOCRHost: "aocr.aerol.ai",
	}, &docker.Client{})
}

func TestAdaptTapSlot(t *testing.T) {
	if got := adaptTapSlot(nil); got != nil {
		t.Fatalf("adaptTapSlot(nil) = %+v, want nil", got)
	}

	in := &tap.Slot{TapName: "fctap1", CIDR: "172.16.0.0/30", HostIP: "172.16.0.1", GuestIP: "172.16.0.2", VsockCID: 33, GuestMAC: "02:00:00:00:00:03"}
	got := adaptTapSlot(in)
	if got == nil || got.TapName != in.TapName || got.CIDR != in.CIDR || got.HostIP != in.HostIP || got.GuestIP != in.GuestIP || got.VsockCID != in.VsockCID || got.GuestMAC != in.GuestMAC {
		t.Fatalf("adaptTapSlot mismatch: got=%+v in=%+v", got, in)
	}
}

func TestFirecrackerPoolAdapter_RoundTrip(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	pool := tap.New(st)
	if err := pool.Seed(ctx, tap.SeedConfig{BaseCIDR: "172.20.0.0/29", PoolSize: 2}, time.Now()); err != nil {
		t.Fatalf("Seed: %v", err)
	}
	adapter := &firecrackerPoolAdapter{inner: pool}

	now := time.Now()
	slot, err := adapter.Allocate(ctx, "vmms-warm", now)
	if err != nil {
		t.Fatalf("Allocate warm slot: %v", err)
	}
	transferred, err := adapter.Transfer(ctx, "vmms-warm", "sb-1", now.Add(time.Second))
	if err != nil {
		t.Fatalf("Transfer: %v", err)
	}
	if transferred == nil || transferred.TapName != slot.TapName {
		t.Fatalf("Transfer slot mismatch: got=%+v want tap %q", transferred, slot.TapName)
	}

	got, err := adapter.Get(ctx, "sb-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got == nil || got.TapName != transferred.TapName {
		t.Fatalf("Get slot mismatch: got=%+v want=%+v", got, transferred)
	}

	if err := adapter.Release(ctx, "sb-1"); err != nil {
		t.Fatalf("Release: %v", err)
	}
	got, err = adapter.Get(ctx, "sb-1")
	if err != nil {
		t.Fatalf("Get after release: %v", err)
	}
	if got != nil {
		t.Fatalf("Get after release = %+v, want nil", got)
	}

	if _, err := adapter.Transfer(ctx, "missing-warm", "sb-miss", now); err == nil {
		t.Fatal("Transfer from missing slot should fail")
	}
}

func TestFirecrackerCIDAllocatorAdapter_RoundTrip(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	pool := tap.New(st)
	if err := pool.Seed(ctx, tap.SeedConfig{BaseCIDR: "172.21.0.0/30", PoolSize: 1}, time.Now()); err != nil {
		t.Fatalf("Seed: %v", err)
	}
	a := &firecrackerCIDAllocatorAdapter{pool: pool}

	cid, err := a.AllocateForTemplate(ctx, "tpl-1")
	if err != nil {
		t.Fatalf("AllocateForTemplate: %v", err)
	}
	if cid == 0 {
		t.Fatalf("cid = 0, want non-zero")
	}
	if err := a.ReleaseForTemplate(ctx, "tpl-1"); err != nil {
		t.Fatalf("ReleaseForTemplate: %v", err)
	}
}

func TestAutoImportSpecResolver_GetSandboxSpec(t *testing.T) {
	logger := testLogger()
	svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
	stub := &specStubCluster{
		Noop: cluster.NewNoop("node-a", "http://node-a", ""),
		specs: map[string]*models.CreateSandboxRequest{
			"sb-1": {Image: "alpine:3.20"},
		},
	}
	svc.AttachCluster(stub)

	resolver := autoImportSpecResolver{svc: svc}
	spec, ok := resolver.GetSandboxSpec("sb-1")
	if !ok || spec == nil || spec.Image != "alpine:3.20" {
		t.Fatalf("GetSandboxSpec hit = (%+v, %v), want image alpine:3.20 + true", spec, ok)
	}
	if miss, ok := resolver.GetSandboxSpec("missing"); ok || miss != nil {
		t.Fatalf("GetSandboxSpec miss = (%+v, %v), want (nil,false)", miss, ok)
	}
}

func TestVMMTemplateListerAdapter_ListWarmableTemplates(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	logger := testLogger()
	svc := service.New(config.Config{}, logger, st, nil, nil, nil, nil, nil, nil)
	a := &vmmTemplateListerAdapter{svc: svc}

	now := time.Now().UTC()
	mustCreateTemplate := func(tpl *models.Template) {
		t.Helper()
		if err := st.CreateTemplate(ctx, tpl); err != nil {
			t.Fatalf("CreateTemplate(%s): %v", tpl.ID, err)
		}
	}

	mustCreateTemplate(&models.Template{
		ID: "tpl-warm", Image: "alpine", Status: models.TemplateStatusReady,
		RootfsPath: "/tmp/rootfs.ext4", CreatedAt: now, UpdatedAt: now,
		HasSnapshot: true, HasOverlay: true, SnapshotMemoryPath: "/tmp/snap.mem", SnapshotStatePath: "/tmp/snap.state", SnapshotChecksum: "abc", SnapshotVsockCID: 200,
	})
	mustCreateTemplate(&models.Template{ID: "tpl-no-path", Image: "alpine", Status: models.TemplateStatusReady, CreatedAt: now, UpdatedAt: now, HasSnapshot: true})
	mustCreateTemplate(&models.Template{ID: "tpl-no-snap", Image: "alpine", Status: models.TemplateStatusReadyNoSnapshot, CreatedAt: now, UpdatedAt: now, HasSnapshot: false})
	mustCreateTemplate(&models.Template{ID: "tpl-pending", Image: "alpine", Status: models.TemplateStatusPending, CreatedAt: now, UpdatedAt: now, HasSnapshot: true, SnapshotMemoryPath: "/tmp/x", SnapshotStatePath: "/tmp/y"})

	got, err := a.ListWarmableTemplates(ctx)
	if err != nil {
		t.Fatalf("ListWarmableTemplates: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("len(ListWarmableTemplates) = %d, want 1 (%+v)", len(got), got)
	}
	if got[0].TemplateID != "tpl-warm" || got[0].SnapshotMemoryPath == "" || got[0].SnapshotStatePath == "" || got[0].VsockCID != 200 || !got[0].HasOverlay {
		t.Fatalf("unexpected warmable template: %+v", got[0])
	}
}

func TestFirecrackerWarmPoolDepthCapsByTapBudget(t *testing.T) {
	for _, tc := range []struct {
		name       string
		configured int
		tapSize    int
		want       int
		wantCapped bool
	}{
		{name: "under budget", configured: 4, tapSize: 64, want: 4},
		{name: "at budget", configured: 8, tapSize: 64, want: 8},
		{name: "over budget", configured: 16, tapSize: 64, want: 8, wantCapped: true},
		{name: "tiny tap pool disables warm depth", configured: 1, tapSize: 4, want: 0, wantCapped: true},
		{name: "negative configured clamps to zero", configured: -1, tapSize: 64, want: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, capped := firecrackerWarmPoolDepth(tc.configured, tc.tapSize)
			if got != tc.want || capped != tc.wantCapped {
				t.Fatalf("firecrackerWarmPoolDepth(%d,%d) = (%d,%v), want (%d,%v)",
					tc.configured, tc.tapSize, got, capped, tc.want, tc.wantCapped)
			}
		})
	}
}

func TestTemplateResolverAdapter_Resolve(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	logger := testLogger()
	svc := service.New(config.Config{}, logger, st, nil, nil, nil, nil, nil, nil)
	a := &templateResolverAdapter{svc: svc}
	now := time.Now().UTC()

	mustCreateTemplate := func(tpl *models.Template) {
		t.Helper()
		if err := st.CreateTemplate(ctx, tpl); err != nil {
			t.Fatalf("CreateTemplate(%s): %v", tpl.ID, err)
		}
	}

	mustCreateTemplate(&models.Template{ID: "tpl-ready", Image: "alpine", Status: models.TemplateStatusReadyNoSnapshot, RootfsPath: "/tmp/rootfs.ext4", CreatedAt: now, UpdatedAt: now})
	mustCreateTemplate(&models.Template{ID: "tpl-pending", Image: "alpine", Status: models.TemplateStatusPending, RootfsPath: "/tmp/rootfs.ext4", CreatedAt: now, UpdatedAt: now})
	mustCreateTemplate(&models.Template{ID: "tpl-no-rootfs", Image: "alpine", Status: models.TemplateStatusReady, RootfsPath: "", CreatedAt: now, UpdatedAt: now, HasSnapshot: true})

	res, err := a.Resolve(ctx, "tpl-ready")
	if err != nil {
		t.Fatalf("Resolve tpl-ready: %v", err)
	}
	if res == nil || res.RootfsPath != "/tmp/rootfs.ext4" || res.HasSnapshot {
		t.Fatalf("unexpected resolve result: %+v", res)
	}

	if _, err := a.Resolve(ctx, "tpl-pending"); err == nil {
		t.Fatalf("expected error for pending template")
	}
	if _, err := a.Resolve(ctx, "tpl-no-rootfs"); err == nil {
		t.Fatalf("expected error for ready template without rootfs")
	}
	if _, err := a.Resolve(ctx, "does-not-exist"); err == nil {
		t.Fatalf("expected not-found error")
	}
}

func TestFirecrackerRootfsAdapter_BuildSuccess(t *testing.T) {
	cfg, work := ociHappyConfig(t)
	builder, err := oci.New(cfg)
	if err != nil {
		t.Fatalf("oci.New: %v", err)
	}
	a := &firecrackerRootfsAdapter{inner: builder}
	out := filepath.Join(work, "rootfs.ext4")
	res, err := a.Build(context.Background(), fcruntime.RootfsBuildRequest{
		ImageRef: "docker://alpine:3.20",
		OutPath:  out,
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if res == nil || res.RootfsPath != out {
		t.Fatalf("unexpected result: %+v", res)
	}
}

func TestFirecrackerRootfsAdapter_BuildWithInjectFiles(t *testing.T) {
	cfg, work := ociHappyConfig(t)
	builder, err := oci.New(cfg)
	if err != nil {
		t.Fatalf("oci.New: %v", err)
	}
	hostBin := filepath.Join(t.TempDir(), "toolboxd")
	if err := os.WriteFile(hostBin, []byte("ELF-ish"), 0o644); err != nil {
		t.Fatal(err)
	}
	a := &firecrackerRootfsAdapter{inner: builder}
	out := filepath.Join(work, "rootfs-inject.ext4")
	res, err := a.Build(context.Background(), fcruntime.RootfsBuildRequest{
		ImageRef: "docker://alpine:3.20",
		OutPath:  out,
		InjectFiles: []fcruntime.InjectFile{
			{HostPath: hostBin, GuestPath: "/usr/local/bin/toolboxd", Mode: 0o755},
			{Content: []byte("SB_TOOLBOX_TOKEN='tok'\n"), GuestPath: "/etc/toolboxd.env", Mode: 0o600},
		},
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if res == nil || res.RootfsPath != out {
		t.Fatalf("unexpected result: %+v", res)
	}
	if err := res.Cleanup(); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
}

func TestTemplateBuilderAdapter_BuildSuccess(t *testing.T) {
	cfg, work := ociHappyConfig(t)
	builder, err := oci.New(cfg)
	if err != nil {
		t.Fatalf("oci.New: %v", err)
	}
	a := &templateBuilderAdapter{inner: builder}
	out := filepath.Join(work, "tpl-rootfs.ext4")
	res, err := a.Build(context.Background(), service.TemplateBuildRequest{
		ImageRef: "docker://alpine:3.20",
		OutPath:  out,
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if res == nil || res.RootfsPath != out {
		t.Fatalf("unexpected result: %+v", res)
	}
}

func TestVMMTemplateListerAdapter_TypeUses(t *testing.T) {
	// Compile-time sanity check that adapter output remains aligned with vmmpool input type.
	var _ vmmpool.TemplateWarmInput
	var _ = fcruntime.TemplateResolution{}
}
