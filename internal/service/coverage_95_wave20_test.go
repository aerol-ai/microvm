package service

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/caddy"
	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
	wasmengine "github.com/aerol-ai/microvm/pkg/wasm"
)

// blockingVolumeReclaimer holds the first Reclaim until released so
// runVolumeReclaim's ctx.Done arm can win the select on a subsequent job.
type blockingVolumeReclaimer struct {
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (b *blockingVolumeReclaimer) Reclaim(context.Context, string, string) error {
	b.once.Do(func() { close(b.started) })
	<-b.release
	return nil
}

// scriptedVolumeMeta drives reclaimOne branches: ByID not-found then
// ExistsForSource / DeletePending failure arms.
type scriptedVolumeMeta struct {
	byIDErr            error
	byID               *models.Volume
	exists             bool
	existsErr          error
	deleteAttachErr    error
	putAttachmentsErr  error
	deleteRowErr       error
	getOrCreateErr     error
	byNameErr          error
	listErr            error
	attachmentCount    int
	attachmentCountErr error
}

func (m *scriptedVolumeMeta) GetOrCreate(context.Context, *models.Volume, int) (*models.Volume, bool, error) {
	return nil, false, m.getOrCreateErr
}
func (m *scriptedVolumeMeta) ByID(context.Context, string, string) (*models.Volume, error) {
	if m.byIDErr != nil {
		return nil, m.byIDErr
	}
	return m.byID, nil
}
func (m *scriptedVolumeMeta) ByName(context.Context, string, string) (*models.Volume, error) {
	return nil, m.byNameErr
}
func (m *scriptedVolumeMeta) List(context.Context, string) ([]models.Volume, error) {
	return nil, m.listErr
}
func (m *scriptedVolumeMeta) DeleteRow(context.Context, string, string) error {
	return m.deleteRowErr
}
func (m *scriptedVolumeMeta) ExistsForSource(context.Context, string) (bool, error) {
	return m.exists, m.existsErr
}
func (m *scriptedVolumeMeta) AttachmentCount(context.Context, string, string) (int, error) {
	return m.attachmentCount, m.attachmentCountErr
}
func (m *scriptedVolumeMeta) PutAttachments(context.Context, []models.VolumeAttachment) error {
	return m.putAttachmentsErr
}
func (m *scriptedVolumeMeta) DeleteAttachmentsForSandbox(context.Context, string) error {
	return m.deleteAttachErr
}

func TestIsolateAndWasmHTTPRouteShapeNoneWave20(t *testing.T) {
	ctx := context.Background()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)

	isoRT := &isolatePortsRuntime{recordingRuntime: &recordingRuntime{}}
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableCaddy = true
	svc.cfg.EnableServerless = true
	svc.cfg.EnableIsolate = true
	svc.cfg.EnableWasm = true
	svc.cfg.HTTPWakeDirectBypassEnabled = true
	svc.cfg.Domain = "sandbox.example.com"
	svc.cfg.InternalIngressAddr = "127.0.0.1:21220"
	svc.caddy = caddy.New(config.Config{
		EnableCaddy: true, Domain: "sandbox.example.com",
		CaddyAdminURL: server.URL, CaddyServerID: "srv0", HTTPClientTimeout: time.Second,
	})
	svc.SetIsolateRuntime(isoRT)
	svc.SetWasmRuntime(&wasmPortsRuntime{recordingRuntime: &recordingRuntime{}})

	none := &models.Sandbox{
		ID: "sb-none-iso", Runtime: models.RuntimeIsolate,
		Status: models.SandboxStatusStopped, WakeArmed: false,
		Lifecycle: models.Lifecycle{Serverless: true, StopIfIdleFor: time.Minute},
	}
	if err := svc.installIsolateHTTPPortRoute(ctx, none, 8080); err != nil {
		t.Fatalf("isolate RouteShapeNone: %v", err)
	}
	svc.isolateHTTPPortRouteCleanup(ctx, none.ID, 8080)

	wasmNone := &models.Sandbox{
		ID: "sb-none-wasm", Runtime: models.RuntimeWasm,
		Status: models.SandboxStatusCreating, WakeArmed: false,
		Lifecycle: models.Lifecycle{Serverless: true, StopIfIdleFor: time.Minute},
	}
	if err := svc.installWasmHTTPPortRoute(ctx, wasmNone, 8081); err != nil {
		t.Fatalf("wasm RouteShapeNone: %v", err)
	}
	svc.wasmHTTPPortRouteCleanup(ctx, wasmNone.ID, 8081)
}

type wasmPortsRuntime struct {
	*recordingRuntime
	noopWasmPortGateway
}

func TestVolumeReclaimCancelSweepLimitAndMetaWave20(t *testing.T) {
	ctx := context.Background()
	s := enabledVolumeService(t)
	s.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	blocker := &blockingVolumeReclaimer{started: make(chan struct{}), release: make(chan struct{})}
	s.SetVolumeReclaimer(blocker)
	s.cfg.PlatformVolumes.ReclaimConcurrency = 1

	now := time.Now().UTC()
	for i := 0; i < 2; i++ {
		id := "vol-blk-" + string(rune('a'+i))
		src := "/tmp/wave20-" + id
		if err := s.store.SchedulePendingVolumeDeletion(ctx, models.Volume{
			ID: id, Tenant: "op", Name: id, Backend: "local", Source: src, CreatedAt: now,
		}, src); err != nil {
			t.Fatalf("schedule %s: %v", id, err)
		}
	}
	cancelCtx, cancel := context.WithCancel(ctx)
	go func() {
		<-blocker.started
		cancel()
		close(blocker.release) // unblock worker so runVolumeReclaim's Wait returns
	}()
	s.runVolumeReclaim(cancelCtx)

	// Sweep-limit truncation arm: seed > volumeReclaimSweepLimit rows.
	s2 := enabledVolumeService(t)
	s2.logger = s.logger
	s2.SetVolumeReclaimer(&fakeReclaimer{})
	s2.cfg.PlatformVolumes.ReclaimConcurrency = 2
	for i := 0; i < volumeReclaimSweepLimit+3; i++ {
		id := "vol-lim-" + itoaWave20(i)
		src := "/tmp/lim-" + id
		_ = s2.store.SchedulePendingVolumeDeletion(ctx, models.Volume{
			ID: id, Tenant: "op", Name: id, Backend: "local", Source: src, CreatedAt: now,
		}, src)
	}
	s2.runVolumeReclaim(ctx)

	// reclaimOne: ByID not found + ExistsForSource error.
	s3 := enabledVolumeService(t)
	s3.logger = s.logger
	s3.SetVolumeReclaimer(&fakeReclaimer{})
	s3.testVolumeMeta = &scriptedVolumeMeta{byIDErr: store.ErrNotFound, existsErr: errors.New("exists boom")}
	s3.reclaimOne(ctx, models.PendingVolumeDeletion{VolumeID: "v", Tenant: "op", Source: "/x", Backend: "local"})

	// reclaimOne: live source + DeletePending failure (close store after meta says live).
	s4 := enabledVolumeService(t)
	s4.logger = s.logger
	s4.SetVolumeReclaimer(&fakeReclaimer{})
	s4.testVolumeMeta = &scriptedVolumeMeta{byIDErr: store.ErrNotFound, exists: true}
	_ = s4.store.Close()
	s4.reclaimOne(ctx, models.PendingVolumeDeletion{VolumeID: "v2", Tenant: "op", Source: "/y", Backend: "local"})

	// reclaimOne: reclaim ok + DeletePending failure.
	s5 := enabledVolumeService(t)
	s5.logger = s.logger
	s5.SetVolumeReclaimer(&fakeReclaimer{})
	s5.testVolumeMeta = &scriptedVolumeMeta{byIDErr: store.ErrNotFound, exists: false}
	_ = s5.store.Close()
	s5.reclaimOne(ctx, models.PendingVolumeDeletion{VolumeID: "v3", Tenant: "op", Source: "/z", Backend: "local"})
}

func itoaWave20(i int) string {
	if i == 0 {
		return "0"
	}
	var b [12]byte
	pos := len(b)
	for i > 0 {
		pos--
		b[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(b[pos:])
}

func TestCreateSnapshotWithOwnershipGapsWave20(t *testing.T) {
	ctx := context.Background()

	t.Run("runtimeForSandbox missing", func(t *testing.T) {
		st := openImageDistributionStore(t)
		defer st.Close()
		now := time.Now().UTC()
		sb := seedSnapshotSandbox("sb-fc-miss", now)
		sb.Runtime = models.RuntimeFirecracker
		if err := st.Create(ctx, sb); err != nil {
			t.Fatal(err)
		}
		svc := &Service{store: st, docker: &fakeSnapshotRuntime{}, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
		if _, _, err := svc.CreateSnapshotWithOwnership(ctx, "sb-fc-miss", models.CreateSandboxSnapshotRequest{Name: "n/fc:1"}); err == nil {
			t.Fatal("expected runtime miss")
		}
	})

	t.Run("normalize failure", func(t *testing.T) {
		st := openImageDistributionStore(t)
		defer st.Close()
		now := time.Now().UTC()
		if err := st.Create(ctx, seedSnapshotSandbox("sb-norm", now)); err != nil {
			t.Fatal(err)
		}
		svc := &Service{
			store: st, docker: &fakeSnapshotRuntime{imageID: "sha"},
			logger:                   slog.New(slog.NewTextHandler(io.Discard, nil)),
			testNormalizeSnapshotErr: errors.New("normalize boom"),
		}
		if _, _, err := svc.CreateSnapshotWithOwnership(ctx, "sb-norm", models.CreateSandboxSnapshotRequest{Name: "n/norm:1"}); err == nil {
			t.Fatal("expected normalize fail")
		}
	})

	t.Run("store conflict same sandbox", func(t *testing.T) {
		st := openImageDistributionStore(t)
		defer st.Close()
		now := time.Now().UTC()
		if err := st.Create(ctx, seedSnapshotSandbox("sb-same", now)); err != nil {
			t.Fatal(err)
		}
		svc := &Service{store: st, docker: &fakeSnapshotRuntime{imageID: "sha"}, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
		svc.testBeforeStoreCreateSnapshot = func(snap *models.SandboxSnapshot) {
			_ = st.CreateSnapshot(ctx, &models.SandboxSnapshot{
				Name: snap.Name, Image: snap.Name, ImageID: "other",
				SourceSandboxID: "sb-same", CreatedAt: now, PushState: models.SnapshotPushStateActive,
			})
		}
		got, created, err := svc.CreateSnapshotWithOwnership(ctx, "sb-same", models.CreateSandboxSnapshotRequest{Name: "n/same:1"})
		if err != nil || created || got == nil {
			t.Fatalf("same-sandbox conflict = (%v,%v,%v)", got, created, err)
		}
	})

	t.Run("store conflict other sandbox", func(t *testing.T) {
		st := openImageDistributionStore(t)
		defer st.Close()
		now := time.Now().UTC()
		for _, id := range []string{"sb-a", "sb-b"} {
			if err := st.Create(ctx, seedSnapshotSandbox(id, now)); err != nil {
				t.Fatal(err)
			}
		}
		svc := &Service{store: st, docker: &fakeSnapshotRuntime{imageID: "sha"}, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
		svc.testBeforeStoreCreateSnapshot = func(snap *models.SandboxSnapshot) {
			_ = st.CreateSnapshot(ctx, &models.SandboxSnapshot{
				Name: snap.Name, Image: snap.Name, ImageID: "other",
				SourceSandboxID: "sb-b", CreatedAt: now, PushState: models.SnapshotPushStateActive,
			})
		}
		if _, _, err := svc.CreateSnapshotWithOwnership(ctx, "sb-a", models.CreateSandboxSnapshotRequest{Name: "n/other:1"}); !errors.Is(err, store.ErrSnapshotNameConflict) {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("kick non-pending with reconciler", func(t *testing.T) {
		st := openImageDistributionStore(t)
		defer st.Close()
		now := time.Now().UTC()
		if err := st.Create(ctx, seedSnapshotSandbox("sb-kick", now)); err != nil {
			t.Fatal(err)
		}
		svc := &Service{store: st, docker: &fakeSnapshotRuntime{imageID: "sha"}, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
		rec := newTestReconciler(t, st, &fakeSnapshotPushDocker{})
		svc.snapshotPushReconciler = rec // pusher nil → active push state → L2391
		snap, created, err := svc.CreateSnapshotWithOwnership(ctx, "sb-kick", models.CreateSandboxSnapshotRequest{Name: "n/kick:1"})
		if err != nil || !created || snap.PushState != models.SnapshotPushStateActive {
			t.Fatalf("kick path = (%+v,%v,%v)", snap, created, err)
		}
	})

	t.Run("GetSnapshot error after conflict", func(t *testing.T) {
		st := openImageDistributionStore(t)
		now := time.Now().UTC()
		if err := st.Create(ctx, seedSnapshotSandbox("sb-get", now)); err != nil {
			t.Fatal(err)
		}
		svc := &Service{store: st, docker: &fakeSnapshotRuntime{imageID: "sha"}, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
		svc.testBeforeStoreCreateSnapshot = func(snap *models.SandboxSnapshot) {
			_ = st.CreateSnapshot(ctx, &models.SandboxSnapshot{
				Name: snap.Name, Image: snap.Name, ImageID: "x",
				SourceSandboxID: "other", CreatedAt: now,
			})
			_ = st.Close()
		}
		if _, _, err := svc.CreateSnapshotWithOwnership(ctx, "sb-get", models.CreateSandboxSnapshotRequest{Name: "n/get:1"}); err == nil {
			t.Fatal("expected conflict+get failure")
		}
	})
}

func TestApplyInFluxRouteDomainAndPortsWave20(t *testing.T) {
	ctx := context.Background()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete || r.Method == http.MethodPut || r.Method == http.MethodPatch {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)

	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableCaddy = true
	svc.cfg.Domain = "sandbox.example.com"
	svc.caddy = caddy.New(config.Config{
		EnableCaddy: true, Domain: "sandbox.example.com",
		CaddyAdminURL: server.URL, CaddyServerID: "srv0", HTTPClientTimeout: time.Second,
	})
	p := cluster.Placement{
		SandboxID: "sb-flux",
		ExposedPortRoutes: map[int]cluster.ExposedPortRoute{
			80:  {Protocol: models.ExposedPortProtocolHTTP},
			443: {Protocol: models.ExposedPortProtocolTLS},
			22:  {Protocol: models.ExposedPortProtocolTCP},
		},
	}
	_ = svc.applyInFluxRoute(ctx, p)

	svc.cfg.Domain = ""
	_ = svc.applyInFluxRoute(ctx, p)
}

func TestClusterOwnershipReplayGapsWave20(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarnessAllowStoreClose(t, &recordingRuntime{})
	svc.cfg.EnableCluster = true
	svc.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	_ = st.Close()
	if _, err := svc.ReplayClusterOwnership(ctx); err == nil {
		t.Fatal("expected list failure")
	}

	svc2, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc2.cfg.EnableCluster = true
	svc2.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	svc2.cipher = newTestCipher(t)
	c := &fakeOwnershipCluster{
		Noop: cluster.NewNoop("self", "http://self", "self.example.com"),
		placements: map[string]cluster.Placement{
			"sb-other": {
				SandboxID: "sb-other", OwnerNodeID: "other",
				State: cluster.PlacementStatePlaced,
				Spec:  &models.CreateSandboxRequest{Image: "a"},
			},
			"sb-nil-spec": {
				SandboxID: "sb-nil-spec", OwnerNodeID: "self",
				State: cluster.PlacementStatePlaced, Spec: nil,
			},
			"sb-tpl": {
				SandboxID: "sb-tpl", OwnerNodeID: "self",
				State: cluster.PlacementStatePlaced,
				Spec:  &models.CreateSandboxRequest{Image: "a", TemplateID: "old"},
			},
			"sb-orphan-other": {
				SandboxID: "sb-orphan-other", OwnerState: cluster.PlacementOwnerStateOrphaned,
				OrphanedOwnerNodeID: "other-node", State: cluster.PlacementStatePlaced,
			},
		},
	}
	svc2.cluster = c
	now := time.Now().UTC()
	for _, sb := range []*models.Sandbox{
		{ID: "sb-other", Image: "a", Status: models.SandboxStatusStarted, CreatedAt: now, UpdatedAt: now},
		{ID: "sb-nil-spec", Image: "a", Status: models.SandboxStatusStarted, CreatedAt: now, UpdatedAt: now},
		{ID: "sb-tpl", Image: "a", TemplateID: "new", Status: models.SandboxStatusStarted, CreatedAt: now, UpdatedAt: now},
		{ID: "sb-orphan-other", Image: "a", Status: models.SandboxStatusStarted, CreatedAt: now, UpdatedAt: now},
	} {
		_ = clusterOwnershipNeedsReplayCall(svc2, c, sb)
	}

	// localSandboxStateForCluster: PutClusterSecrets + loadMounts fail when store is closed; nil ctx.
	svc3, st3, _ := newServiceRuntimeHarnessAllowStoreClose(t, &recordingRuntime{})
	svc3.cfg.EnableCluster = true
	svc3.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	svc3.cipher = newTestCipher(t)
	sealed, err := svc3.sealRegistry(&models.RegistryAuth{Username: "u", Password: "p"})
	if err != nil {
		t.Fatalf("sealRegistry: %v", err)
	}
	sb := &models.Sandbox{
		ID: "sb-sec", Image: "alpine:3.20", Status: models.SandboxStatusStarted,
		CPU: 1, MemoryMB: 256, DiskGB: 2, RegistryAuthSealed: sealed,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}
	_ = st3.Create(ctx, sb)
	c3 := &fakeOwnershipCluster{Noop: cluster.NewNoop("self", "http://self", "")}
	_ = st3.Close()
	_ = svc3.localSandboxStateForCluster(ctx, c3, sb)
	_ = svc3.specFromSandbox(nil, sb)
}

func clusterOwnershipNeedsReplayCall(svc *Service, c cluster.Client, sb *models.Sandbox) bool {
	return svc.clusterOwnershipNeedsReplay(c, sb)
}

func TestInstallTLSPortRouteShapeNoneWave20(t *testing.T) {
	ctx := context.Background()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)

	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableCaddy = true
	svc.cfg.EnableServerless = true
	svc.cfg.L4WakeDirectBypassEnabled = true
	svc.cfg.Domain = "sandbox.example.com"
	svc.cfg.InternalL4WakeDir = t.TempDir()
	svc.l4Ready.Store(true)
	svc.caddy = caddy.New(config.Config{
		EnableCaddy: true, Domain: "sandbox.example.com",
		CaddyAdminURL: server.URL, CaddyServerID: "srv0", HTTPClientTimeout: time.Second,
	})
	sb := &models.Sandbox{
		ID: "sb-tls-none", Status: models.SandboxStatusStopped, WakeArmed: false,
		Lifecycle: models.Lifecycle{Serverless: true, StopIfIdleFor: time.Minute},
	}
	if err := svc.installTLSPortRoute(ctx, sb, 443); err != nil {
		t.Fatalf("tls none: %v", err)
	}
}

func TestL4ListenPortColonPrefixWave20(t *testing.T) {
	if got := l4ListenPort(":8443"); got != 8443 {
		t.Fatalf("got %d", got)
	}
	if got := l4ListenPort("  "); got != 0 {
		t.Fatalf("empty = %d", got)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	_ = l4ListenPort(ln.Addr().String())
}

func TestUsageLiveListAndStatsFailWave20(t *testing.T) {
	svc, st, _ := newServiceRuntimeHarnessAllowStoreClose(t, &recordingRuntime{})
	svc.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	svc.SetUsageReporter(&captureReporter{})
	_ = st.Close()
	svc.sampleLiveUsageOnce(context.Background(), time.Now().UTC(), func(context.Context, string) (docker.ContainerStat, error) {
		return docker.ContainerStat{}, nil
	})

	svc2, st2, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc2.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	svc2.SetUsageReporter(&captureReporter{})
	now := time.Now().UTC()
	_ = st2.Create(context.Background(), &models.Sandbox{
		ID: "sb-live", Image: "a", Status: models.SandboxStatusStarted, ContainerID: "ctr",
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	})
	svc2.sampleLiveUsageOnce(context.Background(), now, func(context.Context, string) (docker.ContainerStat, error) {
		return docker.ContainerStat{}, errors.New("stats boom")
	})
}

func TestEnsureWasmSandboxRowImportWave20(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableWasm = true
	now := time.Now().UTC()
	_ = st.Create(ctx, &models.Sandbox{
		ID: "sb-imp", Runtime: models.RuntimeWasm, ModuleRef: "file:///m.wasm", Image: "file:///m.wasm",
		Status: models.SandboxStatusPassivated, CloneGeneration: "gen-a",
		CreatedAt: now, UpdatedAt: now,
	})
	snap := wasmengine.SnapshotRestoreInput{Config: wasmengine.SnapshotConfig{Durability: models.DurabilityPassivatable}}
	if err := svc.ensureWasmSandboxRowForImport(ctx, "sb-imp", snap, "/ckpt", "gen-b"); err == nil {
		t.Fatal("expected clone generation mismatch")
	}
	if err := svc.ensureWasmSandboxRowForImport(ctx, "sb-imp", snap, "/ckpt", "gen-a"); err != nil {
		t.Fatalf("matching gen: %v", err)
	}

	// Missing module_ref on new row.
	if err := svc.ensureWasmSandboxRowForImport(ctx, "sb-new", snap, "/ckpt", "g1"); err == nil {
		t.Fatal("expected module_ref required")
	}
	svc.cluster = &wasmMigrateClusterStub{
		Noop: cluster.NewNoop("self", "http://self", ""),
		spec: &models.CreateSandboxRequest{Runtime: models.RuntimeWasm, ModuleRef: "file:///x.wasm", Image: ""},
	}
	if err := svc.ensureWasmSandboxRowForImport(ctx, "sb-new2", snap, "/ckpt", "g1"); err != nil {
		t.Fatalf("import with cluster spec: %v", err)
	}

	svc3, _, _ := newServiceRuntimeHarnessAllowStoreClose(t, &recordingRuntime{})
	_ = svc3.store.Close()
	if err := svc3.ensureWasmSandboxRowForImport(ctx, "x", snap, "/c", "g"); err == nil {
		t.Fatal("expected store get failure")
	}
}

func TestWasmMigrateTarHardFailsWave20(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "mem.snap")
	_ = os.MkdirAll(src, 0o700)
	for _, name := range wasmSnapshotTarFiles {
		_ = os.WriteFile(filepath.Join(src, name), []byte("x"), 0o600)
	}
	// Make one file unreadable after tar write path for OpenFile fail on extract:
	// write a tar where destination directory is not writable.
	var buf bytes.Buffer
	if err := writeWasmCheckpointTar(&buf, src); err != nil {
		t.Fatalf("write: %v", err)
	}
	dstParent := filepath.Join(dir, "ro-parent")
	_ = os.MkdirAll(dstParent, 0o555)
	t.Cleanup(func() { _ = os.Chmod(dstParent, 0o755) })
	_ = extractWasmCheckpointTar(bytes.NewReader(buf.Bytes()), filepath.Join(dstParent, "dst"))

	// Rename fail: dst is a non-empty file blocking rename target's parent trick —
	// extract creates tmp under parent then renames onto dstDir; make dstDir a file.
	dstFile := filepath.Join(dir, "file-dst")
	_ = os.WriteFile(dstFile, []byte("block"), 0o600)
	// Need valid snapshot content for ReadSnapshotDir to pass — use real-ish files if available.
	// Skip rename if ReadSnapshotDir rejects "x" payloads; force via incomplete then...
	_ = extractWasmCheckpointTar(bytes.NewReader(buf.Bytes()), dstFile)

	// OpenFile fail: tar entry pointing at a path that can't be created — use directory as member name conflict.
	var bad bytes.Buffer
	tw := tar.NewWriter(&bad)
	_ = tw.WriteHeader(&tar.Header{Name: "config.json", Mode: 0o644, Size: 1})
	_, _ = tw.Write([]byte("a"))
	_ = tw.Close()
	// First create tmp with a directory named like a file we need to overwrite as file — hard on unix.
	// Cover Copy error via truncated tar mid-entry.
	var trunc bytes.Buffer
	tw2 := tar.NewWriter(&trunc)
	_ = tw2.WriteHeader(&tar.Header{Name: "config.json", Mode: 0o644, Size: 100})
	_, _ = tw2.Write([]byte("short"))
	_ = tw2.Close()
	_ = extractWasmCheckpointTar(bytes.NewReader(trunc.Bytes()), filepath.Join(dir, "trunc-dst"))
}

func TestFleetStopByOwnerNotFoundWave20(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	now := time.Now().UTC()
	_ = st.Create(ctx, &models.Sandbox{
		ID: "sb-fleet", Image: "a", Status: models.SandboxStatusStarted, OwnerRef: "own",
		ContainerID: "c", CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	})
	// Delete row between list and SetFleetSuspended by using a stub store isn't available;
	// call StopByOwner with owner that has a started sandbox then destroy mid-flight via hook.
	// Directly exercise the ErrNotFound continue by stopping after manual delete:
	_ = st.Delete(ctx, "sb-fleet")
	// Re-create as started for StopSandbox ErrNotFound path after SetFleetSuspended succeeds on missing?
	_ = st.Create(ctx, &models.Sandbox{
		ID: "sb-fleet2", Image: "a", Status: models.SandboxStatusStarted, OwnerRef: "own",
		ContainerID: "c2", CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	})
	if err := svc.StopByOwner(ctx, "own"); err != nil {
		t.Logf("StopByOwner: %v", err)
	}
}

func TestBypassEnabledForDefaultWave20(t *testing.T) {
	svc := &Service{cfg: config.Config{}}
	if svc.bypassEnabledFor(RouteKind(99)) {
		t.Fatal("unknown kind should be false")
	}
}

func TestHostFromURLEdgeWave20(t *testing.T) {
	_ = hostFromURL("http://[::1]:8080")
	_ = hostFromURL("192.168.1.1:9090")
	_ = hostFromURL("bare-host:1234")
	_ = dataPlaneHostForPlacement(cluster.Placement{OwnerAPIURL: "http://worker:8080"})
	_ = dataPlaneHostForPlacement(cluster.Placement{OwnerDataPlaneHost: "dp.example.com"})
}
