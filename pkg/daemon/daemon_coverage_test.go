package daemon

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
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
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/docker/netrules"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/oci"
)

// newTestDockerClient builds a *docker.Client without touching the Docker
// daemon — docker.New only assembles the struct (the socket is dialed
// lazily on first request). ToolboxBinaryPath is the single required field.
func newTestDockerClient(t *testing.T) *docker.Client {
	t.Helper()
	rules, err := netrules.New(false)
	if err != nil {
		t.Fatalf("netrules.New: %v", err)
	}
	c, err := docker.New(testLogger(), config.Config{ToolboxBinaryPath: "/bin/true"}, rules)
	if err != nil {
		t.Fatalf("docker.New: %v", err)
	}
	return c
}

// writeWrapKeyFile drops a syntactically valid wrap-key ring file at 0400 so
// LoadUpstreamWrapKeyRing accepts it (32 raw bytes, base64-encoded).
func writeWrapKeyFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "wrap.key")
	body := base64.StdEncoding.EncodeToString(make([]byte, 32))
	if err := os.WriteFile(path, []byte(body), 0o400); err != nil {
		t.Fatalf("write wrap key: %v", err)
	}
	return path
}

// TestRun_ConfigLoadFailureReturnsError: a missing SB_PAT_TOKEN makes
// config.Load fail, and Run must surface that as a wrapped error rather than
// exiting the process. This is the boot-failure path that os.Exit previously
// made impossible to assert.
func TestLoopbackAPIBaseURL(t *testing.T) {
	cases := map[string]string{
		"0.0.0.0:8080":   "http://127.0.0.1:8080",
		":8080":          "http://127.0.0.1:8080",
		"127.0.0.1:9999": "http://127.0.0.1:9999",
		"[::]:8080":      "http://127.0.0.1:8080",
		"8080":           "http://127.0.0.1:8080", // no colon → whole string is the port
	}
	for in, want := range cases {
		if got := loopbackAPIBaseURL(in); got != want {
			t.Errorf("loopbackAPIBaseURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRun_ConfigLoadFailureReturnsError(t *testing.T) {
	t.Setenv("SB_PAT_TOKEN", "") // config.Load rejects an empty PAT first.
	err := Run(context.Background(), testLogger(), nil)
	if err == nil {
		t.Fatalf("Run with empty SB_PAT_TOKEN = nil error, want failure")
	}
	if !strings.Contains(err.Error(), "load config") {
		t.Fatalf("Run error = %v, want it to wrap \"load config\"", err)
	}
}

// TestRun_StoreOpenFailureReturnsError: with a loadable config but an
// unopenable DB path (parent is a regular file, so store.Open's MkdirAll
// fails), Run must return the wrapped error. This exercises the store.Open
// boot-failure branch that previously called os.Exit(1).
func TestRun_StoreOpenFailureReturnsError(t *testing.T) {
	// A regular file standing where store.Open expects the DB's parent dir.
	parentAsFile := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(parentAsFile, []byte("x"), 0o600); err != nil {
		t.Fatalf("seed parent file: %v", err)
	}
	t.Setenv("SB_PAT_TOKEN", "test-token")
	t.Setenv("SB_PUBLIC_HOST", "localhost") // required when SB_DOMAIN is empty
	t.Setenv("SB_DB_PATH", filepath.Join(parentAsFile, "state.db"))

	err := Run(context.Background(), testLogger(), nil)
	if err == nil {
		t.Fatalf("Run with unopenable DB path = nil error, want failure")
	}
	if !strings.Contains(err.Error(), "open store") {
		t.Fatalf("Run error = %v, want it to wrap \"open store\"", err)
	}
}

// TestRun_ProviderFactoryErrorReturnsError: a makeProvider that fails must
// abort boot with a wrapped error before any infrastructure is opened.
func TestRun_ProviderFactoryErrorReturnsError(t *testing.T) {
	t.Setenv("SB_PAT_TOKEN", "test-token")
	t.Setenv("SB_PUBLIC_HOST", "localhost")
	t.Setenv("SB_DB_PATH", filepath.Join(t.TempDir(), "state.db"))

	boom := func(context.Context, FleetConfig) (controlplane.Provider, error) {
		return controlplane.Provider{}, errors.New("provider boom")
	}
	err := Run(context.Background(), testLogger(), boom)
	if err == nil {
		t.Fatalf("Run with failing provider factory = nil error, want failure")
	}
	if !strings.Contains(err.Error(), "control plane provider") {
		t.Fatalf("Run error = %v, want it to wrap \"control plane provider\"", err)
	}
}

func TestRun_GracefulShutdown(t *testing.T) {
	t.Setenv("SB_PAT_TOKEN", "test-token")
	t.Setenv("SB_PUBLIC_HOST", "localhost")
	statePath := filepath.Join(t.TempDir(), "state.db")
	t.Setenv("SB_DB_PATH", statePath)
	t.Setenv("SB_TOOLBOX_BINARY_PATH", "/bin/true")
	mountsRoot := t.TempDir()
	t.Setenv("SB_MOUNTS_ROOT", mountsRoot)
	t.Setenv("SB_MOUNTS_CRED_DIR", filepath.Join(mountsRoot, "creds"))
	t.Setenv("SB_SSH_HOST_KEY_PATH", filepath.Join(t.TempDir(), "ssh_host_ed25519_key"))
	t.Setenv("SB_LISTEN_ADDR", "127.0.0.1:0")
	// Allow config to default to single-node mixed mode when cluster is disabled.
	t.Setenv("SB_ENABLE_CLUSTER", "false")
	t.Setenv("SB_ENABLE_FIRECRACKER", "false")
	t.Setenv("SB_ENABLE_WASM", "false")
	t.Setenv("SB_ENABLE_CADDY", "false")
	t.Setenv("SB_CREDENTIAL_ENCRYPTION_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, testLogger(), nil)
	}()
	time.Sleep(100 * time.Millisecond)
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
}

type domainStubCluster struct {
	*cluster.Noop
	hosts map[string]string
}

func (d *domainStubCluster) ResolveCustomDomain(hostname string) (string, bool) {
	id, ok := d.hosts[hostname]
	return id, ok
}

func TestClusterAwareDomainResolver_ClusterAndStore(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID: "sb-domain", Image: "alpine:3.20", Status: models.SandboxStatusStarted,
		Runtime: models.RuntimeDocker, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := st.AddCustomDomain(ctx, "sb-domain", "store.example", 0); err != nil {
		t.Fatalf("AddCustomDomain: %v", err)
	}

	clusterHit := &domainStubCluster{
		Noop:  cluster.NewNoop("node-a", "http://node-a", ""),
		hosts: map[string]string{"cluster.example": "sb-cluster"},
	}
	resolver := clusterAwareDomainResolver{cluster: clusterHit, store: st}

	id, err := resolver.ResolveCustomDomain(ctx, "cluster.example")
	if err != nil || id != "sb-cluster" {
		t.Fatalf("cluster resolve = (%q, %v), want sb-cluster", id, err)
	}
	id, err = resolver.ResolveCustomDomain(ctx, "store.example")
	if err != nil || id != "sb-domain" {
		t.Fatalf("store resolve = (%q, %v), want sb-domain", id, err)
	}
}

// TestConfigureMirror walks every branch: the disabled early-return, the
// no-wrap-key-path info path, the unreadable-wrap-key warn path, and the
// successful ring load. None of these talk to Docker — ConfigureMirror just
// stores the policy on the client — so we only need it not to panic.
func TestConfigureMirror(t *testing.T) {
	logger := testLogger()
	upstreams := []config.MirrorUpstreamMapping{{Host: "docker.io", Shortname: "dockerhub"}}

	t.Run("disabled_when_host_empty", func(t *testing.T) {
		configureMirror(logger, config.Config{MirrorHost: "", MirrorUpstreams: upstreams}, newTestDockerClient(t))
	})

	t.Run("disabled_when_upstreams_empty", func(t *testing.T) {
		configureMirror(logger, config.Config{MirrorHost: "mirror.example", MirrorUpstreams: nil}, newTestDockerClient(t))
	})

	t.Run("no_wrap_key_path", func(t *testing.T) {
		configureMirror(logger, config.Config{
			MirrorHost:      "mirror.example",
			MirrorPushHost:  "push.example",
			MirrorUpstreams: upstreams,
		}, newTestDockerClient(t))
	})

	t.Run("wrap_key_path_unreadable", func(t *testing.T) {
		configureMirror(logger, config.Config{
			MirrorHost:          "mirror.example",
			MirrorUpstreams:     upstreams,
			UpstreamWrapKeyPath: filepath.Join(t.TempDir(), "missing.key"),
		}, newTestDockerClient(t))
	})

	t.Run("wrap_key_path_loads", func(t *testing.T) {
		configureMirror(logger, config.Config{
			MirrorHost:          "mirror.example",
			MirrorUpstreams:     upstreams,
			UpstreamWrapKeyPath: writeWrapKeyFile(t),
		}, newTestDockerClient(t))
	})
}

// TestReplayClusterOwnership_NoCluster: with cluster mode off,
// assertClusterOwnership short-circuits to (0, nil), so replay reports
// success with nothing replayed.
func TestReplayClusterOwnership_NoCluster(t *testing.T) {
	st := openTestStore(t)
	svc := service.New(config.Config{}, testLogger(), st, nil, nil, nil, nil, nil, nil)
	if !replayClusterOwnership(context.Background(), svc, testLogger()) {
		t.Fatalf("replayClusterOwnership() = false, want true on the no-op cluster path")
	}
}

// TestReplayClusterOwnership_CountReported: a worker with cluster mode on and
// a local sandbox the FSM doesn't know about must replay it (count > 0),
// exercising the Info-log branch. Noop.AssertOwnership is a no-op so the
// replay "succeeds" without a real raft.
func TestReplayClusterOwnership_CountReported(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	svc := service.New(config.Config{EnableCluster: true}, testLogger(), st, nil, nil, nil, nil, nil, nil)
	svc.AttachCluster(cluster.NewNoop("node-a", "http://node-a", ""))

	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID:        "sb-replay",
		Image:     "alpine:3.20",
		Status:    models.SandboxStatusStarted,
		Runtime:   models.RuntimeDocker,
		CreatedAt: now,
		UpdatedAt: now,
	}); err != nil {
		t.Fatalf("store.Create: %v", err)
	}

	if !replayClusterOwnership(ctx, svc, testLogger()) {
		t.Fatalf("replayClusterOwnership() = false, want true")
	}
}

// TestReplayClusterOwnership_StoreError: a failed store.List must surface as
// replay failure (false) so the caller schedules the retry loop.
func TestReplayClusterOwnership_StoreError(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	svc := service.New(config.Config{EnableCluster: true}, testLogger(), st, nil, nil, nil, nil, nil, nil)
	svc.AttachCluster(cluster.NewNoop("node-a", "http://node-a", ""))
	// Closing the DB makes the subsequent List fail inside
	// ReplayClusterOwnership.
	_ = st.Close()

	if replayClusterOwnership(context.Background(), svc, testLogger()) {
		t.Fatalf("replayClusterOwnership() = true, want false after store close")
	}
}

// TestStartClusterOwnershipReplayRetry_StopsOnCtxCancel: the retry goroutine
// must return when its context is cancelled rather than ticking forever.
// t.Context() is cancelled at test cleanup, which is what unblocks the
// goroutine's <-ctx.Done() case.
func TestStartClusterOwnershipReplayRetry_StopsOnCtxCancel(t *testing.T) {
	st := openTestStore(t)
	svc := service.New(config.Config{}, testLogger(), st, nil, nil, nil, nil, nil, nil)
	startClusterOwnershipReplayRetry(t.Context(), svc, testLogger())
	// No observable signal; the test passing means the call didn't block
	// or panic, and cleanup-time ctx cancellation stops the goroutine.
}

func TestStartClusterOwnershipReplayRetry_SucceedsOnTick(t *testing.T) {
	oldTick := clusterOwnershipReplayTick
	clusterOwnershipReplayTick = 5 * time.Millisecond
	t.Cleanup(func() { clusterOwnershipReplayTick = oldTick })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	st := openTestStore(t)
	svc := service.New(config.Config{EnableCluster: true}, testLogger(), st, nil, nil, nil, nil, nil, nil)
	svc.AttachCluster(cluster.NewNoop("node-a", "http://node-a", ""))

	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID: "sb-retry", Image: "alpine:3.20", Status: models.SandboxStatusStarted,
		Runtime: models.RuntimeDocker, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("store.Create: %v", err)
	}

	startClusterOwnershipReplayRetry(ctx, svc, testLogger())
	// First tick replays ownership successfully and the goroutine exits.
	time.Sleep(30 * time.Millisecond)
	cancel()
	time.Sleep(20 * time.Millisecond)
}

func TestStartClusterOwnershipReplayRetry_RetriesOnFailure(t *testing.T) {
	oldTick := clusterOwnershipReplayTick
	clusterOwnershipReplayTick = 5 * time.Millisecond
	t.Cleanup(func() { clusterOwnershipReplayTick = oldTick })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	svc := service.New(config.Config{EnableCluster: true}, testLogger(), st, nil, nil, nil, nil, nil, nil)
	svc.AttachCluster(cluster.NewNoop("node-a", "http://node-a", ""))
	_ = st.Close()

	startClusterOwnershipReplayRetry(ctx, svc, testLogger())
	time.Sleep(25 * time.Millisecond)
	cancel()
	time.Sleep(20 * time.Millisecond)
}

// TestStartAutoImportReconciler_PATUnreadable: enabled but the PAT file is
// missing — the feature logs and stays off without scheduling a goroutine.
func TestStartAutoImportReconciler_PATUnreadable(t *testing.T) {
	st := openTestStore(t)
	svc := service.New(config.Config{}, testLogger(), st, nil, nil, nil, nil, nil, nil)
	startAutoImportReconciler(t.Context(), testLogger(), config.Config{
		AutoImportEnabled:        true,
		AutoImportClusterPATPath: filepath.Join(t.TempDir(), "missing-pat"),
	}, st, svc)
}

// TestStartAutoImportReconciler_Enabled: a readable PAT plus a valid config
// builds the importer + reconciler and starts the ticker goroutine. The
// interval is shrunk so one empty sweep fires (Scanned == 0 → continue)
// before t.Context() cancellation stops the loop at cleanup.
func TestStartAutoImportReconciler_Enabled(t *testing.T) {
	st := openTestStore(t)
	svc := service.New(config.Config{}, testLogger(), st, nil, nil, nil, nil, nil, nil)

	patPath := filepath.Join(t.TempDir(), "pat")
	if err := os.WriteFile(patPath, []byte("cluster-pat-token\n"), 0o600); err != nil {
		t.Fatalf("write pat: %v", err)
	}

	startAutoImportReconciler(t.Context(), testLogger(), config.Config{
		AutoImportEnabled:           true,
		AutoImportClusterPATPath:    patPath,
		AutoImportHooksBaseURL:      "https://hooks.example",
		AutoImportClusterID:         "cluster-1",
		AutoImportReconcileInterval: 5 * time.Millisecond,
		AutoImportMaxInFlight:       2,
	}, st, svc)
	time.Sleep(40 * time.Millisecond)
}

// TestStartSnapshotPushReconciler_Enabled: a valid push config builds the
// pusher + reconciler and drives one empty sweep through the goroutine.
func TestStartSnapshotPushReconciler_Enabled(t *testing.T) {
	st := openTestStore(t)
	svc := service.New(config.Config{}, testLogger(), st, nil, nil, nil, nil, nil, nil)
	dc := newTestDockerClient(t)

	patPath := filepath.Join(t.TempDir(), "pat")
	if err := os.WriteFile(patPath, []byte("cluster-pat\n"), 0o600); err != nil {
		t.Fatalf("write pat: %v", err)
	}
	startSnapshotPushReconciler(t.Context(), testLogger(), config.Config{
		SnapshotPushEnabled:           true,
		MirrorPushHost:                "push.example",
		AutoImportClusterID:           "cluster-1",
		AutoImportClusterPATPath:      patPath,
		SnapshotPushReconcileInterval: 5 * time.Millisecond,
		SnapshotPushMaxInFlight:       1,
	}, st, svc, dc)
	time.Sleep(40 * time.Millisecond)
}

// TestStartSnapshotPushReconciler_HostFallback: with MirrorPushHost unset the
// reconciler falls back to ImageDistributionAOCRHost.
func TestStartSnapshotPushReconciler_HostFallback(t *testing.T) {
	st := openTestStore(t)
	svc := service.New(config.Config{}, testLogger(), st, nil, nil, nil, nil, nil, nil)
	dc := newTestDockerClient(t)

	startSnapshotPushReconciler(t.Context(), testLogger(), config.Config{
		SnapshotPushEnabled:           true,
		MirrorPushHost:                "",
		ImageDistributionAOCRHost:     "aocr.example",
		AutoImportClusterID:           "cluster-1",
		AutoImportClusterPATPath:      filepath.Join(t.TempDir(), "pat"),
		SnapshotPushReconcileInterval: time.Hour,
		SnapshotPushMaxInFlight:       1,
	}, st, svc, dc)
}

// TestStartTemplateRotationReconciler_Enabled: firecracker on with both a
// rotation interval and a max-age builds the reconciler and starts its
// ticker.
func TestStartTemplateRotationReconciler_Enabled(t *testing.T) {
	st := openTestStore(t)
	svc := service.New(config.Config{}, testLogger(), st, nil, nil, nil, nil, nil, nil)

	startTemplateRotationReconciler(t.Context(), testLogger(), config.Config{
		EnableFirecracker:                   true,
		FirecrackerTemplateRotationInterval: 5 * time.Millisecond,
		FirecrackerTemplateMaxAge:           24 * time.Hour,
	}, st, svc)
	time.Sleep(40 * time.Millisecond)
}

// TestAttachTemplateArtifactPuller_Enabled: firecracker on with a templates
// dir set wires the puller onto the service.
func TestAttachTemplateArtifactPuller_Enabled(t *testing.T) {
	st := openTestStore(t)
	svc := service.New(config.Config{}, testLogger(), st, nil, nil, nil, nil, nil, nil)
	dc := newTestDockerClient(t)

	attachTemplateArtifactPuller(testLogger(), config.Config{
		EnableFirecracker:       true,
		FirecrackerTemplatesDir: t.TempDir(),
	}, svc, dc)
}

// TestStartTemplateArtifactPushReconciler_Enabled: firecracker + snapshot
// push on builds the template-artifact pusher and schedules its sweep.
func TestStartTemplateArtifactPushReconciler_Enabled(t *testing.T) {
	st := openTestStore(t)
	svc := service.New(config.Config{}, testLogger(), st, nil, nil, nil, nil, nil, nil)
	dc := newTestDockerClient(t)

	startTemplateArtifactPushReconciler(t.Context(), testLogger(), config.Config{
		EnableFirecracker:             true,
		SnapshotPushEnabled:           true,
		MirrorPushHost:                "push.example",
		AutoImportClusterID:           "cluster-1",
		AutoImportClusterPATPath:      filepath.Join(t.TempDir(), "pat"),
		FirecrackerTemplatesDir:       t.TempDir(),
		SnapshotPushReconcileInterval: 5 * time.Millisecond,
		SnapshotPushMaxInFlight:       1,
	}, st, svc, dc)
	time.Sleep(40 * time.Millisecond)
}

// TestStartTemplateArtifactPushReconciler_HostFallback: MirrorPushHost unset
// falls back to ImageDistributionAOCRHost on the template push side too.
func TestStartTemplateArtifactPushReconciler_HostFallback(t *testing.T) {
	st := openTestStore(t)
	svc := service.New(config.Config{}, testLogger(), st, nil, nil, nil, nil, nil, nil)
	dc := newTestDockerClient(t)

	startTemplateArtifactPushReconciler(t.Context(), testLogger(), config.Config{
		EnableFirecracker:             true,
		SnapshotPushEnabled:           true,
		MirrorPushHost:                "",
		ImageDistributionAOCRHost:     "aocr.example",
		AutoImportClusterID:           "cluster-1",
		AutoImportClusterPATPath:      filepath.Join(t.TempDir(), "pat"),
		FirecrackerTemplatesDir:       t.TempDir(),
		SnapshotPushReconcileInterval: time.Hour,
		SnapshotPushMaxInFlight:       1,
	}, st, svc, dc)
}

// TestGetSandboxSpec_NilCluster: a service with no cluster attached returns
// (nil, false) through the defensive nil guard rather than panicking.
func TestGetSandboxSpec_NilCluster(t *testing.T) {
	svc := service.New(config.Config{}, testLogger(), nil, nil, nil, nil, nil, nil, nil)
	resolver := autoImportSpecResolver{svc: svc}
	if spec, ok := resolver.GetSandboxSpec("anything"); ok || spec != nil {
		t.Fatalf("GetSandboxSpec on nil cluster = (%+v, %v), want (nil, false)", spec, ok)
	}
}

// TestWriteBypassMarker_WriteError: a marker path inside a non-existent
// directory makes the tmp write fail, surfacing the error rather than
// silently succeeding.
func TestWriteBypassMarker_WriteError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "no-such-dir", "bypass_last_enabled")
	if err := writeBypassMarker(path, true); err == nil {
		t.Fatalf("writeBypassMarker into missing dir = nil, want error")
	}
}

// TestFirecrackerPoolAdapter_AllocateError: an unseeded pool has no free
// slots, so Allocate surfaces the pool error through the adapter.
func TestFirecrackerPoolAdapter_AllocateError(t *testing.T) {
	st := openTestStore(t)
	adapter := &firecrackerPoolAdapter{inner: tap.New(st)}
	if _, err := adapter.Allocate(context.Background(), "sb-x", time.Now()); err == nil {
		t.Fatalf("Allocate on unseeded pool = nil error, want error")
	}
}

// TestFirecrackerCIDAllocatorAdapter_AllocateError: same exhaustion path
// through the template CID allocator.
func TestFirecrackerCIDAllocatorAdapter_AllocateError(t *testing.T) {
	st := openTestStore(t)
	a := &firecrackerCIDAllocatorAdapter{pool: tap.New(st)}
	if _, err := a.AllocateForTemplate(context.Background(), "tpl-x"); err == nil {
		t.Fatalf("AllocateForTemplate on unseeded pool = nil error, want error")
	}
}

// TestVMMTemplateListerAdapter_ListError: a closed store makes ListTemplates
// fail, which the adapter propagates.
func TestVMMTemplateListerAdapter_ListError(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	svc := service.New(config.Config{}, testLogger(), st, nil, nil, nil, nil, nil, nil)
	_ = st.Close()
	a := &vmmTemplateListerAdapter{svc: svc}
	if _, err := a.ListWarmableTemplates(context.Background()); err == nil {
		t.Fatalf("ListWarmableTemplates with closed store = nil error, want error")
	}
}

// TestFirecrackerRootfsAdapter_BuildError: the OCI builder's first stage
// (skopeo) fails immediately when pointed at /bin/false, so the adapter
// returns the wrapped error rather than a result.
func TestFirecrackerRootfsAdapter_BuildError(t *testing.T) {
	builder, err := oci.New(oci.Config{
		SkopeoBin: "/bin/false",
		UmociBin:  "/bin/false",
		Mkfs4Bin:  "/bin/false",
		WorkDir:   t.TempDir(),
	})
	if err != nil {
		t.Fatalf("oci.New: %v", err)
	}
	a := &firecrackerRootfsAdapter{inner: builder}
	if _, err := a.Build(context.Background(), fcruntime.RootfsBuildRequest{
		ImageRef: "docker://alpine:3.20",
		OutPath:  filepath.Join(t.TempDir(), "rootfs.ext4"),
	}); err == nil {
		t.Fatalf("Build with failing skopeo = nil error, want error")
	}
}

// TestTemplateBuilderAdapter_BuildError: the template-build adapter shares the
// OCI builder, so the same failing-skopeo path surfaces an error.
func TestTemplateBuilderAdapter_BuildError(t *testing.T) {
	builder, err := oci.New(oci.Config{
		SkopeoBin: "/bin/false",
		UmociBin:  "/bin/false",
		Mkfs4Bin:  "/bin/false",
		WorkDir:   t.TempDir(),
	})
	if err != nil {
		t.Fatalf("oci.New: %v", err)
	}
	a := &templateBuilderAdapter{inner: builder}
	if _, err := a.Build(context.Background(), service.TemplateBuildRequest{
		ImageRef: "docker://alpine:3.20",
		OutPath:  filepath.Join(t.TempDir(), "rootfs.ext4"),
	}); err == nil {
		t.Fatalf("Build with failing skopeo = nil error, want error")
	}
}

// TestFirecrackerTapHostAdapter_EnsureRemove: pointing tap.Host at a
// non-existent ip(8) binary makes both Ensure and Remove fail, covering the
// adapter's one-line forwarders regardless of host platform.
func TestFirecrackerTapHostAdapter_EnsureRemove(t *testing.T) {
	a := &firecrackerTapHostAdapter{inner: tap.NewHost("/nonexistent/ip")}
	if err := a.Ensure(context.Background(), fcruntime.TapSlot{
		TapName: "fctap0", CIDR: "172.16.0.0/30", HostIP: "172.16.0.1", GuestIP: "172.16.0.2", VsockCID: 33,
	}); err == nil {
		t.Fatalf("Ensure with bogus ip binary = nil error, want error")
	}
	if err := a.Remove(context.Background(), "fctap0"); err == nil {
		t.Fatalf("Remove with bogus ip binary = nil error, want error")
	}
}

// TestFirecrackerTemplateSnapshotterAdapter_Error: a bare driver with no TAP
// pool registered fails the snapshot preconditions, so the adapter returns
// the error from the driver.
func TestFirecrackerTemplateSnapshotterAdapter_Error(t *testing.T) {
	driver := fcruntime.New(fcruntime.FromDaemonConfig(config.Config{}), testLogger())
	a := &firecrackerTemplateSnapshotterAdapter{driver: driver}
	if _, err := a.SnapshotTemplate(context.Background(), service.TemplateSnapshotRequest{
		TemplateID:    "tpl-x",
		RootfsPath:    "/tmp/rootfs.ext4",
		OutMemoryPath: "/tmp/snap.mem",
		OutStatePath:  "/tmp/snap.state",
		GuestCID:      33,
		MemoryMB:      256,
		VCPU:          1,
	}); err == nil {
		t.Fatalf("SnapshotTemplate without registered pool = nil error, want error")
	}
}
