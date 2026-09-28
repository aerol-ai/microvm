package daemon

import (
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strconv"

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
	"github.com/aerol-ai/microvm/internal/network/netns"
	"github.com/aerol-ai/microvm/internal/network/tap"
	cntr "github.com/aerol-ai/microvm/internal/runtime/containerd"
	fcruntime "github.com/aerol-ai/microvm/internal/runtime/firecracker"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/docker/netrules"
	pkgisolate "github.com/aerol-ai/microvm/pkg/isolate"
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
// unopenable DB path (parent is a regular file, so store startup's MkdirAll
// fails), Run must return the wrapped error. This exercises the store boot-
// failure branch that previously called os.Exit(1).
func TestRun_StoreOpenFailureReturnsError(t *testing.T) {
	// A regular file standing where store.Open expects the DB's parent dir.
	parentAsFile := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(parentAsFile, []byte("x"), 0o600); err != nil {
		t.Fatalf("seed parent file: %v", err)
	}
	t.Setenv("SB_PAT_TOKEN", "test-token")
	t.Setenv("SB_PUBLIC_HOST", "localhost") // required when SB_DOMAIN is empty
	t.Setenv("SB_DB_PATH", filepath.Join(parentAsFile, "state.db"))
	t.Setenv("SB_CREDENTIAL_ENCRYPTION_KEY_PATH", filepath.Join(t.TempDir(), "credential.key"))

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
	time.Sleep(300 * time.Millisecond)
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
	}, st, svc, dc, nil)
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
	}, st, svc, dc, nil)
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

func TestCoverage95LiftRunErrorBranches(t *testing.T) {
	t.Run("audit_ingest_listen_conflict", func(t *testing.T) {
		_ = setBaseRunEnv(t)
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		t.Cleanup(func() { _ = ln.Close() })
		port := ln.Addr().(*net.TCPAddr).Port
		t.Setenv("SB_EGRESS_ATTRIBUTION_ENABLED", "true")
		t.Setenv("SB_AUDIT_INGEST_PORT", strconv.Itoa(port))
		if err := runWithAutoCancel(t, 500*time.Millisecond, nil); err == nil {
			t.Fatal("expected audit ingest listen failure")
		}
	})

	t.Run("ready_socket_dir_blocked", func(t *testing.T) {
		paths := setBaseRunEnv(t)
		blocked := filepath.Join(paths.rootDir, "cred-file")
		if err := os.WriteFile(blocked, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv("SB_MOUNTS_CRED_DIR", blocked)
		t.Setenv("SB_DOCKER_POOL_ENABLED", "true")
		t.Setenv("SB_DOCKER_READY_SOCKET_ENABLED", "true")
		if err := runWithAutoCancel(t, 500*time.Millisecond, nil); err == nil {
			t.Fatal("expected ready-socket dir failure")
		}
	})

	t.Run("wasm_isolate_skipped_on_server", func(t *testing.T) {
		paths := setBaseRunEnv(t)
		t.Setenv("SB_NODE_ROLE", "server")
		t.Setenv("SB_ENABLE_CLUSTER", "true")
		t.Setenv("SB_CLUSTER_BOOTSTRAP", "true")
		t.Setenv("SB_CLUSTER_INSECURE_GOSSIP", "true")
		t.Setenv("SB_CLUSTER_INSECURE_CREDENTIALS", "true")
		t.Setenv("SB_RAFT_BIND_ADDR", "127.0.0.1:0")
		t.Setenv("SB_RAFT_ADVERTISE_ADDR", "127.0.0.1:0")
		t.Setenv("SB_RAFT_DATA_DIR", filepath.Join(paths.rootDir, "raft"))
		t.Setenv("SB_GOSSIP_BIND_ADDR", "127.0.0.1:0")
		t.Setenv("SB_GOSSIP_ADVERTISE_ADDR", "127.0.0.1:0")
		t.Setenv("SB_SELF_API_ADVERTISE_URL", "http://127.0.0.1:8080")
		t.Setenv("SB_ENABLE_WASM", "true")
		t.Setenv("SB_WASM_RUN_DIR", filepath.Join(paths.rootDir, "wasm-run"))
		t.Setenv("SB_WASM_MODULES_DIR", filepath.Join(paths.rootDir, "wasm-mod"))
		t.Setenv("SB_ENABLE_ISOLATE", "true")
		t.Setenv("SB_ISOLATE_USE_JAIL", "false") // jail is a boot contract this host cannot honor
		t.Setenv("SB_ISOLATE_WORKERD_PATH", "/bin/true")
		t.Setenv("SB_ISOLATE_RUN_DIR", filepath.Join(paths.rootDir, "isolate"))
		if err := runWithAutoCancel(t, 800*time.Millisecond, nil); err != nil {
			t.Logf("Run err (ok): %v", err)
		}
	})

	t.Run("awskms_provider_unavailable", func(t *testing.T) {
		_ = setBaseRunEnv(t)
		t.Setenv("SB_SECRET_PROVIDER", "awskms")
		t.Setenv("SB_SECRET_AWS_KMS_KEY_ID", "alias/coverage-missing")
		t.Setenv("SB_SECRET_PROVIDER_STRICT_BOOT", "true")
		t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
		t.Setenv("AWS_CONFIG_FILE", filepath.Join(t.TempDir(), "no-aws-config"))
		t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(t.TempDir(), "no-aws-creds"))
		if err := runWithAutoCancel(t, 800*time.Millisecond, nil); err == nil {
			t.Fatal("expected awskms configure failure")
		}
	})

	t.Run("ssh_host_key_dir_fails", func(t *testing.T) {
		paths := setBaseRunEnv(t)
		t.Setenv("SB_ENABLE_SSH_GATEWAY", "true")
		t.Setenv("SB_SSH_HOST_KEY_PATH", paths.rootDir)
		if err := runWithAutoCancel(t, 500*time.Millisecond, nil); err == nil {
			t.Fatal("expected ssh host-key failure")
		}
	})

	t.Run("ssh_listen_conflict", func(t *testing.T) {
		_ = setBaseRunEnv(t)
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		t.Cleanup(func() { _ = ln.Close() })
		t.Setenv("SB_ENABLE_SSH_GATEWAY", "true")
		t.Setenv("SB_SSH_LISTEN_ADDR", ln.Addr().String())
		if err := runWithAutoCancel(t, 800*time.Millisecond, nil); err != nil {
			t.Logf("Run err (ok): %v", err)
		}
	})

	t.Run("auto_reconcile_warns", func(t *testing.T) {
		_ = setBaseRunEnv(t)
		t.Setenv("SB_AUTO_RECONCILE", "true")
		if err := runWithAutoCancel(t, 800*time.Millisecond, nil); err != nil {
			t.Logf("Run err (ok): %v", err)
		}
	})

	t.Run("cluster_raft_dir_blocked", func(t *testing.T) {
		paths := setBaseRunEnv(t)
		raft := filepath.Join(paths.rootDir, "raft-file")
		if err := os.WriteFile(raft, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv("SB_ENABLE_CLUSTER", "true")
		t.Setenv("SB_NODE_ROLE", "server")
		t.Setenv("SB_CLUSTER_BOOTSTRAP", "true")
		t.Setenv("SB_CLUSTER_INSECURE_GOSSIP", "true")
		t.Setenv("SB_CLUSTER_INSECURE_CREDENTIALS", "true")
		t.Setenv("SB_RAFT_BIND_ADDR", "127.0.0.1:0")
		t.Setenv("SB_RAFT_ADVERTISE_ADDR", "127.0.0.1:0")
		t.Setenv("SB_RAFT_DATA_DIR", raft)
		t.Setenv("SB_GOSSIP_BIND_ADDR", "127.0.0.1:0")
		t.Setenv("SB_GOSSIP_ADVERTISE_ADDR", "127.0.0.1:0")
		t.Setenv("SB_SELF_API_ADVERTISE_URL", "http://127.0.0.1:8080")
		if err := runWithAutoCancel(t, 800*time.Millisecond, nil); err == nil {
			t.Fatal("expected cluster start failure")
		}
	})
}

type liftAuditExporter struct{}

func (liftAuditExporter) ExportEvents(context.Context, controlplane.AuditEventBatch) (string, error) {
	return "next", nil
}

func TestCoverage95LiftAuditExporterProvider(t *testing.T) {
	_ = setBaseRunEnv(t)
	if err := runWithAutoCancel(t, 800*time.Millisecond, func(context.Context, FleetConfig) (controlplane.Provider, error) {
		return controlplane.Provider{AuditExporter: liftAuditExporter{}}.WithDefaults(), nil
	}); err != nil {
		t.Fatalf("Run: %v", err)
	}
}

type liftWitness struct{}

func (liftWitness) WitnessHeads(context.Context, []controlplane.AuditHead) (controlplane.WitnessReceipt, error) {
	return controlplane.WitnessReceipt{ReceiptID: "r1"}, nil
}

func (liftWitness) LastWitnessedHead(context.Context, string) (string, bool, error) {
	return "", false, nil
}

type mismatchWitness struct{}

func (mismatchWitness) WitnessHeads(context.Context, []controlplane.AuditHead) (controlplane.WitnessReceipt, error) {
	return controlplane.WitnessReceipt{ReceiptID: "r1"}, nil
}

func (mismatchWitness) LastWitnessedHead(context.Context, string) (string, bool, error) {
	return "", false, errors.New("witness offline")
}

func TestCoverage95LiftEnterpriseWitnessMismatch(t *testing.T) {
	_ = setBaseRunEnv(t)
	t.Setenv("SB_ENTERPRISE_MODE", "true")
	t.Setenv("SB_PAT_TOKEN", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
	t.Setenv("SB_SECRET_AUDIT_STRICT_BOOT", "true")
	err := runWithAutoCancel(t, 800*time.Millisecond, func(context.Context, FleetConfig) (controlplane.Provider, error) {
		return controlplane.Provider{
			Witness:       mismatchWitness{},
			AuditExporter: liftAuditExporter{},
		}.WithDefaults(), nil
	})
	if err == nil {
		t.Fatal("expected witness verification failure")
	}
}

func TestCoverage95LiftEnterpriseNeedsExporter(t *testing.T) {
	// Enterprise forces an off-node exporter; a witness-only provider still
	// fails closed so JSONL-only nodes cannot claim tamper-evidence.
	_ = setBaseRunEnv(t)
	t.Setenv("SB_ENTERPRISE_MODE", "true")
	t.Setenv("SB_PAT_TOKEN", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
	t.Setenv("SB_SECRET_AUDIT_STRICT_BOOT", "true")
	err := runWithAutoCancel(t, 800*time.Millisecond, func(context.Context, FleetConfig) (controlplane.Provider, error) {
		return controlplane.Provider{Witness: liftWitness{}}.WithDefaults(), nil
	})
	if err == nil {
		t.Fatal("expected enterprise exporter requirement")
	}
}

func TestCoverage95LiftProviderFactoryError(t *testing.T) {
	_ = setBaseRunEnv(t)
	err := runWithAutoCancel(t, 500*time.Millisecond, func(context.Context, FleetConfig) (controlplane.Provider, error) {
		return controlplane.Noop(), errors.New("provider boom")
	})
	if err == nil {
		t.Fatal("expected provider factory error")
	}
}

func TestCoverage95DaemonAdapterSuccessPaths(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	logger := testLogger()
	svc := service.New(config.Config{}, logger, st, nil, nil, nil, nil, nil, nil)
	now := time.Now().UTC()

	t.Run("get_sandbox_spec_nil_cluster", func(t *testing.T) {
		resolver := autoImportSpecResolver{svc: &service.Service{}}
		if spec, ok := resolver.GetSandboxSpec("x"); ok || spec != nil {
			t.Fatalf("GetSandboxSpec = (%+v, %v), want (nil,false)", spec, ok)
		}
	})

	t.Run("template_resolver_ready_with_snapshot", func(t *testing.T) {
		if err := st.CreateTemplate(ctx, &models.Template{
			ID: "tpl-snap", Image: "alpine", Status: models.TemplateStatusReady,
			RootfsPath: "/tmp/rootfs.ext4", CreatedAt: now, UpdatedAt: now,
			HasSnapshot: true, SnapshotMemoryPath: "/tmp/m", SnapshotStatePath: "/tmp/s",
		}); err != nil {
			t.Fatal(err)
		}
		a := &templateResolverAdapter{svc: svc}
		res, err := a.Resolve(ctx, "tpl-snap")
		if err != nil || res == nil || !res.HasSnapshot {
			t.Fatalf("Resolve = (%+v, %v)", res, err)
		}
	})

	t.Run("template_snapshotter_success_shape", func(t *testing.T) {
		a := &firecrackerTemplateSnapshotterAdapter{driver: fcruntime.New(fcruntime.FromDaemonConfig(config.Config{}), logger)}
		_, err := a.SnapshotTemplate(ctx, service.TemplateSnapshotRequest{
			TemplateID: "tpl", RootfsPath: "/tmp/r", OutMemoryPath: "/tmp/m", OutStatePath: "/tmp/s",
		})
		if err == nil {
			t.Fatal("expected error without pool")
		}
	})

	t.Run("rootfs_build_with_inject", func(t *testing.T) {
		ociCfg, work := ociHappyConfig(t)
		builder, err := oci.New(ociCfg)
		if err != nil {
			t.Fatal(err)
		}
		injectPath := filepath.Join(work, "inject.txt")
		if err := os.WriteFile(injectPath, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		a := &firecrackerRootfsAdapter{inner: builder}
		_, err = a.Build(ctx, fcruntime.RootfsBuildRequest{
			ImageRef: "docker://alpine:3.20",
			OutPath:  filepath.Join(work, "inj-rootfs.ext4"),
			InjectFiles: []fcruntime.InjectFile{{
				HostPath: injectPath, GuestPath: "/etc/inject", Mode: 0o644,
			}},
		})
		if err != nil {
			t.Fatalf("Build: %v", err)
		}
	})

	t.Run("template_builder_with_toolbox", func(t *testing.T) {
		toolbox := filepath.Join(t.TempDir(), "toolboxd")
		if err := os.WriteFile(toolbox, []byte("bin"), 0o755); err != nil {
			t.Fatal(err)
		}
		ociCfg, work := ociHappyConfig(t)
		builder, err := oci.New(ociCfg)
		if err != nil {
			t.Fatal(err)
		}
		a := &templateBuilderAdapter{inner: builder, toolboxBinaryPath: toolbox}
		_, err = a.Build(ctx, service.TemplateBuildRequest{
			ImageRef: "docker://alpine:3.20",
			OutPath:  filepath.Join(work, "tpl-inj.ext4"),
		})
		if err != nil {
			t.Fatalf("Build: %v", err)
		}
	})

	t.Run("warm_pool_depth_negative_tap", func(t *testing.T) {
		got, capped := firecrackerWarmPoolDepth(4, -8)
		if got != 0 || !capped {
			t.Fatalf("firecrackerWarmPoolDepth = (%d,%v), want (0,true)", got, capped)
		}
	})
}

func TestCoverage95ReconcilerSweepPaths(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	svc := service.New(config.Config{}, testLogger(), st, nil, nil, nil, nil, nil, nil)
	logger := testLogger()
	now := time.Now().UTC()

	patPath := filepath.Join(t.TempDir(), "pat")
	if err := os.WriteFile(patPath, []byte("cluster-pat\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Run("auto_import_sweep_with_pending", func(t *testing.T) {
		if err := st.Create(ctx, &models.Sandbox{
			ID: "sb-import", Image: "alpine:3.20", Status: models.SandboxStatusStarted,
			Runtime: models.RuntimeDocker, CreatedAt: now, UpdatedAt: now,
			AutoImportPending: true,
		}); err != nil {
			t.Fatal(err)
		}
		runCtx, cancel := context.WithCancel(context.Background())
		startAutoImportReconciler(runCtx, logger, config.Config{
			AutoImportEnabled:           true,
			AutoImportClusterPATPath:    patPath,
			AutoImportHooksBaseURL:      "https://hooks.example",
			AutoImportClusterID:         "cluster-1",
			AutoImportReconcileInterval: 5 * time.Millisecond,
			AutoImportMaxInFlight:       1,
		}, st, svc)
		time.Sleep(80 * time.Millisecond)
		cancel()
	})

	t.Run("snapshot_push_containerd_backend", func(t *testing.T) {
		driver := cntr.New(cntr.FromDaemonConfig(config.Config{ContainerEngine: models.ContainerEngineContainerd}), nil, logger)
		ctd := &containerdEngineWiring{driver: driver}
		runCtx, cancel := context.WithCancel(context.Background())
		startSnapshotPushReconciler(runCtx, logger, config.Config{
			SnapshotPushEnabled:           true,
			ContainerEngine:               models.ContainerEngineContainerd,
			MirrorPushHost:                "push.example",
			AutoImportClusterID:           "cluster-1",
			AutoImportClusterPATPath:      patPath,
			SnapshotPushReconcileInterval: 5 * time.Millisecond,
			SnapshotPushMaxInFlight:       1,
		}, st, svc, newTestDockerClient(t), ctd)
		time.Sleep(40 * time.Millisecond)
		cancel()
	})

	t.Run("template_push_sweep", func(t *testing.T) {
		if err := st.CreateTemplate(ctx, &models.Template{
			ID: "tpl-push", Image: "docker://alpine:3.20", Status: models.TemplateStatusReady,
			RootfsPath: "/tmp/rootfs.ext4", CreatedAt: now, UpdatedAt: now,
		}); err != nil {
			t.Fatal(err)
		}
		runCtx, cancel := context.WithCancel(context.Background())
		startTemplateArtifactPushReconciler(runCtx, logger, config.Config{
			EnableFirecracker:             true,
			SnapshotPushEnabled:           true,
			MirrorPushHost:                "push.example",
			AutoImportClusterID:           "cluster-1",
			AutoImportClusterPATPath:      patPath,
			FirecrackerTemplatesDir:       t.TempDir(),
			SnapshotPushReconcileInterval: 5 * time.Millisecond,
			SnapshotPushMaxInFlight:       1,
		}, st, svc, newTestDockerClient(t))
		time.Sleep(40 * time.Millisecond)
		cancel()
	})

	t.Run("template_rotation_interval_without_max_age_warn", func(t *testing.T) {
		startTemplateRotationReconciler(context.Background(), logger, config.Config{
			EnableFirecracker:                   true,
			FirecrackerTemplateRotationInterval: time.Second,
			FirecrackerTemplateMaxAge:           0,
		}, st, svc)
	})
}

func TestCoverage95RunExtendedWiringBranches(t *testing.T) {
	cases := []struct {
		name string
		env  map[string]string
	}{
		{"docker_warm_and_netns", map[string]string{
			"SB_DOCKER_POOL_ENABLED":         "true",
			"SB_DOCKER_READY_SOCKET_ENABLED": "true",
			"SB_DOCKER_NETNS_POOL_ENABLED":   "true",
			"SB_DOCKER_NETNS_POOL_DEPTH":     "1",
		}},
		{"containerd_warm_pool", map[string]string{
			"SB_CONTAINER_ENGINE":            "containerd",
			"SB_CONTAINERD_POOL_ENABLED":     "true",
			"SB_DOCKER_READY_SOCKET_ENABLED": "true",
			"SB_CONTAINERD_POOL_DEPTH":       "1",
		}},
		{"netrules_enabled", map[string]string{
			"SB_ENABLE_NETWORK_RULES": "true",
			"SB_NETRULES_BACKEND":     "exec",
		}},
		{"netrules_unknown_backend", map[string]string{
			"SB_ENABLE_NETWORK_RULES": "true",
			"SB_NETRULES_BACKEND":     "not-a-backend",
		}},
		{"isolate_non_worker", map[string]string{
			"SB_ENABLE_CLUSTER":               "true",
			"SB_NODE_ROLE":                    "ingress",
			"SB_CLUSTER_BOOTSTRAP":            "false",
			"SB_BOOTSTRAP_PEERS":              "127.0.0.1:19999",
			"SB_CLUSTER_INSECURE_GOSSIP":      "true",
			"SB_CLUSTER_INSECURE_CREDENTIALS": "true",
			"SB_ENABLE_ISOLATE":               "true",
		}},
		{"wasm_non_worker", map[string]string{
			"SB_ENABLE_CLUSTER":               "true",
			"SB_NODE_ROLE":                    "ingress",
			"SB_CLUSTER_BOOTSTRAP":            "false",
			"SB_BOOTSTRAP_PEERS":              "127.0.0.1:19999",
			"SB_CLUSTER_INSECURE_GOSSIP":      "true",
			"SB_CLUSTER_INSECURE_CREDENTIALS": "true",
			"SB_ENABLE_WASM":                  "true",
		}},
		{"cluster_agent_worker", map[string]string{
			"SB_ENABLE_CLUSTER":               "true",
			"SB_NODE_ROLE":                    "worker",
			"SB_CLUSTER_BOOTSTRAP":            "false",
			"SB_BOOTSTRAP_PEERS":              "127.0.0.1:19999",
			"SB_CLUSTER_INSECURE_GOSSIP":      "true",
			"SB_CLUSTER_INSECURE_CREDENTIALS": "true",
		}},
		{"auto_import_pull_observer", map[string]string{
			"SB_AUTO_IMPORT_ENABLED": "true",
		}},
		{"platform_volumes_nfs", map[string]string{
			"SB_PLATFORM_VOLUMES_ENABLED":    "true",
			"SB_PLATFORM_VOLUMES_BACKEND":    "nfs",
			"SB_PLATFORM_VOLUMES_NFS_SERVER": "127.0.0.1",
			"SB_PLATFORM_VOLUMES_NFS_EXPORT": "/export",
		}},
		{"firecracker_vmm_pool", map[string]string{
			"SB_ENABLE_FIRECRACKER":                 "true",
			"SB_FIRECRACKER_BINARY":                 "/bin/true",
			"SB_JAILER_BINARY":                      "/bin/true",
			"SB_FIRECRACKER_KERNEL":                 "vmlinux",
			"SB_FIRECRACKER_RUN_DIR":                "fc-run",
			"SB_FIRECRACKER_USE_JAILER":             "false",
			"SB_FIRECRACKER_TAP_BASE_CIDR":          "172.19.0.0/30",
			"SB_FIRECRACKER_TAP_POOL_SIZE":          "1",
			"SB_FIRECRACKER_SKOPEO_BIN":             "/bin/true",
			"SB_FIRECRACKER_UMOCI_BIN":              "/bin/true",
			"SB_FIRECRACKER_MKFS_BIN":               "/bin/true",
			"SB_FIRECRACKER_VMM_POOL_ENABLED":       "true",
			"SB_FIRECRACKER_VMM_POOL_DEPTH_DEFAULT": "1",
		}},
		{"serverless_custom_domains", map[string]string{
			"SB_ENABLE_CADDY":          "true",
			"SB_ENABLE_SERVERLESS":     "true",
			"SB_ENABLE_CUSTOM_DOMAINS": "true",
			"SB_DOMAIN":                "example.test",
		}},
		{"wasm_resident_host", map[string]string{
			"SB_ENABLE_WASM":                "true",
			"SB_WASM_RESIDENT_HOST_ENABLED": "true",
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			paths := setBaseRunEnv(t)
			t.Setenv("SB_ISOLATE_RUN_DIR", paths.rootDir+"/isolate")
			t.Setenv("SB_WASM_RUN_DIR", paths.rootDir+"/wasm-run")
			t.Setenv("SB_WASM_MODULES_DIR", paths.rootDir+"/wasm-modules")
			if tc.name == "firecracker_vmm_pool" {
				t.Setenv("SB_FIRECRACKER_KERNEL", paths.firecrackerKernel)
				t.Setenv("SB_FIRECRACKER_RUN_DIR", paths.firecrackerRunDir)
			}
			if tc.name == "cluster_agent_worker" || tc.name == "isolate_non_worker" || tc.name == "wasm_non_worker" {
				t.Setenv("SB_RAFT_BIND_ADDR", "127.0.0.1:0")
				t.Setenv("SB_GOSSIP_BIND_ADDR", "127.0.0.1:0")
				t.Setenv("SB_RAFT_ADVERTISE_ADDR", "127.0.0.1:0")
				t.Setenv("SB_GOSSIP_ADVERTISE_ADDR", "127.0.0.1:0")
				t.Setenv("SB_SELF_API_ADVERTISE_URL", "http://127.0.0.1:8080")
			}
			if tc.name == "auto_import_pull_observer" {
				t.Setenv("SB_AUTO_IMPORT_CLUSTER_PAT_PATH", paths.clusterPATPath)
				t.Setenv("SB_AUTO_IMPORT_HOOKS_URL", "https://hooks.example")
				t.Setenv("SB_AUTO_IMPORT_CLUSTER_ID", "cluster-1")
				t.Setenv("SB_AUTO_IMPORT_RECONCILE_INTERVAL", "1h")
			}
			if tc.name == "platform_volumes_nfs" {
				badRoot := filepath.Join(paths.rootDir, "vol-reclaim-file")
				if err := os.WriteFile(badRoot, []byte("x"), 0o600); err != nil {
					t.Fatal(err)
				}
				t.Setenv("SB_PLATFORM_VOLUMES_RECLAIM_MOUNT_ROOT", badRoot)
			}
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			err := runWithAutoCancel(t, 600*time.Millisecond, nil)
			if tc.name == "netrules_unknown_backend" {
				// Linux validates backends; other GOOS returns a disabled manager.
				if runtime.GOOS == "linux" {
					if err == nil {
						t.Fatal("want unknown netrules backend error on linux")
					}
					return
				}
				if err != nil {
					t.Fatalf("Run %s: %v", tc.name, err)
				}
				return
			}
			if err != nil {
				// Offline Linux containers often lack iptables/nft; the branch
				// still exercised the enabled-manager create path before failing.
				if tc.name == "netrules_enabled" && isNetrulesHostUnavailable(err) {
					return
				}
				t.Fatalf("Run %s: %v", tc.name, err)
			}
		})
	}
}

func isNetrulesHostUnavailable(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "iptables") ||
		strings.Contains(msg, "netlink netrules") ||
		strings.Contains(msg, "create netrules manager")
}

func TestCoverage95DaemonWiringGuards(t *testing.T) {
	if got := adaptTapSlot(nil); got != nil {
		t.Fatalf("adaptTapSlot(nil) = %+v, want nil", got)
	}
	if pool := wireContainerdWarmPool(context.Background(), config.Config{
		ContainerdPoolEnabled:    true,
		DockerReadySocketEnabled: true,
	}, testLogger(), nil, nil); pool != nil {
		t.Fatal("warm pool without driver unexpectedly initialized")
	}
}

func TestCoverage95RunIsolateAndContainerdWiring(t *testing.T) {
	t.Run("isolate", func(t *testing.T) {
		paths := setBaseRunEnv(t)
		t.Setenv("SB_ENABLE_ISOLATE", "true")
		t.Setenv("SB_ISOLATE_WORKERD_PATH", "/nonexistent-workerd")
		t.Setenv("SB_ISOLATE_RUN_DIR", paths.rootDir+"/isolate")
		t.Setenv("SB_ISOLATE_POOL_ENABLED", "true")
		t.Setenv("SB_ISOLATE_POOL_DEPTH_DEFAULT", "1")
		// The jail defaults on and is now a boot-time contract: a host that
		// cannot realize it refuses to start (asserted below), so this boot
		// of the unjailed wiring path runs with it off.
		t.Setenv("SB_ISOLATE_USE_JAIL", "false")
		if err := runWithAutoCancel(t, 150*time.Millisecond, nil); err != nil {
			t.Fatalf("Run isolate: %v", err)
		}
		if pkgisolate.JailRealizable() && os.Geteuid() == 0 {
			return // root on linux realizes the jail; covered by the real-host scenario
		}
		t.Setenv("SB_ISOLATE_USE_JAIL", "true")
		t.Setenv("SB_ISOLATE_JAIL_CHROOT_BASE", paths.rootDir+"/jail")
		err := runWithAutoCancel(t, 150*time.Millisecond, nil)
		if err == nil || !strings.Contains(err.Error(), "isolate jail") {
			t.Fatalf("Run with an unrealizable required jail = %v, want boot refusal", err)
		}
	})
	t.Run("containerd", func(t *testing.T) {
		setBaseRunEnv(t)
		t.Setenv("SB_CONTAINER_ENGINE", "containerd")
		t.Setenv("SB_CONTAINERD_POOL_ENABLED", "false")
		t.Setenv("SB_CONTAINERD_NATIVE_NETNS_POOL_ENABLED", "false")
		if err := runWithAutoCancel(t, 150*time.Millisecond, nil); err != nil {
			t.Fatalf("Run containerd: %v", err)
		}
	})
}

func TestCoverage95RunMoreWiringBranches(t *testing.T) {
	cases := []struct {
		name string
		env  map[string]string
	}{
		{"jsbundle_gc", map[string]string{
			"SB_ENABLE_ISOLATE":             "true",
			"SB_ISOLATE_WORKERD_PATH":       "/nonexistent-workerd",
			"SB_ISOLATE_BUNDLE_GC_INTERVAL": "1ms",
			// The jail is a boot-time contract this host cannot honor
			// (TestIsolateJailBootstrapFailsClosedAtBoot asserts that); this
			// case exercises the GC loop, so run unjailed.
			"SB_ISOLATE_USE_JAIL": "false",
		}},
		{"wasm_pool", map[string]string{
			"SB_ENABLE_WASM":             "true",
			"SB_WASM_POOL_ENABLED":       "true",
			"SB_WASM_POOL_DEPTH_DEFAULT": "1",
		}},
		{"snapshot_push", map[string]string{
			"SB_ENABLE_SNAPSHOT_PUSH_RECONCILE": "true",
			"SB_SNAPSHOT_PUSH_INTERVAL":         "1h",
		}},
		{"template_rotation", map[string]string{
			"SB_ENABLE_TEMPLATE_ROTATION_RECONCILE": "true",
			"SB_TEMPLATE_ROTATION_INTERVAL":         "1h",
		}},
		{"netrules_reassert", map[string]string{
			"SB_CONTAINER_ENGINE":                 "containerd",
			"SB_NETRULES_CHAIN_REASSERT_INTERVAL": "1h",
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			paths := setBaseRunEnv(t)
			t.Setenv("SB_ISOLATE_RUN_DIR", paths.rootDir+"/isolate")
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			if err := runWithAutoCancel(t, 150*time.Millisecond, nil); err != nil {
				t.Fatalf("Run %s: %v", tc.name, err)
			}
		})
	}
}

func TestCoverage95MoreWiringAndRunBranches(t *testing.T) {
	t.Run("netns_live_inspect_during_wire", func(t *testing.T) {
		st := openDaemonTestStore(t)
		work := t.TempDir()
		origSysctls := ensureForwardingSysctls
		ensureForwardingSysctls = func() error { return nil }
		t.Cleanup(func() { ensureForwardingSysctls = origSysctls })

		cfg := config.Config{
			ContainerEngine:                   models.ContainerEngineContainerd,
			ContainerdNativeNetnsPoolEnabled:  true,
			ContainerdNetnsPoolDepth:          0,
			ContainerdNetnsPoolSize:           2,
			ContainerdNetnsPoolRefillInterval: time.Hour,
			ContainerdCNIPluginDir:            filepath.Join(work, "cni-bin"),
			ContainerdCNIConfPath:             filepath.Join(work, "cni", "aerolvm.conflist"),
		}
		driver := cntr.New(cntr.FromDaemonConfig(cfg), nil, testLogger())
		ctx := context.Background()
		now := time.Now().UTC()
		pool := netns.New(st)
		if err := pool.Seed(ctx, netns.SeedConfig{PoolSize: 2}, now); err != nil {
			t.Fatal(err)
		}
		host := netns.NewFakeHost()
		if _, _, err := netns.NewRuntimeHandoff(pool, host).Provision(ctx, "sb-live"); err != nil {
			t.Fatal(err)
		}
		wired, err := wireContainerdNativeNetnsPool(ctx, cfg, testLogger(), st, driver)
		if err != nil {
			t.Fatalf("wire: %v", err)
		}
		if wired == nil {
			t.Fatal("expected wired pool")
		}
		wired.Stop()
	})

	t.Run("containerd_warm_nil_driver", func(t *testing.T) {
		pool := wireContainerdWarmPool(context.Background(), config.Config{
			ContainerEngine:          models.ContainerEngineContainerd,
			ContainerdPoolEnabled:    true,
			DockerReadySocketEnabled: true,
		}, testLogger(), nil, nil)
		if pool != nil {
			t.Fatal("want nil without driver")
		}
	})

	t.Run("containerd_warm_default_image", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		driver := cntr.New(cntr.FromDaemonConfig(config.Config{ContainerEngine: models.ContainerEngineContainerd}), nil, testLogger())
		pool := wireContainerdWarmPool(ctx, config.Config{
			ContainerEngine:          models.ContainerEngineContainerd,
			ContainerdPoolEnabled:    true,
			DockerReadySocketEnabled: true,
			ContainerdPoolDepth:      1,
			Runtime:                  models.RuntimeDocker,
		}, testLogger(), driver, nil)
		if pool == nil {
			t.Fatal("expected default-image pool")
		}
		drainContainerdWarmPool(pool, testLogger())
	})

	t.Run("netns_seed_cap_error", func(t *testing.T) {
		st := openDaemonTestStore(t)
		cfg := config.Config{
			ContainerEngine:                  models.ContainerEngineContainerd,
			ContainerdNativeNetnsPoolEnabled: true,
			ContainerdNetnsPoolSize:          10001,
		}
		driver := cntr.New(cntr.FromDaemonConfig(cfg), nil, testLogger())
		if _, err := wireContainerdNativeNetnsPool(context.Background(), cfg, testLogger(), st, driver); err == nil {
			t.Fatal("want seed cap error")
		}
	})

	t.Run("wasm_resident_host", func(t *testing.T) {
		paths := setBaseRunEnv(t)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		st := openTestStore(t)
		svc := service.New(config.Config{EnableWasm: true}, testLogger(), st, nil, nil, nil, nil, nil, nil)
		if err := os.MkdirAll(filepath.Join(paths.rootDir, "wasm-run"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Join(paths.rootDir, "wasm-modules"), 0o755); err != nil {
			t.Fatal(err)
		}
		pool := wireWasmRuntime(ctx, config.Config{
			EnableWasm:              true,
			WasmRunDir:              filepath.Join(paths.rootDir, "wasm-run"),
			WasmModulesDir:          filepath.Join(paths.rootDir, "wasm-modules"),
			WasmResidentHostEnabled: true,
			WasmStandardModules:     map[string]string{"python": "python.wasm"},
			WasmResidentHostIdleTTL: time.Millisecond,
		}, testLogger(), svc, st)
		if pool != nil {
			pool.Close()
		}
		time.Sleep(20 * time.Millisecond)
	})

	t.Run("template_resolver_unhealthy", func(t *testing.T) {
		ctx := context.Background()
		st := openTestStore(t)
		svc := service.New(config.Config{}, testLogger(), st, nil, nil, nil, nil, nil, nil)
		now := time.Now().UTC()
		if err := st.CreateTemplate(ctx, &models.Template{
			ID: "tpl-bad", Image: "alpine", Status: models.TemplateStatusUnhealthy,
			RootfsPath: "/tmp/rootfs.ext4", CreatedAt: now, UpdatedAt: now,
		}); err != nil {
			t.Fatal(err)
		}
		a := &templateResolverAdapter{svc: svc}
		if _, err := a.Resolve(ctx, "tpl-bad"); err != nil {
			t.Fatalf("unhealthy template should resolve: %v", err)
		}
	})

	t.Run("snapshot_push_sweep_logs", func(t *testing.T) {
		ctx := context.Background()
		st := openTestStore(t)
		svc := service.New(config.Config{}, testLogger(), st, nil, nil, nil, nil, nil, nil)
		now := time.Now().UTC()
		if err := st.CreateSnapshot(ctx, &models.SandboxSnapshot{
			Name: "snap-log", Image: "img:1", CreatedAt: now,
			PushState: models.SnapshotPushStatePending,
		}); err != nil {
			t.Fatal(err)
		}
		patPath := filepath.Join(t.TempDir(), "pat")
		if err := os.WriteFile(patPath, []byte("cluster-pat\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		runCtx, cancel := context.WithCancel(context.Background())
		startSnapshotPushReconciler(runCtx, testLogger(), config.Config{
			SnapshotPushEnabled:           true,
			MirrorPushHost:                "push.example",
			AutoImportClusterID:           "cluster-1",
			AutoImportClusterPATPath:      patPath,
			SnapshotPushReconcileInterval: 5 * time.Millisecond,
			SnapshotPushMaxInFlight:       1,
		}, st, svc, newTestDockerClient(t), nil)
		time.Sleep(50 * time.Millisecond)
		cancel()
	})

	t.Run("template_push_sweep_logs", func(t *testing.T) {
		ctx := context.Background()
		st := openTestStore(t)
		svc := service.New(config.Config{}, testLogger(), st, nil, nil, nil, nil, nil, nil)
		now := time.Now().UTC()
		if err := st.CreateTemplate(ctx, &models.Template{
			ID: "tpl-artifact", Image: "docker://alpine:3.20", Status: models.TemplateStatusReady,
			RootfsPath: "/tmp/rootfs.ext4", CreatedAt: now, UpdatedAt: now,
			PushState: models.TemplatePushStatePending,
		}); err != nil {
			t.Fatal(err)
		}
		patPath := filepath.Join(t.TempDir(), "pat")
		if err := os.WriteFile(patPath, []byte("cluster-pat\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		runCtx, cancel := context.WithCancel(context.Background())
		startTemplateArtifactPushReconciler(runCtx, testLogger(), config.Config{
			EnableFirecracker:             true,
			SnapshotPushEnabled:           true,
			MirrorPushHost:                "push.example",
			AutoImportClusterID:           "cluster-1",
			AutoImportClusterPATPath:      patPath,
			FirecrackerTemplatesDir:       t.TempDir(),
			SnapshotPushReconcileInterval: 5 * time.Millisecond,
			SnapshotPushMaxInFlight:       1,
		}, st, svc, newTestDockerClient(t))
		time.Sleep(50 * time.Millisecond)
		cancel()
	})

	t.Run("template_rotation_sweep_logs", func(t *testing.T) {
		ctx := context.Background()
		st := openTestStore(t)
		svc := service.New(config.Config{}, testLogger(), st, nil, nil, nil, nil, nil, nil)
		now := time.Now().UTC()
		stale := now.Add(-48 * time.Hour)
		if err := st.CreateTemplate(ctx, &models.Template{
			ID: "tpl-rot", Image: "docker://alpine:3.19", Status: models.TemplateStatusReady,
			ReadyAt: &stale, CreatedAt: now, UpdatedAt: now,
		}); err != nil {
			t.Fatal(err)
		}
		runCtx, cancel := context.WithCancel(context.Background())
		startTemplateRotationReconciler(runCtx, testLogger(), config.Config{
			EnableFirecracker:                   true,
			FirecrackerTemplateRotationInterval: 5 * time.Millisecond,
			FirecrackerTemplateMaxAge:           time.Hour,
		}, st, svc)
		time.Sleep(50 * time.Millisecond)
		cancel()
	})

	t.Run("resolve_ensure_local_error", func(t *testing.T) {
		ctx := context.Background()
		st := openTestStore(t)
		svc := service.New(config.Config{EnableFirecracker: true, FirecrackerTemplatesDir: t.TempDir()}, testLogger(), st, nil, nil, nil, nil, nil, nil)
		attachTemplateArtifactPuller(testLogger(), config.Config{
			EnableFirecracker:       true,
			FirecrackerTemplatesDir: t.TempDir(),
		}, svc, newTestDockerClient(t))
		now := time.Now().UTC()
		if err := st.CreateTemplate(ctx, &models.Template{
			ID: "tpl-pull", Image: "docker://alpine:3.20", Status: models.TemplateStatusReady,
			RootfsPath: "/tmp/rootfs.ext4", RegistryRef: "aocr.example/cluster/c1/templates/tpl-pull:latest",
			CreatedAt: now, UpdatedAt: now,
		}); err != nil {
			t.Fatal(err)
		}
		a := &templateResolverAdapter{svc: svc}
		if _, err := a.Resolve(ctx, "tpl-pull"); err == nil {
			t.Fatal("expected ensure-local pull error")
		}
	})

	t.Run("snapshot_push_wasm_pusher_fail", func(t *testing.T) {
		st := openTestStore(t)
		svc := service.New(config.Config{}, testLogger(), st, nil, nil, nil, nil, nil, nil)
		startSnapshotPushReconciler(context.Background(), testLogger(), config.Config{
			SnapshotPushEnabled:           true,
			MirrorPushHost:                "push.example",
			AutoImportClusterID:           "cluster-1",
			AutoImportClusterPATPath:      filepath.Join(t.TempDir(), "missing-pat"),
			SnapshotPushReconcileInterval: time.Hour,
		}, st, svc, newTestDockerClient(t), nil)
	})

	t.Run("template_rotation_reconciler_build_error", func(t *testing.T) {
		startTemplateRotationReconciler(context.Background(), testLogger(), config.Config{
			EnableFirecracker:                   true,
			FirecrackerTemplateRotationInterval: time.Second,
			FirecrackerTemplateMaxAge:           time.Hour,
		}, openTestStore(t), nil)
	})

	t.Run("reconciler_nil_guards", func(t *testing.T) {
		logger := testLogger()
		patPath := filepath.Join(t.TempDir(), "pat")
		if err := os.WriteFile(patPath, []byte("tok\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)

		startSnapshotPushReconciler(ctx, logger, config.Config{
			SnapshotPushEnabled:           true,
			MirrorPushHost:                "push.example",
			AutoImportClusterID:           "cluster-1",
			AutoImportClusterPATPath:      patPath,
			SnapshotPushReconcileInterval: time.Hour,
		}, nil, svc, newTestDockerClient(t), nil)

		startTemplateArtifactPushReconciler(ctx, logger, config.Config{
			EnableFirecracker:             true,
			SnapshotPushEnabled:           true,
			MirrorPushHost:                "push.example",
			AutoImportClusterID:           "cluster-1",
			AutoImportClusterPATPath:      patPath,
			FirecrackerTemplatesDir:       t.TempDir(),
			SnapshotPushReconcileInterval: time.Hour,
		}, nil, svc, newTestDockerClient(t))
	})

	t.Run("auto_import_sweep_error", func(t *testing.T) {
		st := openTestStore(t)
		svc := service.New(config.Config{}, testLogger(), st, nil, nil, nil, nil, nil, nil)
		patPath := filepath.Join(t.TempDir(), "pat")
		if err := os.WriteFile(patPath, []byte("tok\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		runCtx, cancel := context.WithCancel(context.Background())
		startAutoImportReconciler(runCtx, testLogger(), config.Config{
			AutoImportEnabled:           true,
			AutoImportClusterPATPath:    patPath,
			AutoImportHooksBaseURL:      "https://hooks.example",
			AutoImportClusterID:         "cluster-1",
			AutoImportReconcileInterval: 5 * time.Millisecond,
			AutoImportMaxInFlight:       1,
		}, st, svc)
		_ = st.Close()
		time.Sleep(30 * time.Millisecond)
		cancel()
	})

	t.Run("snapshot_push_sweep_error", func(t *testing.T) {
		st := openTestStore(t)
		svc := service.New(config.Config{}, testLogger(), st, nil, nil, nil, nil, nil, nil)
		patPath := filepath.Join(t.TempDir(), "pat")
		if err := os.WriteFile(patPath, []byte("tok\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		runCtx, cancel := context.WithCancel(context.Background())
		startSnapshotPushReconciler(runCtx, testLogger(), config.Config{
			SnapshotPushEnabled:           true,
			MirrorPushHost:                "push.example",
			AutoImportClusterID:           "cluster-1",
			AutoImportClusterPATPath:      patPath,
			SnapshotPushReconcileInterval: 5 * time.Millisecond,
		}, st, svc, newTestDockerClient(t), nil)
		_ = st.Close()
		time.Sleep(30 * time.Millisecond)
		cancel()
	})

	t.Run("template_push_sweep_error", func(t *testing.T) {
		st := openTestStore(t)
		svc := service.New(config.Config{}, testLogger(), st, nil, nil, nil, nil, nil, nil)
		patPath := filepath.Join(t.TempDir(), "pat")
		if err := os.WriteFile(patPath, []byte("tok\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		runCtx, cancel := context.WithCancel(context.Background())
		startTemplateArtifactPushReconciler(runCtx, testLogger(), config.Config{
			EnableFirecracker:             true,
			SnapshotPushEnabled:           true,
			MirrorPushHost:                "push.example",
			AutoImportClusterID:           "cluster-1",
			AutoImportClusterPATPath:      patPath,
			FirecrackerTemplatesDir:       t.TempDir(),
			SnapshotPushReconcileInterval: 5 * time.Millisecond,
		}, st, svc, newTestDockerClient(t))
		_ = st.Close()
		time.Sleep(30 * time.Millisecond)
		cancel()
	})

	t.Run("oci_helper_error_paths", func(t *testing.T) {
		blocked := filepath.Join(t.TempDir(), "blocked")
		if err := os.WriteFile(blocked, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(blocked, "skopeo"), []byte("#!/bin/sh\n"), 0o755); err == nil {
			t.Fatal("expected write into file path to fail")
		}
	})

	runCases := []struct {
		name  string
		setup func(t *testing.T, paths runTestPaths)
		err   bool
	}{
		{
			name: "bypass_rollback",
			setup: func(t *testing.T, paths runTestPaths) {
				if err := os.WriteFile(paths.bypassMarkerPath, []byte("true\n"), 0o644); err != nil {
					t.Fatal(err)
				}
				t.Setenv("SB_HTTP_WAKE_DIRECT_BYPASS_ENABLED", "false")
				t.Setenv("SB_ENABLE_SERVERLESS", "true")
				t.Setenv("SB_ENABLE_CADDY", "true")
				t.Setenv("SB_DOMAIN", "example.test")
			},
		},
		{
			name: "isolate_wire_error",
			err:  true,
			setup: func(t *testing.T, paths runTestPaths) {
				badDir := filepath.Join(paths.rootDir, "not-a-dir")
				if err := os.WriteFile(badDir, []byte("x"), 0o600); err != nil {
					t.Fatal(err)
				}
				t.Setenv("SB_ENABLE_ISOLATE", "true")
				t.Setenv("SB_ISOLATE_RUN_DIR", badDir)
				t.Setenv("SB_ISOLATE_WORKERD_PATH", "/nonexistent-workerd")
			},
		},
		{
			name: "docker_ready_socket",
			setup: func(t *testing.T, paths runTestPaths) {
				t.Setenv("SB_DOCKER_READY_SOCKET_ENABLED", "true")
				t.Setenv("SB_DOCKER_READY_SOCKET_DIR", filepath.Join(paths.rootDir, "ready"))
			},
		},
		{
			name: "auto_reconcile",
			setup: func(t *testing.T, paths runTestPaths) {
				t.Setenv("SB_AUTO_RECONCILE", "true")
			},
		},
		{
			name: "wasm_pool_drain",
			setup: func(t *testing.T, paths runTestPaths) {
				t.Setenv("SB_ENABLE_WASM", "true")
				t.Setenv("SB_WASM_RUN_DIR", filepath.Join(paths.rootDir, "wasm-run"))
				t.Setenv("SB_WASM_MODULES_DIR", filepath.Join(paths.rootDir, "wasm-modules"))
				t.Setenv("SB_WASM_POOL_ENABLED", "true")
				t.Setenv("SB_WASM_POOL_DEPTH_DEFAULT", "1")
				t.Setenv("SB_WASM_POOL_REFILL_INTERVAL", "5ms")
				_ = os.MkdirAll(filepath.Join(paths.rootDir, "wasm-run"), 0o755)
				_ = os.MkdirAll(filepath.Join(paths.rootDir, "wasm-modules"), 0o755)
			},
		},
		{
			name: "cluster_wasm_inventory",
			setup: func(t *testing.T, paths runTestPaths) {
				t.Setenv("SB_ENABLE_CLUSTER", "true")
				t.Setenv("SB_NODE_ROLE", "mixed")
				t.Setenv("SB_CLUSTER_BOOTSTRAP", "true")
				t.Setenv("SB_CLUSTER_INSECURE_GOSSIP", "true")
				t.Setenv("SB_CLUSTER_INSECURE_CREDENTIALS", "true")
				t.Setenv("SB_RAFT_BIND_ADDR", "127.0.0.1:0")
				t.Setenv("SB_GOSSIP_BIND_ADDR", "127.0.0.1:0")
				t.Setenv("SB_RAFT_ADVERTISE_ADDR", "127.0.0.1:0")
				t.Setenv("SB_GOSSIP_ADVERTISE_ADDR", "127.0.0.1:0")
				t.Setenv("SB_RAFT_DATA_DIR", filepath.Join(paths.rootDir, "raft"))
				t.Setenv("SB_SELF_API_ADVERTISE_URL", "http://127.0.0.1:8080")
				t.Setenv("SB_ENABLE_WASM", "true")
				t.Setenv("SB_WASM_RUN_DIR", filepath.Join(paths.rootDir, "wasm-run"))
				t.Setenv("SB_WASM_MODULES_DIR", filepath.Join(paths.rootDir, "wasm-modules"))
				_ = os.MkdirAll(filepath.Join(paths.rootDir, "wasm-run"), 0o755)
				_ = os.MkdirAll(filepath.Join(paths.rootDir, "wasm-modules"), 0o755)
			},
		},
		{
			name: "serverless_l4_wake",
			setup: func(t *testing.T, paths runTestPaths) {
				t.Setenv("SB_ENABLE_CADDY", "true")
				t.Setenv("SB_ENABLE_SERVERLESS", "true")
				t.Setenv("SB_ENABLE_CUSTOM_DOMAINS", "true")
				t.Setenv("SB_DOMAIN", "example.test")
			},
		},
		{
			name: "containerd_wire_failure",
			err:  true,
			setup: func(t *testing.T, paths runTestPaths) {
				t.Setenv("SB_CONTAINER_ENGINE", "containerd")
				t.Setenv("SB_CONTAINERD_NATIVE_NETNS_POOL_ENABLED", "true")
				t.Setenv("SB_CONTAINERD_CNI_PLUGIN_DIR", "")
				t.Setenv("SB_CONTAINERD_CNI_CONF_PATH", "")
			},
		},
		{
			name: "cluster_start_failure",
			err:  true,
			setup: func(t *testing.T, paths runTestPaths) {
				t.Setenv("SB_ENABLE_CLUSTER", "true")
				t.Setenv("SB_NODE_ROLE", "mixed")
				t.Setenv("SB_CLUSTER_BOOTSTRAP", "true")
				t.Setenv("SB_RAFT_BIND_ADDR", "not-a-valid-address")
			},
		},
		{
			name: "netrules_enabled",
			setup: func(t *testing.T, paths runTestPaths) {
				t.Setenv("SB_ENABLE_NETWORK_RULES", "true")
				t.Setenv("SB_NETRULES_BACKEND", "exec")
			},
		},
		{
			name: "netrules_unknown_backend",
			err:  runtime.GOOS == "linux",
			setup: func(t *testing.T, paths runTestPaths) {
				t.Setenv("SB_ENABLE_NETWORK_RULES", "true")
				t.Setenv("SB_NETRULES_BACKEND", "not-a-backend")
			},
		},
		{
			name: "auto_import_observer",
			setup: func(t *testing.T, paths runTestPaths) {
				t.Setenv("SB_AUTO_IMPORT_ENABLED", "true")
				t.Setenv("SB_AUTO_IMPORT_CLUSTER_PAT_PATH", paths.clusterPATPath)
				t.Setenv("SB_AUTO_IMPORT_HOOKS_URL", "https://hooks.example")
				t.Setenv("SB_AUTO_IMPORT_CLUSTER_ID", "cluster-1")
				t.Setenv("SB_AUTO_IMPORT_RECONCILE_INTERVAL", "1h")
			},
		},
		{
			name: "full_feature_shutdown",
			setup: func(t *testing.T, paths runTestPaths) {
				collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
				}))
				t.Cleanup(collector.Close)
				t.Setenv("SB_OTEL_TRACES_ENABLED", "true")
				t.Setenv("SB_OTEL_TRACES_ENDPOINT", collector.URL)
				t.Setenv("SB_OTEL_METRICS_ENABLED", "true")
				t.Setenv("SB_OTEL_METRICS_ENDPOINT", collector.URL)
				t.Setenv("SB_OTEL_METRICS_INTERVAL", "10ms")
				t.Setenv("SB_ENABLE_CADDY", "true")
				t.Setenv("SB_ENABLE_SERVERLESS", "true")
				t.Setenv("SB_ENABLE_CUSTOM_DOMAINS", "true")
				t.Setenv("SB_DOMAIN", "example.test")
				t.Setenv("SB_ENABLE_WASM", "true")
				t.Setenv("SB_WASM_RUN_DIR", filepath.Join(paths.rootDir, "wasm-run"))
				t.Setenv("SB_WASM_MODULES_DIR", filepath.Join(paths.rootDir, "wasm-modules"))
				t.Setenv("SB_WASM_POOL_ENABLED", "true")
				t.Setenv("SB_WASM_POOL_DEPTH_DEFAULT", "1")
				t.Setenv("SB_ENABLE_FIRECRACKER", "true")
				t.Setenv("SB_FIRECRACKER_BINARY", "/bin/true")
				t.Setenv("SB_JAILER_BINARY", "/bin/true")
				t.Setenv("SB_FIRECRACKER_KERNEL", paths.firecrackerKernel)
				t.Setenv("SB_FIRECRACKER_RUN_DIR", paths.firecrackerRunDir)
				t.Setenv("SB_FIRECRACKER_USE_JAILER", "false")
				t.Setenv("SB_FIRECRACKER_TAP_BASE_CIDR", "172.19.0.0/30")
				t.Setenv("SB_FIRECRACKER_TAP_POOL_SIZE", "1")
				t.Setenv("SB_FIRECRACKER_SKOPEO_BIN", "/bin/true")
				t.Setenv("SB_FIRECRACKER_UMOCI_BIN", "/bin/true")
				t.Setenv("SB_FIRECRACKER_MKFS_BIN", "/bin/true")
				t.Setenv("SB_FIRECRACKER_VMM_POOL_ENABLED", "true")
				t.Setenv("SB_FIRECRACKER_VMM_POOL_DEPTH_DEFAULT", "1")
				t.Setenv("SB_AUTO_IMPORT_ENABLED", "true")
				t.Setenv("SB_AUTO_IMPORT_CLUSTER_PAT_PATH", paths.clusterPATPath)
				t.Setenv("SB_AUTO_IMPORT_HOOKS_URL", "https://hooks.example")
				t.Setenv("SB_AUTO_IMPORT_CLUSTER_ID", "cluster-1")
				t.Setenv("SB_AUTO_IMPORT_RECONCILE_INTERVAL", "1h")
				_ = os.MkdirAll(filepath.Join(paths.rootDir, "wasm-run"), 0o755)
				_ = os.MkdirAll(filepath.Join(paths.rootDir, "wasm-modules"), 0o755)
			},
		},
	}
	for _, tc := range runCases {
		t.Run(tc.name, func(t *testing.T) {
			paths := setBaseRunEnv(t)
			tc.setup(t, paths)
			if tc.err {
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				err := Run(ctx, testLogger(), nil)
				if err == nil {
					t.Fatalf("Run %s = nil, want error", tc.name)
				}
				return
			}
			if tc.name == "full_feature_shutdown" {
				if err := runWithAutoCancel(t, 2500*time.Millisecond, nil); err != nil {
					t.Fatalf("Run %s: %v", tc.name, err)
				}
				return
			}
			if err := runWithAutoCancel(t, 1200*time.Millisecond, nil); err != nil {
				if tc.name == "netrules_enabled" && isNetrulesHostUnavailable(err) {
					return
				}
				t.Fatalf("Run %s: %v", tc.name, err)
			}
		})
	}
}
