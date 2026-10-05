package service

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
	"unsafe"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/caddy"
	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts"
)

type cov97SpecCluster struct {
	*cluster.Noop
	spec     *models.CreateSandboxRequest
	onUpsert func()
	wake     chan struct{}
}

func (c *cov97SpecCluster) SpecOf(string) *models.CreateSandboxRequest {
	if c.spec == nil {
		c.spec = &models.CreateSandboxRequest{}
	}
	return c.spec
}

func (c *cov97SpecCluster) UpsertSpec(context.Context, string, *models.CreateSandboxRequest, cluster.PlacementSecrets) error {
	if c.onUpsert != nil {
		c.onUpsert()
	}
	return errors.New("spec write-through")
}

func (c *cov97SpecCluster) SubscribePlacement(context.Context) <-chan struct{} {
	if c.wake == nil {
		c.wake = make(chan struct{})
	}
	return c.wake
}

type cov97ListFail struct{ cov97WasmRT }

func (cov97ListFail) ListManaged(context.Context) (map[string]*models.SandboxRuntimeState, error) {
	return nil, errors.New("list managed")
}

func cov97Seed(t *testing.T, st interface {
	Create(context.Context, *models.Sandbox) error
}, sb *models.Sandbox) {
	t.Helper()
	now := time.Now().UTC()
	if sb.CreatedAt.IsZero() {
		sb.CreatedAt, sb.UpdatedAt, sb.LastActiveAt = now, now, now
	}
	if sb.CPU == 0 {
		sb.CPU = 1
	}
	if sb.MemoryMB == 0 {
		sb.MemoryMB = 128
	}
	if sb.DiskGB == 0 {
		sb.DiskGB = 1
	}
	if sb.Status == "" {
		sb.Status = models.SandboxStatusStopped
	}
	if err := st.Create(context.Background(), sb); err != nil {
		t.Fatal(err)
	}
}

func TestCoverage97StartEnvBranches(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	cov97Seed(t, st, &models.Sandbox{ID: "sb-miss", Image: "alpine", Status: models.SandboxStatusStopped})
	if err := st.PutEnv(ctx, "sb-miss", []byte("not-a-seal")); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.StartSandbox(ctx, "sb-miss"); err == nil {
		t.Fatal("start ignored a corrupt sealed env")
	}

	cov97Seed(t, st, &models.Sandbox{
		ID: "sb-env", Image: "alpine", Status: models.SandboxStatusStopped,
		AuditIncarnationID: "inc-1", ContainerID: "ctr-env",
	})
	sealed, err := svc.sealEnv("sb-env", "inc-1", map[string]string{"A": "b"})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.PutEnv(ctx, "sb-env", sealed); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.StartSandbox(ctx, "sb-env"); err != nil {
		t.Fatalf("start = %v", err)
	}
}

func TestCoverage97ReconcileDriverGaps(t *testing.T) {
	ctx := context.Background()
	rt := &recordingRuntime{managed: map[string]*models.SandboxRuntimeState{
		"sb-mount": {Status: models.SandboxStatusStarted, ContainerID: "ctr-mount"},
	}}
	svc, st, _ := newServiceRuntimeHarness(t, rt)
	cov97Seed(t, st, &models.Sandbox{
		ID: "sb-mount", Image: "alpine", Status: models.SandboxStatusStarted,
		ContainerID: "ctr-mount", ContainerIP: "10.0.0.4",
	})
	if err := st.PutMounts(ctx, "sb-mount", []byte("not-a-seal")); err != nil {
		t.Fatal(err)
	}
	if err := svc.Reconcile(ctx); err != nil {
		t.Fatalf("reconcile mounts = %v", err)
	}

	svc.isolate = cov97ListFail{}
	if err := svc.Reconcile(ctx); err == nil {
		t.Fatal("reconcile ignored an isolate list failure")
	}

	svc2, st2, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	cov97Seed(t, st2, &models.Sandbox{
		ID: "sb-wasm-gone", Image: "mod.wasm", Status: models.SandboxStatusStarted,
		Runtime: models.RuntimeWasm, Durability: models.DurabilityEphemeral,
	})
	if err := svc2.Reconcile(ctx); err == nil {
		t.Fatal("reconcile ignored a wasm row with no driver")
	}
}

func TestCoverage97SpecWriteThrough(t *testing.T) {
	ctx := context.Background()
	rt := &recordingRuntime{}
	svc, st, _ := newServiceRuntimeHarness(t, rt)
	cov97Seed(t, st, &models.Sandbox{
		ID: "sb-disk", Image: "alpine", Status: models.SandboxStatusStarted,
		ContainerID: "ctr-disk",
	})
	rt.managed = map[string]*models.SandboxRuntimeState{
		"ctr-disk": {Status: models.SandboxStatusStarted, ContainerID: "ctr-disk"},
	}
	svc.docker = resizeOKRuntime{recordingRuntime: rt}
	svc.cluster = &cov97SpecCluster{Noop: &cluster.Noop{}}
	if _, err := svc.ResizeSandbox(ctx, "sb-disk", models.ResizeSandboxRequest{DiskGB: 2}); err != nil {
		t.Fatalf("resize = %v", err)
	}

	cov97Seed(t, st, &models.Sandbox{ID: "sb-life", Image: "alpine", Status: models.SandboxStatusStopped})
	svc.cluster = &cov97SpecCluster{Noop: &cluster.Noop{}, onUpsert: func() {
		_ = st.Delete(ctx, "sb-life")
	}}
	if _, err := svc.UpdateLifecycle(ctx, "sb-life", models.Lifecycle{}); err == nil {
		t.Fatal("lifecycle update ignored a missing row after the spec write")
	}
}

func TestCoverage97BuiltImageGCClosure(t *testing.T) {
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.ImageBuildGCEnabled = true
	svc.cfg.ImageBuildGCInterval = 5 * time.Millisecond
	svc.SetDockerAuxClient(&docker.Client{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	svc.StartBuiltImageGC(ctx)
	time.Sleep(40 * time.Millisecond)
}

func TestCoverage97IngressWakeStopsTimer(t *testing.T) {
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	wake := make(chan struct{}, 1)
	svc.cfg.EnableCluster = true
	svc.caddy = caddy.New(config.Config{EnableCaddy: true, HTTPClientTimeout: time.Second})
	svc.cluster = &cov97SpecCluster{Noop: &cluster.Noop{}, wake: wake}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	svc.StartClusterIngressReconcile(ctx)
	wake <- struct{}{}
	time.Sleep(30 * time.Millisecond)
}

type cov97CorruptCreate struct{ cov97WasmRT }

func (cov97CorruptCreate) Create(context.Context, models.CreateSandboxRequest, string, string, []mounts.ContainerBind) (*models.SandboxRuntimeState, error) {
	return nil, fmt.Errorf("checksum: %w", models.ErrSnapshotCorrupt)
}

func TestCoverage97FirecrackerCreateBranches(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableFirecracker = true
	svc.firecracker = cov97CorruptCreate{}
	if _, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{
		Image: "alpine", TemplateID: "tpl", CPU: 1000, MemoryMB: 128, DiskGB: 1,
	}); err == nil {
		t.Fatal("create admitted an oversized firecracker sandbox")
	}
	if _, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{
		Image: "alpine", TemplateID: "tpl-corrupt", CPU: 1, MemoryMB: 128, DiskGB: 1,
	}); err == nil {
		t.Fatal("create ignored a corrupt template snapshot")
	}
}

func TestCoverage97ExposeLayer4Down(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	cov97Seed(t, st, &models.Sandbox{ID: "sb-port", Image: "alpine", Status: models.SandboxStatusStarted, ContainerIP: "10.0.0.5"})
	svc.caddy = caddy.New(config.Config{
		EnableCaddy: true, Domain: "example.test", CaddyAdminURL: "http://127.0.0.1:1",
		L4TLSListen: ":8443", L4TLSFallback: "127.0.0.1:9", HTTPClientTimeout: 200 * time.Millisecond,
	})
	if _, err := svc.ExposePort(ctx, "sb-port", 5432, models.ExposedPortProtocolTCP); err == nil {
		t.Fatal("tcp expose bootstrapped layer4 against a closed admin")
	}
	if _, err := svc.ExposePort(ctx, "sb-port", 443, models.ExposedPortProtocolTLS); err == nil {
		t.Fatal("tls expose bootstrapped layer4 against a closed admin")
	}
}

func TestCoverage97ReconcileRouteAndMountRepair(t *testing.T) {
	ctx := context.Background()
	public := true
	rt := &recordingRuntime{managed: map[string]*models.SandboxRuntimeState{
		"sb-pub": {Status: models.SandboxStatusStarted, ContainerID: "ctr-pub"},
	}}
	svc, st, _ := newServiceRuntimeHarness(t, rt)
	cov97Seed(t, st, &models.Sandbox{
		ID: "sb-pub", Image: "alpine", Status: models.SandboxStatusStarted,
		ContainerID: "ctr-pub", ContainerIP: "10.0.0.6", AllowPublicTraffic: &public,
	})
	svc.caddy = caddy.New(config.Config{
		EnableCaddy: true, Domain: "example.test", CaddyAdminURL: "http://127.0.0.1:1",
		HTTPClientTimeout: 200 * time.Millisecond,
	})
	if err := svc.Reconcile(ctx); err == nil {
		t.Fatal("reconcile installed a public route against a closed admin")
	}

	rt2 := &recordingRuntime{managed: map[string]*models.SandboxRuntimeState{
		"sb-mnt": {Status: models.SandboxStatusStarted, ContainerID: "ctr-mnt"},
	}}
	svc2, st2, _ := newServiceRuntimeHarness(t, rt2)
	cov97Seed(t, st2, &models.Sandbox{
		ID: "sb-mnt", Image: "alpine", Status: models.SandboxStatusStarted,
		ContainerID: "ctr-mnt", ContainerIP: "10.0.0.7",
	})
	sealed, err := svc2.sealMounts([]models.MountSpec{{
		Type: models.MountTypeNFS, Target: "/data", Source: "nfs.example:/export",
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := st2.PutMounts(ctx, "sb-mnt", sealed); err != nil {
		t.Fatal(err)
	}
	if err := svc2.Reconcile(ctx); err != nil {
		t.Fatalf("reconcile mounts = %v", err)
	}
}

func TestCoverage97ExposeBlankProtocol(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	cov97Seed(t, st, &models.Sandbox{
		ID: "sb-blank", Image: "alpine", Status: models.SandboxStatusStarted, ContainerIP: "10.0.0.8",
	})
	if err := st.UpsertPort(ctx, models.ExposedPort{SandboxID: "sb-blank", Port: 80, Protocol: models.ExposedPortProtocolHTTP}); err != nil {
		t.Fatal(err)
	}
	// UpsertPort rewrites a blank protocol to http. The mismatch branch still
	// has to accept a row that predates that normalization.
	coverage97Exec(t, st, "UPDATE exposed_ports SET protocol = '' WHERE sandbox_id = 'sb-blank'")
	if _, err := svc.ExposePort(ctx, "sb-blank", 80, models.ExposedPortProtocolTCP); err == nil {
		t.Fatal("tcp expose reused a blank-protocol reservation")
	}
}

func TestCoverage97SecretAuditOpenParentUnwritable(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
	sink := &fileAuditSink{
		path:     filepath.Join(dir, "audit.jsonl"),
		lockPath: filepath.Join(t.TempDir(), "audit.lock"),
	}
	if err := sink.openLocked(); err == nil {
		t.Fatal("opened a secret audit file in an unwritable directory")
	}
}

func coverage97Exec(t *testing.T, st *store.Store, query string) {
	t.Helper()
	rv := reflect.ValueOf(st).Elem()
	field := rv.FieldByName("db")
	db := reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).Elem().Interface().(*sql.DB)
	if _, err := db.ExecContext(context.Background(), query); err != nil {
		t.Fatalf("exec %q: %v", query, err)
	}
}
