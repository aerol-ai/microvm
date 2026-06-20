package service

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/caddy"
	"github.com/aerol-ai/microvm/pkg/models"
	wasmengine "github.com/aerol-ai/microvm/pkg/wasm"
	"github.com/aerol-ai/microvm/pkg/wasmmod"
)

type erroringWasmModuleResolver struct {
	err error
}

func (r erroringWasmModuleResolver) Resolve(context.Context, string) (*wasmmod.ResolvedModule, error) {
	return nil, r.err
}

type failingOwnershipCluster struct {
	*cluster.Noop
	err error
}

func (f *failingOwnershipCluster) AssertOwnership(context.Context, []cluster.LocalSandboxState) error {
	return f.err
}

type recordingCheckpointStore struct {
	mu          sync.Mutex
	destRef     string
	pullCalls   []checkpointPullCall
	deleteCalls []string
	pullErr     error
}

type customDomainConflictCluster struct {
	*cluster.Noop
	mu          sync.Mutex
	addCalls    int
	removeCalls []string
}

func (c *customDomainConflictCluster) AddCustomDomain(context.Context, string, string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.addCalls++
	if c.addCalls == 2 {
		return cluster.ErrCustomHostnameConflict
	}
	return nil
}

func (c *customDomainConflictCluster) RemoveCustomDomain(_ context.Context, _ string, hostname string) error {
	c.mu.Lock()
	c.removeCalls = append(c.removeCalls, hostname)
	c.mu.Unlock()
	return nil
}

type wasmMigrationTargetClusterStub struct {
	*cluster.Noop
	owner   cluster.OwnerInfo
	members []cluster.Member
	drained map[string]bool
	spec    *models.CreateSandboxRequest
}

func (c *wasmMigrationTargetClusterStub) OwnerOf(string) (cluster.OwnerInfo, error) {
	return c.owner, nil
}

func (c *wasmMigrationTargetClusterStub) Members() []cluster.Member {
	return append([]cluster.Member(nil), c.members...)
}

func (c *wasmMigrationTargetClusterStub) IsNodeDrained(nodeID string) bool {
	if c.drained == nil {
		return false
	}
	return c.drained[nodeID]
}

func (c *wasmMigrationTargetClusterStub) SpecOf(string) *models.CreateSandboxRequest {
	if c.spec == nil {
		return nil
	}
	cp := *c.spec
	return &cp
}

type checkpointPullCall struct {
	RegistryRef string
	DstDir      string
}

func (r *recordingCheckpointStore) DestRefFor(sandboxID string) string {
	if r.destRef == "" {
		return ""
	}
	return r.destRef
}

func (r *recordingCheckpointStore) DestRefTagged(sandboxID, tag string) string {
	if strings.TrimSpace(sandboxID) == "" {
		return ""
	}
	if strings.TrimSpace(tag) == "" {
		tag = "latest"
	}
	return fmt.Sprintf("test://%s:%s", sandboxID, tag)
}

func (r *recordingCheckpointStore) PushOnceTo(context.Context, string, string, string) (WasmCheckpointPushResult, error) {
	return WasmCheckpointPushResult{RegistryRef: r.destRef, Digest: "sha256:deadbeef"}, nil
}

func (r *recordingCheckpointStore) PullOnce(_ context.Context, registryRef, dstDir string) error {
	r.mu.Lock()
	r.pullCalls = append(r.pullCalls, checkpointPullCall{RegistryRef: registryRef, DstDir: dstDir})
	r.mu.Unlock()
	if r.pullErr != nil {
		return r.pullErr
	}
	if err := os.MkdirAll(dstDir, 0o700); err != nil {
		return err
	}
	snap := wasmengine.SnapshotCapture{
		Config: wasmengine.SnapshotConfig{
			SchemaVersion:   1,
			Engine:          wasmengine.EngineNameWazero(),
			BaseModule:      wasmengine.SnapshotBaseModule{Digest: "sha256:abc"},
			Durability:      models.DurabilityDurable,
			CloneGeneration: "gen-1",
		},
		Memory:    []byte("mem"),
		Globals:   []byte("[]"),
		WASIState: []byte("{}"),
	}
	return wasmengine.WriteSnapshotDir(dstDir, snap)
}

func (r *recordingCheckpointStore) DeleteRef(_ context.Context, registryRef string) error {
	r.mu.Lock()
	r.deleteCalls = append(r.deleteCalls, registryRef)
	r.mu.Unlock()
	return nil
}

func TestStorageAndWasmHelperCoverage(t *testing.T) {
	t.Run("cluster ownership", func(t *testing.T) {
		ctx := context.Background()
		dir := t.TempDir()
		st, err := store.Open(filepath.Join(dir, "state.db"))
		if err != nil {
			t.Fatalf("store.Open: %v", err)
		}
		t.Cleanup(func() { _ = st.Close() })

		svc := &Service{
			cfg:    config.Config{EnableCluster: true},
			store:  st,
			cipher: newTestCipher(t),
		}

		plainRegistry := &models.RegistryAuth{Server: "ghcr.io", Username: "alice", Password: "secret"}
		sealedRegistry, err := svc.sealRegistry(plainRegistry)
		if err != nil {
			t.Fatalf("SealRegistry: %v", err)
		}

		sb := &models.Sandbox{
			ID:                 "sb-cluster",
			Image:              "alpine",
			Status:             models.SandboxStatusStopped,
			Runtime:            models.RuntimeFirecracker,
			TemplateID:         "tpl-fast",
			OverlaySizeGB:      4,
			Failover:           &models.Failover{Policy: models.FailoverPolicyRecreate},
			RegistryAuthSealed: sealedRegistry,
			CustomDomains:      []models.CustomDomain{{Hostname: "api.acme.com"}},
			ExposedPorts:       []models.ExposedPort{{Port: 8080, Protocol: models.ExposedPortProtocolHTTP, HostPort: 18080, PublicURL: "http://127.0.0.1:18080"}},
			ContainerCommand:   []string{"entry"},
		}

		spec := svc.specFromSandbox(context.Background(), sb)
		if spec == nil || spec.Registry == nil || spec.Registry.Password != "secret" {
			t.Fatalf("specFromSandbox registry = %+v", spec.Registry)
		}
		if spec.Failover != nil {
			t.Fatalf("stopped firecracker replay should clear failover, got %+v", spec.Failover)
		}

		c := cluster.NewNoop("self", "http://self", "")
		if got := placementCanBeClaimedBySelf(cluster.Placement{OwnerState: cluster.PlacementOwnerStateOrphaned}, "self"); !got {
			t.Fatal("orphaned placement without owner should be claimable")
		}
		if got := placementCanBeClaimedBySelf(cluster.Placement{OwnerState: cluster.PlacementOwnerStateOrphaned, OrphanedOwnerNodeID: "peer"}, "self"); got {
			t.Fatal("peer orphaned placement should not be claimable")
		}
		noCD := &models.Sandbox{ID: "sb-nocd", Runtime: models.RuntimeWasm}
		if got := placementMissingLocalCustomHostnames(cluster.Placement{CustomHostnames: []string{}}, noCD); got {
			t.Fatal("empty local custom-hostname list should not force replay")
		}
		if got := placementMissingLocalCustomHostnames(cluster.Placement{CustomHostnames: []string{"other.acme.com"}}, sb); !got {
			t.Fatal("missing hostname should force replay")
		}
		if got := placementMissingLocalPorts(cluster.Placement{ExposedPortRoutes: map[int]cluster.ExposedPortRoute{8080: {Protocol: models.ExposedPortProtocolHTTP, HostPort: 18080, PublicURL: "http://127.0.0.1:18080"}}}, sb); got {
			t.Fatal("matching port route should not force replay")
		}
		if got := placementMissingLocalPorts(cluster.Placement{}, sb); !got {
			t.Fatal("missing port route should force replay")
		}

		state := svc.localSandboxStateForCluster(ctx, c, sb)
		if state.Spec == nil || state.Spec.Registry == nil || state.Spec.Registry.Password != "" {
			t.Fatalf("redacted cluster spec leaked secrets: %+v", state.Spec)
		}
		if state.Secrets.Ref == "" || state.Secrets.Version == 0 {
			t.Fatalf("expected secret ref with store, got %+v", state.Secrets)
		}
		if state.Spec.Failover != nil {
			t.Fatalf("localSandboxStateForCluster should keep redacted failover nil, got %+v", state.Spec.Failover)
		}
		if state.Spec.ContainerCommand[0] != "entry" {
			t.Fatalf("container command lost: %+v", state.Spec.ContainerCommand)
		}

		svc.AttachCluster(&recordingOwnershipCluster{
			Noop:       cluster.NewNoop("self", "http://self", ""),
			placements: map[string]cluster.Placement{},
		})
		count, err := svc.assertClusterOwnership(ctx, []*models.Sandbox{sb}, nil)
		if err != nil {
			t.Fatalf("assertClusterOwnership: %v", err)
		}
		if count != 1 {
			t.Fatalf("assertClusterOwnership count = %d, want 1", count)
		}

		svc.AttachCluster(&failingOwnershipCluster{
			Noop: cluster.NewNoop("self", "http://self", ""),
			err:  errors.New("assert failed"),
		})
		svc.reconcileLocalClusterOwnership(ctx, []*models.Sandbox{sb}, nil)

		// Early-return branches.
		if count, err := (&Service{}).assertClusterOwnership(ctx, []*models.Sandbox{sb}, nil); err != nil || count != 0 {
			t.Fatalf("assertClusterOwnership without cluster = (%d, %v)", count, err)
		}
	})

	t.Run("cluster secrets", func(t *testing.T) {
		ctx := context.Background()
		svc := &Service{cipher: newTestCipher(t)}
		req := models.CreateSandboxRequest{
			Image: "alpine",
			Registry: &models.RegistryAuth{
				Server:   "ghcr.io",
				Username: "alice",
				Password: "secret",
			},
			Mounts: []models.MountSpec{
				{Type: models.MountTypeS3, Target: "/data", Source: "bucket", Credentials: map[string]string{"token": "mount-secret"}},
			},
			Env:      map[string]string{"A": "B"},
			Failover: &models.Failover{Policy: models.FailoverPolicyRecreate},
		}

		sealed, err := svc.SealClusterSecrets(req)
		if err != nil {
			t.Fatalf("SealClusterSecrets: %v", err)
		}
		if len(sealed) == 0 {
			t.Fatal("expected sealed payload")
		}
		redacted := RedactClusterSecrets(req)
		if redacted.Registry == nil || redacted.Registry.Password != "" {
			t.Fatalf("RedactClusterSecrets registry = %+v", redacted.Registry)
		}
		if redacted.Mounts[0].Credentials != nil {
			t.Fatalf("RedactClusterSecrets mount creds leaked: %+v", redacted.Mounts[0].Credentials)
		}
		if redacted.Failover == nil || redacted.Failover.Policy != models.FailoverPolicyRecreate {
			t.Fatalf("RedactClusterSecrets should preserve failover: %+v", redacted.Failover)
		}

		merged, err := svc.UnsealClusterSecrets(redacted, sealed)
		if err != nil {
			t.Fatalf("UnsealClusterSecrets: %v", err)
		}
		if merged.Registry == nil || merged.Registry.Password != "secret" {
			t.Fatalf("UnsealClusterSecrets registry = %+v", merged.Registry)
		}
		if merged.Mounts[0].Credentials["token"] != "mount-secret" {
			t.Fatalf("UnsealClusterSecrets mount creds = %+v", merged.Mounts[0].Credentials)
		}

		if got := normalizeClusterSecretRecipients([]string{" node-b ", "node-a", "node-b", "", "node-c"}); len(got) != 3 || got[0] != "node-a" || got[1] != "node-b" || got[2] != "node-c" {
			t.Fatalf("normalizeClusterSecretRecipients = %#v", got)
		}
		if got := normalizeClusterSecretRecipients(nil); len(got) != 1 || got[0] != "*" {
			t.Fatalf("normalizeClusterSecretRecipients(nil) = %#v", got)
		}
		if !clusterSecretRecipientAllowed([]string{"*"}, "") {
			t.Fatal("wildcard recipient should be allowed")
		}
		if clusterSecretRecipientAllowed([]string{"node-a"}, "node-b") {
			t.Fatal("non-matching recipient should be rejected")
		}
		if got := clusterSecretRef(" sb ", 2); got != "cluster-secret://sandbox/sb/v2" {
			t.Fatalf("clusterSecretRef = %q", got)
		}

		if _, err := (&Service{cipher: newTestCipher(t)}).PutClusterSecretsForRecipient(ctx, " ", req, "node-a"); err == nil {
			t.Fatal("empty sandbox id accepted")
		}
		if _, err := (&Service{cipher: newTestCipher(t)}).PutClusterSecretsForRecipient(ctx, "sb", req, "node-a"); err == nil {
			t.Fatal("storeless PutClusterSecretsForRecipient accepted")
		}
		if _, err := (&Service{cipher: newTestCipher(t)}).OpenClusterSecretsForNode(ctx, redacted, cluster.PlacementSecrets{Ref: "cluster-secret://sandbox/sb/v1", Version: 1}, "node-a"); err == nil {
			t.Fatal("storeless OpenClusterSecretsForNode accepted")
		}
		if _, err := openClusterSecretEnvelopePayload([]byte("bad"), []byte("short"), []string{"node-a"}); err == nil {
			t.Fatal("invalid envelope payload accepted")
		}
	})

	t.Run("wasm module catalogue and api", func(t *testing.T) {
		ctx := context.Background()
		dir := t.TempDir()
		st, err := store.Open(filepath.Join(dir, "state.db"))
		if err != nil {
			t.Fatalf("store.Open: %v", err)
		}
		t.Cleanup(func() { _ = st.Close() })

		logger := slog.New(slog.NewTextHandler(io.Discard, nil))
		svc := New(config.Config{EnableWasm: true, WasmPoolEnabled: true}, logger, st, &recordingRuntime{}, nil, nil, nil, nil, nil)

		// Helper functions.
		if entryExportFromSandbox(nil) != "_start" {
			t.Fatal("entryExportFromSandbox(nil) should default to _start")
		}
		if entryExportFromSandbox(&models.Sandbox{ContainerCommand: []string{"entry"}}) != "entry" {
			t.Fatal("entryExportFromSandbox should use first command")
		}

		// registerWasmModuleCatalogue no-ops for non-WASM / empty ref.
		svc.registerWasmModuleCatalogue(ctx, nil, "/module", 1)
		svc.registerWasmModuleCatalogue(ctx, &models.Sandbox{ID: "sb-docker", Runtime: models.RuntimeDocker, ModuleRef: "file:///tmp/x"}, "/module", 1)
		svc.registerWasmModuleCatalogue(ctx, &models.Sandbox{ID: "sb-empty", Runtime: models.RuntimeWasm}, "/module", 1)
		if _, err := st.GetWasmModule(ctx, "sb-docker"); err == nil {
			t.Fatal("registerWasmModuleCatalogue should not write non-WASM row")
		}

		// Success path writes digest-based row for file:// refs.
		svc.registerWasmModuleCatalogue(ctx, &models.Sandbox{
			ID:               "sb-wasm",
			Runtime:          models.RuntimeWasm,
			ModuleRef:        "file:///tmp/mod.wasm",
			ModuleDigest:     "sha256:abc",
			ContainerCommand: []string{"entry"},
		}, "/module", 42)
		rec, err := st.GetWasmModule(ctx, "sha256:abc")
		if err != nil {
			t.Fatalf("GetWasmModule: %v", err)
		}
		if rec.Entrypoint != "entry" || rec.ModuleSizeBytes != 42 || !rec.ReadyAt.Equal(rec.CreatedAt) {
			t.Fatalf("catalogue row = %+v", rec)
		}

		disabled := New(config.Config{}, logger, st, &recordingRuntime{}, nil, nil, nil, nil, nil)
		if _, err := disabled.CreateWasmModule(ctx, models.CreateWasmModuleRequest{ModuleRef: "x"}); !errors.Is(err, models.ErrRuntimeNotImplemented) {
			t.Fatalf("disabled CreateWasmModule = %v", err)
		}
		if _, err := disabled.ListWasmModules(ctx); !errors.Is(err, models.ErrRuntimeNotImplemented) {
			t.Fatalf("disabled ListWasmModules = %v", err)
		}
		if _, err := disabled.GetWasmModule(ctx, "x"); !errors.Is(err, models.ErrRuntimeNotImplemented) {
			t.Fatalf("disabled GetWasmModule = %v", err)
		}
		if err := disabled.DeleteWasmModule(ctx, "x"); !errors.Is(err, models.ErrRuntimeNotImplemented) {
			t.Fatalf("disabled DeleteWasmModule = %v", err)
		}

		enabled := New(config.Config{EnableWasm: true}, logger, st, &recordingRuntime{}, nil, nil, nil, nil, nil)
		if _, err := enabled.CreateWasmModule(ctx, models.CreateWasmModuleRequest{ModuleRef: "file:///tmp/mod.wasm"}); err == nil {
			t.Fatal("CreateWasmModule without resolver accepted")
		}

		enabled.SetWasmModuleResolver(erroringWasmModuleResolver{err: errors.New("resolve failed")})
		if _, err := enabled.CreateWasmModule(ctx, models.CreateWasmModuleRequest{ID: "explicit", ModuleRef: "file:///tmp/mod.wasm"}); err == nil {
			t.Fatal("CreateWasmModule should fail on resolver error")
		}
		if rec, err := st.GetWasmModule(ctx, "explicit"); err != nil || rec.Status != string(models.WasmModuleStatusFailed) {
			t.Fatalf("failed module row = %+v, %v", rec, err)
		}

		enabled.SetWasmModuleResolver(stubWasmModuleResolver{path: "/tmp/mod.wasm", digest: ""})
		if _, err := enabled.CreateWasmModule(ctx, models.CreateWasmModuleRequest{ModuleRef: "file:///tmp/mod.wasm"}); err == nil {
			t.Fatal("CreateWasmModule should fail on empty digest")
		}

		enabled.SetWasmModuleResolver(stubWasmModuleResolver{path: "/tmp/mod.wasm", digest: "sha256:cid"})
		_ = st.UpsertWasmModule(ctx, store.WasmModuleRecord{
			ID:        "conflict",
			ModuleRef: "file:///tmp/other.wasm",
			Status:    string(models.WasmModuleStatusReady),
			CreatedAt: time.Now().UTC(),
			UpdatedAt: time.Now().UTC(),
		})
		if _, err := enabled.CreateWasmModule(ctx, models.CreateWasmModuleRequest{ID: "conflict", ModuleRef: "file:///tmp/mod.wasm"}); !errors.Is(err, store.ErrWasmModuleIDConflict) {
			t.Fatalf("CreateWasmModule conflict = %v", err)
		}

		remover := &recordingRuntime{}
		enabled = New(config.Config{EnableWasm: true}, logger, st, remover, nil, nil, nil, nil, nil)
		enabled.SetWasmRuntime(remover)
		_ = st.UpsertWasmModule(ctx, store.WasmModuleRecord{
			ID:        "delete-me",
			ModuleRef: "file:///tmp/delete-me.wasm",
			Status:    string(models.WasmModuleStatusReady),
			CreatedAt: time.Now().UTC(),
			UpdatedAt: time.Now().UTC(),
		})
		if err := enabled.DeleteWasmModule(ctx, "delete-me"); err != nil {
			t.Fatalf("DeleteWasmModule: %v", err)
		}
		if len(remover.removeImages) != 1 || remover.removeImages[0] != "file:///tmp/delete-me.wasm" {
			t.Fatalf("RemoveImage calls = %#v", remover.removeImages)
		}
	})

	t.Run("wasm module gc", func(t *testing.T) {
		ctx := context.Background()
		dir := t.TempDir()
		st, err := store.Open(filepath.Join(dir, "state.db"))
		if err != nil {
			t.Fatalf("store.Open: %v", err)
		}
		t.Cleanup(func() { _ = st.Close() })

		modulesDir := filepath.Join(dir, "modules")
		modulePath := filepath.Join(modulesDir, "mod-1", "module.wasm")
		if err := os.MkdirAll(filepath.Dir(modulePath), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(modulePath, []byte("wasm"), 0o600); err != nil {
			t.Fatalf("write module: %v", err)
		}
		if err := st.UpsertWasmModule(ctx, store.WasmModuleRecord{
			ID:         "mod-1",
			ModuleRef:  "file:///tmp/mod-1.wasm",
			ModulePath: modulePath,
			Status:     "ready",
		}); err != nil {
			t.Fatalf("UpsertWasmModule: %v", err)
		}

		rt := &recordingRuntime{}
		svc := &Service{cfg: config.Config{WasmModuleGCTTL: time.Millisecond, WasmModulesDir: modulesDir}, store: st, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
		svc.SetWasmRuntime(rt)
		svc.StartWasmModuleGC(context.Background()) // interval disabled / no-op coverage
		time.Sleep(10 * time.Millisecond)
		svc.runWasmModuleGC(ctx, time.Now().UTC())

		if _, err := st.GetWasmModule(ctx, "mod-1"); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("module row still exists after GC: %v", err)
		}
	})

	t.Run("wasm migration tar", func(t *testing.T) {
		if !wasmSnapshotTarMember("config.json") || wasmSnapshotTarMember("missing.json") {
			t.Fatal("wasmSnapshotTarMember failed")
		}
		if err := writeWasmCheckpointTar(io.Discard, filepath.Join(t.TempDir(), "missing")); err == nil {
			t.Fatal("writeWasmCheckpointTar accepted missing dir")
		}

		tmp := t.TempDir()
		dirPath := filepath.Join(tmp, "dir")
		if err := os.MkdirAll(dirPath, 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		var out bytes.Buffer
		tw := tar.NewWriter(&out)
		if err := writeTarFileEntry(tw, "dir", dirPath); err == nil {
			t.Fatal("writeTarFileEntry accepted directory")
		}
		_ = tw.Close()

		var bad bytes.Buffer
		tw = tar.NewWriter(&bad)
		if err := tw.WriteHeader(&tar.Header{Name: "unexpected.txt", Mode: 0o644, Size: 1, Typeflag: tar.TypeReg}); err != nil {
			t.Fatalf("write hdr: %v", err)
		}
		if _, err := tw.Write([]byte("x")); err != nil {
			t.Fatalf("write body: %v", err)
		}
		_ = tw.Close()
		if err := extractWasmCheckpointTar(bytes.NewReader(bad.Bytes()), filepath.Join(t.TempDir(), "dst")); err == nil || !strings.Contains(err.Error(), "unexpected tar entry") {
			t.Fatalf("unexpected entry error = %v", err)
		}

		var missing bytes.Buffer
		tw = tar.NewWriter(&missing)
		for _, name := range []string{"config.json", "memory.zstd"} {
			if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: 1, Typeflag: tar.TypeReg}); err != nil {
				t.Fatalf("write hdr: %v", err)
			}
			if _, err := tw.Write([]byte("x")); err != nil {
				t.Fatalf("write body: %v", err)
			}
		}
		_ = tw.Close()
		if err := extractWasmCheckpointTar(bytes.NewReader(missing.Bytes()), filepath.Join(t.TempDir(), "dst")); err == nil || !strings.Contains(err.Error(), "missing") {
			t.Fatalf("missing entry error = %v", err)
		}
	})

	t.Run("wasm checkpoint pull and push", func(t *testing.T) {
		ctx := context.Background()
		dir := t.TempDir()
		st, err := store.Open(filepath.Join(dir, "state.db"))
		if err != nil {
			t.Fatalf("store.Open: %v", err)
		}
		t.Cleanup(func() { _ = st.Close() })

		svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
		svc.cfg.EnableWasm = true
		svc.cfg.WasmModulesDir = filepath.Join(dir, "modules")

		if _, err := svc.ensureWasmCheckpointLocal(ctx, nil); err == nil {
			t.Fatal("ensureWasmCheckpointLocal accepted nil sandbox")
		}

		validPath := filepath.Join(dir, "existing", "mem.snap")
		snap := wasmengine.SnapshotCapture{
			Config: wasmengine.SnapshotConfig{
				SchemaVersion:   1,
				Engine:          wasmengine.EngineNameWazero(),
				BaseModule:      wasmengine.SnapshotBaseModule{Digest: "sha256:abc"},
				Durability:      models.DurabilityDurable,
				CloneGeneration: "gen-existing",
			},
			Memory:    []byte("mem"),
			Globals:   []byte("[]"),
			WASIState: []byte("{}"),
		}
		if err := wasmengine.WriteSnapshotDir(validPath, snap); err != nil {
			t.Fatalf("WriteSnapshotDir: %v", err)
		}
		existing := &models.Sandbox{
			ID:             "sb-existing",
			Runtime:        models.RuntimeWasm,
			Durability:     models.DurabilityDurable,
			CheckpointPath: validPath,
		}
		if got, err := svc.ensureWasmCheckpointLocal(ctx, existing); err != nil || got != validPath {
			t.Fatalf("ensureWasmCheckpointLocal(existing) = (%q, %v)", got, err)
		}

		invalidPath := filepath.Join(dir, "invalid", "mem.snap")
		if err := os.MkdirAll(invalidPath, 0o755); err != nil {
			t.Fatalf("mkdir invalid: %v", err)
		}
		if err := os.WriteFile(filepath.Join(invalidPath, "config.json"), []byte("{}"), 0o600); err != nil {
			t.Fatalf("write invalid file: %v", err)
		}
		if _, err := svc.ensureWasmCheckpointLocal(ctx, &models.Sandbox{
			ID:             "sb-invalid",
			Runtime:        models.RuntimeWasm,
			Durability:     models.DurabilityEphemeral,
			CheckpointPath: invalidPath,
		}); err == nil {
			t.Fatal("expected error for invalid ephemeral checkpoint")
		}

		durable := &models.Sandbox{
			ID:         "sb-durable",
			Runtime:    models.RuntimeWasm,
			Durability: models.DurabilityDurable,
		}
		if _, err := svc.ensureWasmCheckpointLocal(ctx, durable); err == nil || !strings.Contains(err.Error(), "AOCR pull is disabled") {
			t.Fatalf("durable checkpoint without pusher = %v", err)
		}

		pusher := &recordingCheckpointStore{}
		svc.wasmCheckpointPusher = pusher
		if _, err := svc.ensureWasmCheckpointLocal(ctx, durable); err == nil || !strings.Contains(err.Error(), "no AOCR ref") {
			t.Fatalf("durable checkpoint without ref = %v", err)
		}

		pusher.destRef = "test://sb-durable:latest"
		if err := st.Create(ctx, &models.Sandbox{
			ID:         "sb-durable",
			Runtime:    models.RuntimeWasm,
			Durability: models.DurabilityDurable,
			Status:     models.SandboxStatusStarted,
			CreatedAt:  time.Now().UTC(),
			UpdatedAt:  time.Now().UTC(),
		}); err != nil {
			t.Fatalf("Create durable sandbox: %v", err)
		}
		gotPath, err := svc.ensureWasmCheckpointLocal(ctx, &models.Sandbox{
			ID:         "sb-durable",
			Runtime:    models.RuntimeWasm,
			Durability: models.DurabilityDurable,
		})
		if err != nil {
			t.Fatalf("ensureWasmCheckpointLocal durable pull: %v", err)
		}
		if len(pusher.pullCalls) != 1 {
			t.Fatalf("PullOnce calls = %d", len(pusher.pullCalls))
		}
		if gotPath == "" {
			t.Fatal("checkpoint path is empty")
		}
		pusher = &recordingCheckpointStore{destRef: "test://sb-push:latest"}
		if got := pusher.DestRefTagged("sb-push", "latest"); !strings.Contains(got, "sb-push:latest") {
			t.Fatalf("DestRefTagged = %q", got)
		}

		cpusher, err := NewWasmCheckpointPusher(SnapshotPushConfig{Enabled: true, Host: "aocr.test", ClusterID: "c1", PATPath: filepath.Join(dir, "pat")}, nil)
		if err != nil {
			t.Fatalf("NewWasmCheckpointPusher: %v", err)
		}
		if cpusher.DestRefTagged(" ", "latest") != "" {
			t.Fatal("blank sandbox id should return empty dest ref")
		}
		if _, err := cpusher.PushOnce(context.Background(), "", "/tmp"); err == nil {
			t.Fatal("PushOnce should reject empty sandbox id")
		}
		if _, err := cpusher.PushOnceTo(context.Background(), "sb", "/tmp", ""); err == nil {
			t.Fatal("PushOnceTo should reject empty destination")
		}
		if err := cpusher.PullOnce(context.Background(), "", "/tmp"); err == nil {
			t.Fatal("PullOnce should reject empty registry ref")
		}
		if err := cpusher.DeleteRef(context.Background(), ""); err == nil {
			t.Fatal("DeleteRef should reject empty ref")
		}
	})
}

func TestClusterSecretAndCustomDomainRollbackBranches(t *testing.T) {
	ctx := context.Background()

	if _, err := (&Service{}).SealClusterSecrets(models.CreateSandboxRequest{
		Image: "alpine",
		Registry: &models.RegistryAuth{
			Server:   "ghcr.io",
			Username: "alice",
			Password: "secret",
		},
	}); err == nil || !strings.Contains(err.Error(), "cipher is not configured") {
		t.Fatalf("SealClusterSecrets without cipher = %v, want configured-cipher error", err)
	}

	cryptoSvc := &Service{cipher: newTestCipher(t)}
	plain := []byte("legacy-sealed-secret")
	rawSealed, err := cryptoSvc.cipher.Encrypt(plain)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if got, err := cryptoSvc.openClusterSecretPayload(rawSealed, "node-a"); err != nil || string(got) != string(plain) {
		t.Fatalf("openClusterSecretPayload(raw) = (%q, %v), want plaintext", string(got), err)
	}

	req := models.CreateSandboxRequest{
		Image: "alpine",
		Registry: &models.RegistryAuth{
			Server:   "ghcr.io",
			Username: "alice",
			Password: "secret",
		},
		Mounts: []models.MountSpec{{
			Type:        models.MountTypeS3,
			Target:      "/data",
			Source:      "bucket",
			Credentials: map[string]string{"token": "mount-secret"},
		}},
	}
	sealed, err := cryptoSvc.SealClusterSecretsForRecipient(req, "node-a")
	if err != nil {
		t.Fatalf("SealClusterSecretsForRecipient: %v", err)
	}
	if _, err := cryptoSvc.openClusterSecretPayload(sealed, "node-b"); err == nil || !strings.Contains(err.Error(), "not allowed") {
		t.Fatalf("openClusterSecretPayload(recipient mismatch) = %v, want recipient denied", err)
	}

	svc := &Service{cipher: newTestCipher(t)}
	stub := &specWriteThroughCluster{
		Noop: cluster.NewNoop("self", "http://self", ""),
		spec: &models.CreateSandboxRequest{Image: "alpine", CPU: 1, MemoryMB: 512, DiskGB: 1},
	}
	svc.AttachCluster(stub)
	svc.replicateSpecPatch(ctx, "sb-replicate", func(spec *models.CreateSandboxRequest) {
		spec.CPU = 4
		spec.MemoryMB = 2048
	})
	calls := stub.calls()
	if len(calls) != 1 || calls[0].CPU != 4 || calls[0].MemoryMB != 2048 {
		t.Fatalf("replicateSpecPatch calls = %+v, want one updated spec", calls)
	}

	svc.replicateSpecPatch(ctx, "sb-no-cluster", func(spec *models.CreateSandboxRequest) {
		spec.CPU = 8
	})

	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	svc = &Service{
		cfg: config.Config{
			EnableCustomDomains: true,
			Domain:              "sandbox.test",
			HTTPClientTimeout:   time.Second,
		},
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		store:  st,
		caddy:  caddy.New(config.Config{EnableCaddy: false, HTTPClientTimeout: time.Second}),
	}
	clusterStub := &customDomainConflictCluster{Noop: cluster.NewNoop("self", "http://self", "sandbox.test")}
	svc.AttachCluster(clusterStub)
	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID:           "sb-domains",
		Image:        "alpine",
		Status:       models.SandboxStatusStarted,
		Runtime:      models.RuntimeDocker,
		ContainerID:  "ctr-domains",
		ContainerIP:  "10.0.0.70",
		CPU:          1,
		MemoryMB:     256,
		DiskGB:       5,
		CreatedAt:    now,
		UpdatedAt:    now,
		LastActiveAt: now,
	}); err != nil {
		t.Fatalf("seed sandbox: %v", err)
	}
	err = svc.persistCustomDomainsOnCreate(ctx, "sb-domains", []string{"api.sandbox.test", "www.sandbox.test"})
	if err == nil {
		t.Fatal("persistCustomDomainsOnCreate should fail on cluster conflict")
	}
	if len(clusterStub.removeCalls) == 0 {
		t.Fatal("persistCustomDomainsOnCreate should rollback earlier domain rows on failure")
	}
	domains, err := svc.ListCustomDomains(ctx, "sb-domains")
	if err != nil {
		t.Fatalf("ListCustomDomains after rollback: %v", err)
	}
	if len(domains) != 0 {
		t.Fatalf("custom domains survived rollback: %+v", domains)
	}
}

func TestWasmCheckpointAndMigrationHelperBranches(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.store = st
	svc.cfg.EnableWasm = true
	svc.cfg.WasmModulesDir = filepath.Join(dir, "modules")

	if _, _, err := svc.MigrateWasmSandbox(ctx, "sb-no-driver", dir); err == nil || !strings.Contains(err.Error(), "wasm runtime not configured") {
		t.Fatalf("MigrateWasmSandbox without runtime = %v", err)
	}
	svc.SetWasmRuntime(&fakeCapacityRuntime{})
	if _, _, err := svc.MigrateWasmSandbox(ctx, "sb-no-migration-host", dir); err == nil || !strings.Contains(err.Error(), "does not implement migration") {
		t.Fatalf("MigrateWasmSandbox without migration host = %v", err)
	}

	if err := st.Create(ctx, &models.Sandbox{
		ID:        "sb-docker",
		Runtime:   models.RuntimeDocker,
		Status:    models.SandboxStatusStarted,
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("seed docker sandbox: %v", err)
	}
	svc.SetWasmRuntime(&fakeWasmMigrateRuntime{snapDir: t.TempDir(), cloneGen: "gen-1"})
	if _, _, err := svc.MigrateWasmSandbox(ctx, "sb-docker", dir); err == nil || !strings.Contains(err.Error(), "not wasm runtime") {
		t.Fatalf("MigrateWasmSandbox(non-wasm row) = %v", err)
	}

	svc.cfg.EnableWasm = false
	if _, err := svc.ExportWasmMigration(ctx, "sb-any", io.Discard); err == nil || !strings.Contains(err.Error(), "not configured") {
		t.Fatalf("ExportWasmMigration disabled = %v", err)
	}
	svc.cfg.EnableWasm = true
	if err := svc.ImportWasmMigration(ctx, " ", "", bytes.NewReader(nil)); err == nil || !strings.Contains(err.Error(), "sandbox id required") {
		t.Fatalf("ImportWasmMigration blank ID = %v", err)
	}

	snap := wasmengine.SnapshotRestoreInput{
		Config: wasmengine.SnapshotConfig{
			SchemaVersion:   1,
			Engine:          wasmengine.EngineNameWazero(),
			BaseModule:      wasmengine.SnapshotBaseModule{Digest: "sha256:abc"},
			Durability:      models.DurabilityPassivatable,
			CloneGeneration: "gen-new",
		},
		Memory:    []byte("mem"),
		Globals:   []byte("[]"),
		WASIState: []byte("{}"),
	}
	if err := svc.ensureWasmSandboxRowForImport(ctx, "sb-import", snap, filepath.Join(dir, "checkpoint"), "gen-new"); err == nil || !strings.Contains(err.Error(), "module_ref required") {
		t.Fatalf("ensureWasmSandboxRowForImport missing module ref = %v", err)
	}

	migrateSvc := New(config.Config{EnableWasm: true, WasmModulesDir: filepath.Join(dir, "modules")}, slog.New(slog.NewTextHandler(io.Discard, nil)), st, nil, nil, nil, nil, nil, nil)
	migrateSvc.SetWasmRuntime(&fakeWasmMigrateRuntime{snapDir: t.TempDir(), cloneGen: "gen-1"})

	ownerAlreadyTarget := &wasmMigrationTargetClusterStub{
		Noop:  cluster.NewNoop("node-a", "http://self", ""),
		owner: cluster.OwnerInfo{NodeID: "node-b", APIURL: "http://peer", IsSelf: false},
		members: []cluster.Member{
			{NodeID: "node-a", APIURL: "http://self", Alive: true, Role: config.NodeRoleWorker},
			{NodeID: "node-b", APIURL: "http://peer", Alive: true, Role: config.NodeRoleWorker},
		},
		spec: &models.CreateSandboxRequest{Runtime: models.RuntimeWasm, ModuleRef: "file:///tmp/demo.wasm"},
	}
	migrateSvc.AttachCluster(ownerAlreadyTarget)
	if _, err := migrateSvc.MigrateWasmSandboxToNode(ctx, "sb-target", "node-b"); err == nil || !strings.Contains(err.Error(), "already owns") {
		t.Fatalf("MigrateWasmSandboxToNode target already owns = %v", err)
	}

	notAliveCluster := &wasmMigrationTargetClusterStub{
		Noop:  cluster.NewNoop("node-a", "http://self", ""),
		owner: cluster.OwnerInfo{NodeID: "node-a", APIURL: "http://self", IsSelf: true},
		members: []cluster.Member{
			{NodeID: "node-a", APIURL: "http://self", Alive: true, Role: config.NodeRoleWorker},
			{NodeID: "node-b", APIURL: "http://peer", Alive: false, Role: config.NodeRoleWorker},
		},
		spec: &models.CreateSandboxRequest{Runtime: models.RuntimeWasm, ModuleRef: "file:///tmp/demo.wasm"},
	}
	migrateSvc.AttachCluster(notAliveCluster)
	if _, err := migrateSvc.MigrateWasmSandboxToNode(ctx, "sb-target", "node-b"); err == nil || !strings.Contains(err.Error(), "not found or not alive") {
		t.Fatalf("MigrateWasmSandboxToNode target not alive = %v", err)
	}

	drainedCluster := &wasmMigrationTargetClusterStub{
		Noop:  cluster.NewNoop("node-a", "http://self", ""),
		owner: cluster.OwnerInfo{NodeID: "node-a", APIURL: "http://self", IsSelf: true},
		members: []cluster.Member{
			{NodeID: "node-a", APIURL: "http://self", Alive: true, Role: config.NodeRoleWorker},
			{NodeID: "node-b", APIURL: "http://peer", Alive: true, Role: config.NodeRoleWorker},
		},
		drained: map[string]bool{"node-b": true},
		spec:    &models.CreateSandboxRequest{Runtime: models.RuntimeWasm, ModuleRef: "file:///tmp/demo.wasm"},
	}
	migrateSvc.AttachCluster(drainedCluster)
	if _, err := migrateSvc.MigrateWasmSandboxToNode(ctx, "sb-target", "node-b"); err == nil || !strings.Contains(err.Error(), "drained") {
		t.Fatalf("MigrateWasmSandboxToNode target drained = %v", err)
	}

	if _, ok := memberByID([]cluster.Member{{NodeID: "node-a"}}, "missing"); ok {
		t.Fatal("memberByID should return false for missing node")
	}
	if got, ok := memberByID([]cluster.Member{{NodeID: "node-a", Alive: true}}, "node-a"); !ok || got.NodeID != "node-a" {
		t.Fatalf("memberByID found = (%+v, %v), want node-a/true", got, ok)
	}

	target, ok := selectWasmEvacuationTarget(&wasmMigrationTargetClusterStub{
		Noop: cluster.NewNoop("self", "http://self", ""),
		members: []cluster.Member{
			{NodeID: "dead", Alive: false, APIURL: "http://dead", Role: config.NodeRoleWorker},
			{NodeID: "self", Alive: true, APIURL: "http://self", Role: config.NodeRoleWorker},
			{NodeID: "drained", Alive: true, APIURL: "http://drained", Role: config.NodeRoleWorker},
			{NodeID: "noapi", Alive: true, APIURL: "", Role: config.NodeRoleWorker},
			{NodeID: "badrole", Alive: true, APIURL: "http://badrole", Role: config.NodeRoleServer},
			{NodeID: "worker", Alive: true, APIURL: "http://worker", Role: config.NodeRoleWorker},
		},
		drained: map[string]bool{"drained": true},
	}, "self")
	if !ok || target.NodeID != "worker" {
		t.Fatalf("selectWasmEvacuationTarget = (%+v, %v), want worker/true", target, ok)
	}

	checkpointRT := &fakeCheckpointRuntime{
		checkpointPath: "/tmp/checkpoint",
		cloneGen:       "gen-1",
		wasmRecordingRuntime: wasmRecordingRuntime{
			managed: map[string]*models.SandboxRuntimeState{
				"sb-evict": {SandboxID: "sb-evict"},
			},
		},
	}
	evacSvc, evacStore, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	evacSvc.cfg.EnableWasm = true
	evacSvc.SetWasmRuntime(checkpointRT)
	now := time.Now().UTC()
	if err := evacStore.Create(ctx, &models.Sandbox{
		ID:         "sb-evict",
		Runtime:    models.RuntimeWasm,
		Status:     models.SandboxStatusStarted,
		Durability: models.DurabilityPassivatable,
		CreatedAt:  now,
		UpdatedAt:  now,
	}); err != nil {
		t.Fatalf("seed wasm sandbox: %v", err)
	}
	evacSvc.AttachCluster(&wasmMigrationTargetClusterStub{
		Noop:    cluster.NewNoop("self", "http://self", ""),
		owner:   cluster.OwnerInfo{NodeID: "self", APIURL: "http://self", IsSelf: true},
		members: []cluster.Member{{NodeID: "self", APIURL: "http://self", Alive: true, Role: config.NodeRoleWorker}},
		spec:    &models.CreateSandboxRequest{Runtime: models.RuntimeWasm, ModuleRef: "file:///tmp/demo.wasm"},
	})
	if err := evacSvc.EvacuateLocalWasmSandboxesForDrain(ctx); err == nil || !strings.Contains(err.Error(), "no evacuation target") {
		t.Fatalf("EvacuateLocalWasmSandboxesForDrain = %v, want no target error", err)
	}

	checkpointSvc, checkpointStore, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	checkpointSvc.cfg.EnableWasm = true
	failingCheckpointHost := &fakeCheckpointRuntime{
		checkpointErr: errors.New("checkpoint failed"),
		wasmRecordingRuntime: wasmRecordingRuntime{
			managed: map[string]*models.SandboxRuntimeState{
				"sb-checkpoint": {SandboxID: "sb-checkpoint"},
			},
		},
	}
	checkpointSvc.SetWasmRuntime(failingCheckpointHost)
	if err := checkpointStore.Create(ctx, &models.Sandbox{
		ID:         "sb-checkpoint",
		Runtime:    models.RuntimeWasm,
		Status:     models.SandboxStatusStarted,
		Durability: models.DurabilityPassivatable,
		CreatedAt:  now,
		UpdatedAt:  now,
	}); err != nil {
		t.Fatalf("seed checkpoint sandbox: %v", err)
	}
	sandbox, err := checkpointStore.Get(ctx, "sb-checkpoint")
	if err != nil {
		t.Fatalf("Get checkpoint sandbox: %v", err)
	}
	if err := checkpointSvc.checkpointWasmSandbox(ctx, failingCheckpointHost, sandbox); err != nil {
		t.Fatalf("checkpointWasmSandbox error path should return nil: %v", err)
	}
	got, err := checkpointStore.Get(ctx, "sb-checkpoint")
	if err != nil {
		t.Fatalf("Get checkpointed sandbox: %v", err)
	}
	if got.Status != models.SandboxStatusPassivateFailed {
		t.Fatalf("checkpoint failure status = %q, want passivate_failed", got.Status)
	}

	liveCheckpointHost := &fakeCheckpointRuntime{
		liveCheckpointErr: errors.New("live checkpoint failed"),
	}
	if err := checkpointSvc.checkpointLiveWasmSandbox(ctx, liveCheckpointHost, got); err != nil {
		t.Fatalf("checkpointLiveWasmSandbox error path should return nil: %v", err)
	}

	cancelCtx, cancel := context.WithCancel(ctx)
	cancel()
	if err := checkpointSvc.runWasmCheckpointPool(cancelCtx, []*models.Sandbox{{ID: "sb-1"}}, func(*models.Sandbox) error { return nil }); !errors.Is(err, context.Canceled) {
		t.Fatalf("runWasmCheckpointPool canceled = %v, want context.Canceled", err)
	}
}

func TestTemplatePullHelperBranches(t *testing.T) {
	ctx := context.Background()

	if _, err := NewTemplateArtifactPuller(nil, t.TempDir(), slog.Default()); err == nil {
		t.Fatal("NewTemplateArtifactPuller should reject nil docker client")
	}
	if _, err := NewTemplateArtifactPuller(&fakeTemplatePullDocker{}, " ", slog.Default()); err == nil {
		t.Fatal("NewTemplateArtifactPuller should reject blank templatesDir")
	}

	puller := newTestPuller(t, &fakeTemplatePullDocker{}, t.TempDir())
	if err := puller.PullOnce(ctx, nil); err == nil {
		t.Fatal("PullOnce should reject nil template")
	}
	if err := puller.PullOnce(ctx, &models.Template{}); err == nil {
		t.Fatal("PullOnce should reject blank template ID")
	}
	if err := puller.PullOnce(ctx, &models.Template{ID: "tpl-1"}); err == nil {
		t.Fatal("PullOnce should reject blank registry_ref")
	}

	dir := t.TempDir()
	tpl := &models.Template{RootfsPath: filepath.Join(dir, templateRootfsFilename), SnapshotMemoryPath: filepath.Join(dir, snapshotMemoryFilename), SnapshotStatePath: filepath.Join(dir, snapshotStateFilename)}
	if templateLocalFilesPresent(dir, tpl) {
		t.Fatal("templateLocalFilesPresent should fail when files are missing")
	}
	for _, p := range []string{tpl.RootfsPath, tpl.SnapshotMemoryPath, tpl.SnapshotStatePath} {
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatalf("write %s: %v", p, err)
		}
	}
	if !templateLocalFilesPresent(dir, tpl) {
		t.Fatal("templateLocalFilesPresent should succeed when files exist")
	}

	var outer bytes.Buffer
	tw := tar.NewWriter(&outer)
	if err := tw.WriteHeader(&tar.Header{Name: "metadata.json", Mode: 0o644, Size: 1, Typeflag: tar.TypeReg}); err != nil {
		t.Fatalf("write outer hdr: %v", err)
	}
	if _, err := tw.Write([]byte("x")); err != nil {
		t.Fatalf("write outer body: %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close outer: %v", err)
	}
	if _, err := extractTemplateArtifactsFromSave(bytes.NewReader(outer.Bytes()), t.TempDir()); err == nil {
		t.Fatal("extractTemplateArtifactsFromSave should reject save output without layer.tar")
	}

	var layer bytes.Buffer
	tw = tar.NewWriter(&layer)
	manifest := TemplateArtifactManifest{SchemaVersion: TemplateArtifactSchemaVersion, TemplateID: "tpl-x"}
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	if err := tw.WriteHeader(&tar.Header{Name: templateManifestFilename, Mode: 0o644, Size: int64(len(manifestBytes)), Typeflag: tar.TypeReg}); err != nil {
		t.Fatalf("write manifest hdr: %v", err)
	}
	if _, err := tw.Write(manifestBytes); err != nil {
		t.Fatalf("write manifest body: %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close layer tar: %v", err)
	}
	if _, err := extractTemplateArtifactsFromLayer(bytes.NewReader(layer.Bytes()), t.TempDir()); err == nil {
		t.Fatal("extractTemplateArtifactsFromLayer should reject missing artifact files")
	}

	if err := writeFileFromTar(bytes.NewReader([]byte("abc")), 3, t.TempDir()); err == nil {
		t.Fatal("writeFileFromTar should reject directory destination")
	}
	if _, err := computeSnapshotChecksum(filepath.Join(dir, "missing-memory"), filepath.Join(dir, "missing-state")); err == nil {
		t.Fatal("computeSnapshotChecksum should fail when files are missing")
	}
	if _, err := hashFileSHA256(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("hashFileSHA256 should fail for missing file")
	}
}
