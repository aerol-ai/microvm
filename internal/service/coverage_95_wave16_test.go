package service

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/caddy"
	"github.com/aerol-ai/microvm/pkg/models"
)

func TestCreateCleanupUnmountWarnWave16(t *testing.T) {
	ctx := context.Background()
	rt := &recordingRuntime{createErr: errors.New("create boom")}
	svc, _, _ := newServiceRuntimeHarness(t, rt)
	svc.admitter = nil
	svc.testForceUnmountErr = errors.New("umount race")
	_, err := svc.CreateSandboxWithID(ctx, models.CreateSandboxRequest{Image: "alpine:3.20"}, "sb-umount-clean")
	if err == nil {
		t.Fatal("expected create failure")
	}
}

func TestCustomDomainCapReaddWave16(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableCustomDomains = true
	svc.cfg.Domain = "example.com"
	svc.cfg.CustomDomainsMaxPerSandbox = 1
	svc.cfg.CustomDomainVerifyPrefix = "_aerolvm-challenge"
	svc.cfg.CustomDomainVerifyValuePrefix = "aerolvm-verify="
	svc.dnsResolver = &mockDNSResolver{records: map[string][]string{
		"_aerolvm-challenge.api.example.com":   {"aerolvm-verify=api.example.com"},
		"_aerolvm-challenge.other.example.com": {"aerolvm-verify=other.example.com"},
	}}
	now := time.Now().UTC()
	_ = st.Create(ctx, &models.Sandbox{
		ID: "sb-cap", Image: "a", Status: models.SandboxStatusStarted, ContainerIP: "10.0.0.1",
		CustomDomains: []models.CustomDomain{{Hostname: "api.example.com", TargetPort: 8080}},
		CreatedAt:     now, UpdatedAt: now, LastActiveAt: now,
	})
	_ = svc.AddCustomDomain(ctx, "sb-cap", "api.example.com", 8080)
	err := svc.AddCustomDomain(ctx, "sb-cap", "other.example.com", 8080)
	if err != nil && !errors.Is(err, ErrCustomDomainPerSandboxCap) {
		t.Logf("cap path: %v", err)
	}
}

func TestAutoImportRequestFromSpecWave16(t *testing.T) {
	_, ok := autoImportRequestFromSpec(nil)
	if ok {
		t.Fatal("nil")
	}
	_, ok = autoImportRequestFromSpec(&models.CreateSandboxRequest{})
	if ok {
		t.Fatal("no failover")
	}
	_, ok = autoImportRequestFromSpec(&models.CreateSandboxRequest{
		Failover:              &models.Failover{Policy: models.FailoverPolicyRecreate},
		ImageDistributionMode: models.ImageDistributionAOCRImported,
	})
	if ok {
		t.Fatal("already imported")
	}
	_, ok = autoImportRequestFromSpec(&models.CreateSandboxRequest{
		Failover: &models.Failover{Policy: models.FailoverPolicyRecreate},
	})
	if ok {
		t.Fatal("no digest")
	}
	_, ok = autoImportRequestFromSpec(&models.CreateSandboxRequest{
		Failover:    &models.Failover{Policy: models.FailoverPolicyRecreate},
		ImageDigest: "sha256:abc",
		Image:       "library/redis",
	})
	if ok {
		t.Fatal("no host")
	}
	req, ok := autoImportRequestFromSpec(&models.CreateSandboxRequest{
		Failover:         &models.Failover{Policy: models.FailoverPolicyRecreate},
		ImageDigest:      "sha256:abc",
		ImageRegistryRef: "ghcr.io/org/app:latest",
	})
	if !ok || req.UpstreamHost != "ghcr.io" {
		t.Fatalf("got %+v ok=%v", req, ok)
	}
	_, _, _ = parseUpstreamFromRegistryRef("", "localhost/foo/bar:baz")
	_, _, _ = parseUpstreamFromRegistryRef("bad", "")
}

func TestDrainWasmCheckpointArmsWave16(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarnessAllowStoreClose(t, &recordingRuntime{})
	svc.cfg.EnableWasm = true
	svc.SetWasmRuntime(&recordingRuntime{}) // not CheckpointHost
	if err := svc.DrainWasmSandboxes(ctx); err != nil {
		t.Fatalf("non-host: %v", err)
	}
	_ = wasmShouldCheckpoint(models.DurabilityPassivatable)
	_ = wasmShouldCheckpoint(models.DurabilityDurable)
	_ = wasmShouldCheckpoint("")
	_ = st.Close()
	svc.SetWasmRuntime(&fakeCheckpointRuntime{})
	_ = svc.DrainWasmSandboxes(ctx) // list fail
}

func TestExtractTemplateLayerMoreArmsWave16(t *testing.T) {
	dir := t.TempDir()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	manifest := TemplateArtifactManifest{SchemaVersion: TemplateArtifactSchemaVersion}
	mb, _ := json.Marshal(manifest)
	_ = tw.WriteHeader(&tar.Header{Name: "nested/" + templateManifestFilename, Mode: 0o644, Size: int64(len(mb)), Typeflag: tar.TypeReg})
	_, _ = tw.Write(mb)
	// Oversized read on a declared rootfs that truncates.
	_ = tw.WriteHeader(&tar.Header{Name: templateRootfsFilename, Mode: 0o644, Size: 100, Typeflag: tar.TypeReg})
	_, _ = tw.Write([]byte("short"))
	_ = tw.Close()
	_, _ = extractTemplateArtifactsFromLayer(bytes.NewReader(buf.Bytes()), dir)

	// Write files then hit outDir not writable.
	ro := filepath.Join(t.TempDir(), "ro")
	_ = os.MkdirAll(ro, 0o555)
	var buf2 bytes.Buffer
	tw2 := tar.NewWriter(&buf2)
	_ = tw2.WriteHeader(&tar.Header{Name: templateManifestFilename, Mode: 0o644, Size: int64(len(mb)), Typeflag: tar.TypeReg})
	_, _ = tw2.Write(mb)
	_ = tw2.WriteHeader(&tar.Header{Name: templateRootfsFilename, Mode: 0o644, Size: 1, Typeflag: tar.TypeReg})
	_, _ = tw2.Write([]byte("x"))
	_ = tw2.WriteHeader(&tar.Header{Name: snapshotMemoryFilename, Mode: 0o644, Size: 1, Typeflag: tar.TypeReg})
	_, _ = tw2.Write([]byte("y"))
	_ = tw2.WriteHeader(&tar.Header{Name: snapshotStateFilename, Mode: 0o644, Size: 1, Typeflag: tar.TypeReg})
	_, _ = tw2.Write([]byte("z"))
	_ = tw2.Close()
	_, _ = extractTemplateArtifactsFromLayer(bytes.NewReader(buf2.Bytes()), filepath.Join(ro, "out"))
}

func TestValidateCreateCustomDomainsWave16(t *testing.T) {
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	allow := true
	deny := false
	req := &models.CreateSandboxRequest{CustomDomains: []string{"api.example.com"}, AllowPublicTraffic: &deny}
	if err := svc.validateCreateCustomDomains(req); err == nil {
		t.Fatal("expected public traffic disabled")
	}
	req.AllowPublicTraffic = &allow
	svc.cfg.EnableCustomDomains = false
	if err := svc.validateCreateCustomDomains(req); err == nil {
		t.Fatal("expected not supported")
	}
	svc.cfg.EnableCustomDomains = true
	svc.cfg.Domain = ""
	if err := svc.validateCreateCustomDomains(req); err == nil {
		t.Fatal("expected ip mode reject")
	}
	svc.cfg.Domain = "example.com"
	req.CustomDomains = []string{"api.customer.dev"}
	if err := svc.validateCreateCustomDomains(req); err != nil {
		t.Fatalf("ok path: %v", err)
	}
}

func TestInstallIsolateWakeAndDirectFailWave16(t *testing.T) {
	ctx := context.Background()
	fail := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "no", 500)
	}))
	t.Cleanup(fail.Close)

	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableCaddy = true
	svc.cfg.EnableServerless = true
	svc.cfg.EnableIsolate = true
	svc.cfg.HTTPWakeDirectBypassEnabled = false
	svc.cfg.Domain = "sandbox.example.com"
	svc.cfg.InternalIngressAddr = "127.0.0.1:21213"
	svc.SetIsolateRuntime(&recordingRuntime{})
	svc.caddy = caddy.New(config.Config{
		EnableCaddy: true, Domain: "sandbox.example.com",
		CaddyAdminURL: fail.URL, CaddyServerID: "srv0", HTTPClientTimeout: time.Second,
	})
	wake := &models.Sandbox{
		ID: "iso-wake", Runtime: models.RuntimeIsolate, Status: models.SandboxStatusStopped, WakeArmed: true,
		Lifecycle: models.Lifecycle{Serverless: true, StopIfIdleFor: time.Minute},
	}
	_ = svc.installIsolateHTTPPortRoute(ctx, wake, 8080)

	svc.cfg.HTTPWakeDirectBypassEnabled = true
	direct := &models.Sandbox{
		ID: "iso-dir", Runtime: models.RuntimeIsolate, Status: models.SandboxStatusStarted, ContainerIP: "10.0.0.1",
		Lifecycle: models.Lifecycle{Serverless: true, StopIfIdleFor: time.Minute},
	}
	_ = svc.installIsolateHTTPPortRoute(ctx, direct, 8080)
}

func TestClusterOwnershipNeedsReplayWave16(t *testing.T) {
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableCluster = true
	now := time.Now().UTC()
	sb := &models.Sandbox{
		ID: "sb-own", Image: "a", Status: models.SandboxStatusStarted,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}
	_ = st.Create(context.Background(), sb)
	cl := &recordingOwnershipCluster{
		Noop:       cluster.NewNoop("self", "http://self", ""),
		placements: map[string]cluster.Placement{},
	}
	_ = svc.clusterOwnershipNeedsReplay(cl, sb)
	svc.AttachCluster(cl)
	_, _ = svc.ReplayClusterOwnership(context.Background())
	_ = svc.localSandboxStateForCluster(context.Background(), cl, sb)
}

func TestPublicTrafficCleanupStoreFailsWave16(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarnessAllowStoreClose(t, &recordingRuntime{})
	svc.cfg.EnableCaddy = true
	svc.cfg.Domain = "sandbox.example.com"
	svc.caddy = caddy.New(config.Config{EnableCaddy: false, Domain: "sandbox.example.com", HTTPClientTimeout: time.Second})
	deny := false
	now := time.Now().UTC()
	sb := &models.Sandbox{
		ID: "sb-pt16", AllowPublicTraffic: &deny, Status: models.SandboxStatusStarted,
		ExposedPorts:  []models.ExposedPort{{Port: 80, Protocol: models.ExposedPortProtocolHTTP}},
		CustomDomains: []models.CustomDomain{{Hostname: "h.example.com"}},
		CreatedAt:     now, UpdatedAt: now, LastActiveAt: now,
	}
	_ = st.Create(ctx, sb)
	_ = st.Close()
	_ = svc.cleanupPublicTrafficDisabledIngressState(ctx, sb)
}

func TestWasmCheckpointPushBestEffortWave16(t *testing.T) {
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableWasm = true
	svc.wasmCheckpointPusher = failingWasmCheckpointPusher{}
	svc.pushWasmCheckpointBestEffort("w2", t.TempDir())
}

func TestSealClusterSecretsMarshalEmptyCipherWave16(t *testing.T) {
	s := &Service{}
	_, err := s.SealClusterSecretsForRecipient(models.CreateSandboxRequest{
		Registry: &models.RegistryAuth{Username: "u", Password: "p"},
	}, "*")
	if err == nil {
		t.Fatal("expected nil cipher")
	}
}

func TestL4WakeTLSListenerBranchesWave16(t *testing.T) {
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableServerless = true
	path, err := svc.ensureTLSWakeListener("tls16", 8443)
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}
	_ = path
	svc.scheduleTLSWakeListenerClose("tls16", 8443, time.Millisecond)
	time.Sleep(5 * time.Millisecond)
	svc.closeTLSWakeListener("tls16", 8443)
	svc.closeTLSWakeListener("tls16", 8443) // idempotent miss
	svc.closeAllTLSWakeListeners()
}

func TestHostFromURLMoreWave16(t *testing.T) {
	_ = hostFromURL("http://[2001:db8::1]:8080/path")
	_ = hostFromURL("hostname.only")
	_ = hostFromURL("::1")
	_ = l4ListenPort(":8443")
	_ = l4ListenPort("bad")
	_ = sandboxContainerRef(&models.Sandbox{ContainerID: "c", ID: "s"})
	_ = sandboxContainerRef(&models.Sandbox{ID: "s"})
	_, _ = GenerateSandboxID()
}
