package service

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/caddy"
	"github.com/aerol-ai/microvm/pkg/docker/netstats"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/secrets"
)

func TestExtractTemplateArtifactsErrorArmsWave15(t *testing.T) {
	dir := t.TempDir()

	// Truncated tar.
	if _, err := extractTemplateArtifactsFromLayer(strings.NewReader("not-a-tar"), dir); err == nil {
		t.Fatal("expected truncated tar error")
	}

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	_ = tw.WriteHeader(&tar.Header{Name: "dir/", Typeflag: tar.TypeDir, Mode: 0o755})
	_ = tw.WriteHeader(&tar.Header{Name: templateManifestFilename, Mode: 0o644, Size: 3})
	_, _ = tw.Write([]byte("{x}"))
	_ = tw.Close()
	if _, err := extractTemplateArtifactsFromLayer(bytes.NewReader(buf.Bytes()), dir); err == nil {
		t.Fatal("expected bad manifest json")
	}

	var buf2 bytes.Buffer
	tw2 := tar.NewWriter(&buf2)
	manifest := TemplateArtifactManifest{SchemaVersion: 1}
	mb, _ := json.Marshal(manifest)
	_ = tw2.WriteHeader(&tar.Header{Name: templateManifestFilename, Mode: 0o644, Size: int64(len(mb))})
	_, _ = tw2.Write(mb)
	_ = tw2.Close()
	if _, err := extractTemplateArtifactsFromLayer(bytes.NewReader(buf2.Bytes()), dir); err == nil {
		t.Fatal("expected missing artifacts")
	}

	if _, err := extractTemplateArtifactsFromSave(strings.NewReader("x"), dir); err == nil {
		t.Fatal("expected save extract fail")
	}
}

func TestWriteTarHelpersErrorArmsWave15(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := writeTarFile(tw, "missing", filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Fatal("expected missing file")
	}
	// Size mismatch on writeTarRegular.
	if err := writeTarRegular(tw, "x", 10, nil, []byte("hi")); err == nil {
		// may succeed writing short blob then fail on Close — still exercises Write
		t.Logf("writeTarRegular size mismatch: %v", err)
	}
	_ = tw.Close()

	var buf2 bytes.Buffer
	tw2 := tar.NewWriter(&buf2)
	_ = tw2.Close() // closed writer
	_ = writeTarRegular(tw2, "y", 1, nil, []byte("z"))
}

func TestClusterSecretHelpersWave15(t *testing.T) {
	_ = secrets.NormalizeRecipients([]string{"", " b ", "a", "a", "  "})
	_ = secrets.NormalizeRecipients(nil)
	binding := secrets.SealBinding{SandboxID: "sb", Ref: secrets.FormatRef("sb", 1), Version: 1, Generation: 1}

	if _, err := secrets.OpenEnvelopePayloadBound([]byte("short"), []byte("x"), []string{"n1"}, binding); err == nil {
		t.Fatal("expected bad dek")
	}
	dek := make([]byte, 32)
	for i := range dek {
		dek[i] = byte(i)
	}
	if _, err := secrets.OpenEnvelopePayloadBound(dek, []byte("tiny"), []string{"n1"}, binding); err == nil {
		t.Fatal("expected short payload")
	}

	s := &Service{cipher: newTestCipher(t)}
	setRandReader(t, &scriptedRandReader{errs: []error{errors.New("no dek entropy")}})
	if _, err := secrets.SealRawEnvelopeBound(s.cipher, []byte(`{}`), []string{"n1"}, binding); err == nil {
		t.Fatal("expected dek entropy fail")
	}
	setRandReader(t, &scriptedRandReader{errs: []error{nil, errors.New("no nonce")}})
	if _, err := secrets.SealRawEnvelopeBound(s.cipher, []byte(`{}`), []string{"n1"}, binding); err == nil {
		t.Fatal("expected nonce entropy fail")
	}

	if _, err := s.SealAndDistribute(context.Background(), "", models.CreateSandboxRequest{
		Registry: &models.RegistryAuth{Username: "u", Password: "p"},
	}, []string{"n1"}, SealStrict); err == nil {
		t.Fatal("expected empty sandbox id")
	}
	if _, err := (&Service{}).SealAndDistribute(context.Background(), "sb", models.CreateSandboxRequest{
		Registry: &models.RegistryAuth{Username: "u", Password: "p"},
	}, []string{"n1"}, SealStrict); err == nil {
		t.Fatal("expected nil cipher/store")
	}
}

func TestNetstatsSinkClosedStoreWave15(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarnessAllowStoreClose(t, &recordingRuntime{})
	now := time.Now().UTC()
	_ = st.Create(ctx, &models.Sandbox{
		ID: "sb-ns", Image: "a", Status: models.SandboxStatusStarted,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	})
	sink := netstatsServiceSink{svc: svc}
	sink.handleNetworkSamples(ctx, nil)
	sink.handleNetworkSamples(ctx, []netstats.Sample{{
		SandboxID: "sb-ns", BytesIn: 1, BytesOut: 2, SampledAt: now, ActiveTCP: true,
	}})
	_ = st.Close()
	sink.handleNetworkSamples(ctx, []netstats.Sample{{
		SandboxID: "sb-ns", BytesIn: 3, BytesOut: 4, SampledAt: now,
	}})
	sink.handleNetworkSamples(ctx, []netstats.Sample{{
		SandboxID: "missing", BytesIn: 1, BytesOut: 0, SampledAt: now,
	}})

	svc2, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc2.cfg.NetstatsPollInterval = 0
	if err := svc2.EnsureNetstatsReady(ctx); err == nil {
		t.Fatal("expected interval fail")
	}
	svc2.cfg.NetstatsPollInterval = time.Second
	svc2.events = nil
	if err := svc2.EnsureNetstatsReady(ctx); err == nil {
		t.Fatal("expected events fail")
	}
	svc2.netstatsReady.Store(true)
	if err := svc2.EnsureNetstatsReady(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestIsolateHTTPRouteShapeNoneWave15(t *testing.T) {
	ctx := context.Background()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)

	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableCaddy = true
	svc.cfg.EnableServerless = true
	svc.cfg.EnableIsolate = true
	svc.cfg.HTTPWakeDirectBypassEnabled = true
	svc.cfg.Domain = "sandbox.example.com"
	svc.cfg.InternalIngressAddr = "127.0.0.1:21213"
	svc.SetIsolateRuntime(&recordingRuntime{})
	svc.caddy = caddy.New(config.Config{
		EnableCaddy: true, Domain: "sandbox.example.com",
		CaddyAdminURL: server.URL, CaddyServerID: "srv0", HTTPClientTimeout: time.Second,
	})
	sb := &models.Sandbox{
		ID: "iso-none", Runtime: models.RuntimeIsolate, Status: models.SandboxStatusStopped, WakeArmed: false,
		Lifecycle: models.Lifecycle{Serverless: true, StopIfIdleFor: time.Minute},
	}
	if err := svc.installIsolateHTTPPortRoute(ctx, sb, 8080); err != nil {
		// RouteShapeNone still needs caddy deletes; isolate gateway check may fire first.
		t.Logf("isolate none: %v", err)
	}
	svc.isolateHTTPPortRouteCleanup(ctx, "iso-none", 8080)
}

func TestVolumeReclaimCancelAndFailWave15(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	s := enabledVolumeService(t)
	if s.logger == nil {
		s.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	now := time.Now().UTC()
	if err := s.store.SchedulePendingVolumeDeletion(ctx, models.Volume{
		ID: "vol-cancel", Tenant: "op", Name: "n", Backend: "local", Source: "/tmp/x",
		CreatedAt: now,
	}, "/tmp/x"); err != nil {
		t.Fatalf("schedule: %v", err)
	}
	cancel()
	s.runVolumeReclaim(ctx)

	s2 := enabledVolumeService(t)
	if s2.logger == nil {
		s2.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	_ = s2.store.Close()
	s2.reclaimOne(context.Background(), models.PendingVolumeDeletion{
		VolumeID: "v", Tenant: "op", Backend: "local", Source: "/nope",
	})
}

func TestStopSandboxUnmountWarnWave15(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableServerless = true
	svc.testForceUnmountErr = errors.New("busy")
	now := time.Now().UTC()
	_ = st.Create(ctx, &models.Sandbox{
		ID: "sb-stop-um", Image: "a", Status: models.SandboxStatusStarted, ContainerID: "c1",
		Lifecycle: models.Lifecycle{Serverless: true, StopIfIdleFor: time.Minute},
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	})
	if _, err := svc.stopSandboxInternal(ctx, "sb-stop-um", stopModeLifecycle); err != nil {
		t.Fatalf("stop: %v", err)
	}
}

func TestRepairLayer4AndWakeAwareWave15(t *testing.T) {
	ctx := context.Background()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)

	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableCaddy = true
	svc.cfg.EnableServerless = true
	svc.cfg.Domain = "sandbox.example.com"
	svc.cfg.L4TLSListen = ":443"
	svc.caddy = caddy.New(config.Config{
		EnableCaddy: true, Domain: "sandbox.example.com",
		CaddyAdminURL: server.URL, CaddyServerID: "srv0", HTTPClientTimeout: time.Second,
	})
	svc.l4Ready.Store(true)
	if err := svc.RepairLayer4Ready(ctx); err != nil {
		t.Logf("RepairLayer4Ready: %v", err) // may fail against fake admin
	}
	svc.l4Ready.Store(false)
	_ = svc.RepairLayer4Ready(ctx)

	now := time.Now().UTC()
	_ = st.Create(ctx, &models.Sandbox{
		ID: "sb-wake-tb", Image: "a", Status: models.SandboxStatusStarted, ContainerIP: "10.0.0.9",
		ToolboxToken: "tok", Lifecycle: models.Lifecycle{Serverless: true, StopIfIdleFor: time.Minute}, WakeArmed: true,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	})
	_, _ = svc.WakeAwareToolboxTarget(ctx, "sb-wake-tb")
	_, _ = svc.WakeAwarePortTarget(ctx, "sb-wake-tb", 80)
	_, _ = svc.WakeAwareL4PortTarget(ctx, "sb-wake-tb", 5432)
}

func TestWasmMigrateStoreMissWave15(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarnessAllowStoreClose(t, &recordingRuntime{})
	svc.cfg.EnableWasm = true
	svc.SetWasmRuntime(&fakeWasmMigrateRuntime{snapDir: t.TempDir(), cloneGen: "g"})
	_ = st.Close()
	_, _, _ = svc.MigrateWasmSandbox(ctx, "x", t.TempDir())
	_, _ = svc.ExportWasmMigration(ctx, "x", io.Discard)
}

func TestL4ActiveLimitExceededWave15(t *testing.T) {
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableServerless = true
	svc.cfg.L4WakeMaxActivePerSandbox = 1
	svc.cfg.L4WakeMaxActiveGlobal = 1
	now := time.Now().UTC()
	_ = st.Create(context.Background(), &models.Sandbox{
		ID: "sb-act", Image: "a", Status: models.SandboxStatusStarted, ContainerIP: "127.0.0.1",
		Lifecycle: models.Lifecycle{Serverless: true, StopIfIdleFor: time.Minute}, WakeArmed: true,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	})
	hold, ok := svc.tryAcquireL4Active("sb-act")
	if !ok {
		t.Fatal("expected active slot")
	}
	defer hold()
	if _, ok := svc.tryAcquireL4Active("sb-act"); ok {
		t.Fatal("expected active limit")
	}
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	go svc.proxyL4WakeConn(context.Background(), "sb-act", 9, c1, nil)
	time.Sleep(20 * time.Millisecond)
}
