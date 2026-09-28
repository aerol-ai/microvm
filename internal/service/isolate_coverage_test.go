package service

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/jsbundle"
	"github.com/aerol-ai/microvm/pkg/models"
)

func TestCreateIsolateSandboxHappyPath(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableIsolate = true
	driver := &recordingRuntime{
		createState: &models.SandboxRuntimeState{
			SandboxID:    "sb-iso-ok",
			Status:       models.SandboxStatusStarted,
			ModuleDigest: "deadbeef",
		},
	}
	svc.SetIsolateRuntime(driver)

	resp, err := svc.CreateSandboxWithID(ctx, models.CreateSandboxRequest{
		Runtime:   models.RuntimeIsolate,
		ModuleRef: "mybundle",
		MemoryMB:  128,
		Lifecycle: &models.Lifecycle{StopIfIdleFor: time.Minute},
	}, "sb-iso-ok")
	if err != nil {
		t.Fatalf("CreateSandboxWithID: %v", err)
	}
	if resp.Sandbox.ID != "sb-iso-ok" || resp.Sandbox.ContainerIP != "127.0.0.1" {
		t.Fatalf("sandbox = %+v", resp.Sandbox)
	}
	if resp.Sandbox.ModuleDigest != "deadbeef" {
		t.Fatalf("ModuleDigest = %q", resp.Sandbox.ModuleDigest)
	}
	stored, err := st.Get(ctx, "sb-iso-ok")
	if err != nil || stored.Runtime != models.RuntimeIsolate {
		t.Fatalf("store row = %+v err=%v", stored, err)
	}
}

func TestCreateIsolateSandboxDuplicateIdempotent(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableIsolate = true
	driver := &recordingRuntime{}
	svc.SetIsolateRuntime(driver)

	first, err := svc.CreateSandboxWithID(ctx, models.CreateSandboxRequest{
		Runtime: models.RuntimeIsolate, ModuleRef: "mybundle",
	}, "sb-iso-dup")
	if err != nil {
		t.Fatalf("first create: %v", err)
	}
	// Second create with the same id hits ErrSandboxExists after driver.Create;
	// must return the committed row rather than Destroy the winner.
	second, err := svc.CreateSandboxWithID(ctx, models.CreateSandboxRequest{
		Runtime: models.RuntimeIsolate, ModuleRef: "mybundle",
	}, "sb-iso-dup")
	if err != nil {
		t.Fatalf("duplicate create: %v", err)
	}
	if second.Sandbox.ID != first.Sandbox.ID {
		t.Fatalf("duplicate returned %q, want %q", second.Sandbox.ID, first.Sandbox.ID)
	}
	if len(driver.destroyIDs) != 0 {
		t.Fatalf("duplicate must not Destroy winner, got %v", driver.destroyIDs)
	}
}

func TestCreateIsolateSandboxScopedFileRefRejected(t *testing.T) {
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableIsolate = true
	driver := &recordingRuntime{createErr: errors.New("should not reach")}
	svc.SetIsolateRuntime(driver)

	_, err := svc.CreateSandbox(userCtx("acme"), models.CreateSandboxRequest{
		Runtime: models.RuntimeIsolate, ModuleRef: "file:///etc/passwd",
	})
	if err == nil || !strings.Contains(err.Error(), "operator-only") {
		t.Fatalf("err = %v, want operator-only file:// rejection", err)
	}
	if driver.createCalls != 0 {
		t.Fatal("driver reached for scoped file:// ref")
	}
}

func TestCreateIsolateSandboxBundleStageAndPin(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableIsolate = true
	bundleStore, err := jsbundle.NewStore(jsbundle.StoreConfig{Dir: filepath.Join(t.TempDir(), "bundles")})
	if err != nil {
		t.Fatal(err)
	}
	svc.SetIsolateBundleStore(bundleStore)
	driver := &recordingRuntime{}
	svc.SetIsolateRuntime(driver)

	created, err := svc.CreateJSBundle(ctx, models.CreateJSBundleRequest{Name: "hook", Source: jsBundleSrc})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := svc.CreateSandboxWithID(ctx, models.CreateSandboxRequest{
		Runtime: models.RuntimeIsolate, ModuleRef: "hook",
	}, "sb-iso-bundle")
	if err != nil {
		t.Fatalf("CreateSandbox: %v", err)
	}
	if !strings.HasPrefix(resp.Sandbox.ModuleRef, "sha256:") {
		t.Fatalf("ModuleRef = %q, want sha256: digest pin", resp.Sandbox.ModuleRef)
	}
	if driver.lastCreateReq.ModuleRef != "sha256:"+created.Digest {
		t.Fatalf("driver ModuleRef = %q, want pinned digest", driver.lastCreateReq.ModuleRef)
	}
	// Staging pin is released after create returns.
	if digests := svc.stagingDigests(); len(digests) != 0 {
		t.Fatalf("staging digests left behind: %v", digests)
	}
}

func TestCreateIsolateSandboxDirectValidation(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableIsolate = true
	svc.SetIsolateRuntime(&recordingRuntime{})

	// Direct createIsolateSandbox call covers the helper's own template_id /
	// empty-ref messages (CreateSandbox routes template_id elsewhere).
	_, err := svc.createIsolateSandbox(ctx, models.CreateSandboxRequest{
		Runtime: models.RuntimeIsolate, ModuleRef: "b", TemplateID: "tpl",
	}, "x")
	if err == nil || !strings.Contains(err.Error(), "template_id") {
		t.Fatalf("template_id = %v", err)
	}
	_, err = svc.createIsolateSandbox(ctx, models.CreateSandboxRequest{
		Runtime: models.RuntimeIsolate,
	}, "x")
	if err == nil || !strings.Contains(err.Error(), "module_ref or image") {
		t.Fatalf("empty ref = %v", err)
	}
	_, err = svc.createIsolateSandbox(ctx, models.CreateSandboxRequest{
		Runtime: models.RuntimeIsolate, ModuleRef: "b",
		Lifecycle: &models.Lifecycle{StopIfIdleFor: -time.Second},
	}, "x")
	if err == nil || !strings.Contains(err.Error(), "lifecycle") {
		t.Fatalf("bad lifecycle = %v", err)
	}
}

func TestCreateIsolateSandboxEntropyWave10(t *testing.T) {
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableIsolate = true
	svc.admitter = nil
	svc.SetIsolateRuntime(&recordingRuntime{})
	// Fail the first entropy read so createIsolateSandbox aborts early.
	setRandReader(t, &scriptedRandReader{errs: []error{errors.New("no entropy")}})
	_, err := svc.createIsolateSandbox(context.Background(), models.CreateSandboxRequest{
		Runtime: models.RuntimeIsolate, ModuleRef: "b",
	}, "")
	if err == nil {
		t.Fatal("expected entropy failure")
	}
}

func TestCreateIsolateSandboxDirectDuplicateWave26(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableIsolate = true
	svc.admitter = nil
	driver := &recordingRuntime{
		createState: &models.SandboxRuntimeState{SandboxID: "sb-iso-d26", Status: models.SandboxStatusStarted},
	}
	svc.SetIsolateRuntime(driver)
	now := time.Now().UTC()
	_ = st.Create(ctx, &models.Sandbox{
		ID: "sb-iso-d26", Image: "bundle", Runtime: models.RuntimeIsolate, Status: models.SandboxStatusStarted,
		ModuleRef: "mybundle", CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	})
	resp, err := svc.createIsolateSandbox(ctx, models.CreateSandboxRequest{
		Runtime: models.RuntimeIsolate, ModuleRef: "mybundle",
	}, "sb-iso-d26")
	if err != nil {
		t.Fatalf("duplicate isolate create: %v", err)
	}
	if resp == nil || resp.Sandbox.ID != "sb-iso-d26" {
		t.Fatalf("resp = %+v", resp)
	}
	if len(driver.destroyIDs) != 0 {
		t.Fatalf("must not destroy winner: %v", driver.destroyIDs)
	}
}

func TestCreateIsolateSandboxIDGenerationFailure(t *testing.T) {
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableIsolate = true
	svc.SetIsolateRuntime(&recordingRuntime{})
	setRandReader(t, &scriptedRandReader{errs: []error{errors.New("no entropy")}})
	_, err := svc.createIsolateSandbox(context.Background(), models.CreateSandboxRequest{
		Runtime: models.RuntimeIsolate, ModuleRef: "mybundle",
	}, "")
	if err == nil || !strings.Contains(err.Error(), "generate sandbox id") {
		t.Fatalf("err = %v", err)
	}
}

func TestCreateIsolateSandboxBundleResolveMiss(t *testing.T) {
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableIsolate = true
	svc.SetIsolateRuntime(&recordingRuntime{})
	bundleStore, err := jsbundle.NewStore(jsbundle.StoreConfig{Dir: filepath.Join(t.TempDir(), "b")})
	if err != nil {
		t.Fatal(err)
	}
	svc.SetIsolateBundleStore(bundleStore)
	_, err = svc.CreateSandbox(context.Background(), models.CreateSandboxRequest{
		Runtime: models.RuntimeIsolate, ModuleRef: "missing-name",
	})
	if err == nil || !strings.Contains(err.Error(), "resolve bundle") {
		t.Fatalf("err = %v, want resolve failure", err)
	}
}

func TestCreateIsolateSandboxMemoryDefaultAndNilAdmitter(t *testing.T) {
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableIsolate = true
	svc.admitter = nil
	driver := &recordingRuntime{}
	svc.SetIsolateRuntime(driver)
	resp, err := svc.createIsolateSandbox(context.Background(), models.CreateSandboxRequest{
		Runtime: models.RuntimeIsolate, ModuleRef: "b", MemoryMB: 0,
	}, "sb-mem-default")
	if err != nil {
		t.Fatalf("createIsolateSandbox: %v", err)
	}
	if resp.Sandbox.MemoryMB != models.DefaultMemoryMB {
		t.Fatalf("MemoryMB = %d, want default %d", resp.Sandbox.MemoryMB, models.DefaultMemoryMB)
	}
}
