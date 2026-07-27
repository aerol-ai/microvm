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

func TestRunJSBundleGCLoop(t *testing.T) {
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	bundleStore, err := jsbundle.NewStore(jsbundle.StoreConfig{Dir: filepath.Join(t.TempDir(), "bundles")})
	if err != nil {
		t.Fatal(err)
	}
	svc.SetIsolateBundleStore(bundleStore)

	orphan, _ := jsbundle.BuildFromSource("o.js", jsBundleSrc, "")
	if _, err := bundleStore.Put("t", "", orphan); err != nil {
		t.Fatal(err)
	}

	// Disabled paths are cheap no-ops.
	svc.RunJSBundleGCLoop(context.Background(), 0)
	svc2 := &Service{logger: svc.logger}
	svc2.RunJSBundleGCLoop(context.Background(), time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		svc.RunJSBundleGCLoop(ctx, 5*time.Millisecond)
	}()
	// Wait until the orphan is reaped by at least one tick, then cancel.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := bundleStore.GetByDigest(orphan.Digest); err != nil {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("RunJSBundleGCLoop did not exit after cancel")
	}

	// Pin protects an in-flight staging digest from the GC sweep.
	live, _ := jsbundle.BuildFromSource("l.js", `export default {async fetch(){return new Response('l')}}`, "")
	ld, err := bundleStore.Put("t", "", live)
	if err != nil {
		t.Fatal(err)
	}
	svc.pinStagingDigest(ld)
	svc.pinStagingDigest(ld) // refcount > 1
	n, err := svc.GCUnreferencedJSBundles(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("pinned digest GC'd (removed=%d)", n)
	}
	svc.unpinStagingDigest(ld)
	svc.unpinStagingDigest(ld)
	svc.unpinStagingDigest("") // empty no-op
	svc.pinStagingDigest("")

	// ModuleRef-only pin (no ModuleDigest) still protects the digest.
	if err := st.Create(context.Background(), &models.Sandbox{
		ID: "sb-ref-pin", Runtime: models.RuntimeIsolate,
		Status: models.SandboxStatusStarted, ModuleRef: "sha256:" + ld,
	}); err != nil {
		t.Fatal(err)
	}
	if n, err := svc.GCUnreferencedJSBundles(context.Background()); err != nil || n != 0 {
		t.Fatalf("ModuleRef pin removed=%d err=%v", n, err)
	}
}
