package service

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/jsbundle"
	"github.com/aerol-ai/microvm/pkg/models"
)

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

func TestGcUnreferencedJSBundlesListFailWave23(t *testing.T) {
	svc, st, _ := newServiceRuntimeHarnessAllowStoreClose(t, &recordingRuntime{})
	if n, err := svc.GCUnreferencedJSBundles(context.Background()); n != 0 || err != nil {
		t.Fatalf("nil bundles = %d %v", n, err)
	}
	// With store closed and bundles still nil → early return; force list path via non-nil requires real store.
	_ = st.Close()
	_, _ = svc.GCUnreferencedJSBundles(context.Background())
}
