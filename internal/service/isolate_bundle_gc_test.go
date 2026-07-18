package service

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/aerol-ai/microvm/pkg/jsbundle"
	"github.com/aerol-ai/microvm/pkg/models"
)

func TestGCUnreferencedJSBundles(t *testing.T) {
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	bundleStore, err := jsbundle.NewStore(jsbundle.StoreConfig{Dir: filepath.Join(t.TempDir(), "bundles")})
	if err != nil {
		t.Fatal(err)
	}
	svc.SetIsolateBundleStore(bundleStore)

	orphan, _ := jsbundle.BuildFromSource("o.js", "export default {async fetch(){return new Response('o')}}", "")
	live, _ := jsbundle.BuildFromSource("l.js", "export default {async fetch(){return new Response('l')}}", "")
	od, err := bundleStore.Put("t", "", orphan)
	if err != nil {
		t.Fatal(err)
	}
	ld, err := bundleStore.Put("t", "", live)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	if err := st.Create(ctx, &models.Sandbox{
		ID:           "sb-live",
		Runtime:      models.RuntimeIsolate,
		Status:       models.SandboxStatusStarted,
		ModuleDigest: ld,
		ModuleRef:    "sha256:" + ld,
	}); err != nil {
		t.Fatal(err)
	}

	n, err := svc.GCUnreferencedJSBundles(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("removed = %d, want 1", n)
	}
	if _, err := bundleStore.GetByDigest(od); err == nil {
		t.Fatal("orphan digest still present")
	}
	if _, err := bundleStore.GetByDigest(ld); err != nil {
		t.Fatalf("live digest GC'd: %v", err)
	}
}
