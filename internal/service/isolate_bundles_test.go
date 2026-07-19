package service

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/jsbundle"
	"github.com/aerol-ai/microvm/pkg/models"
)

const jsBundleSrc = `export default { async fetch(r) { return new Response("ok"); } };`

func newBundleService(t *testing.T) *Service {
	t.Helper()
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableIsolate = true
	bundleStore, err := jsbundle.NewStore(jsbundle.StoreConfig{Dir: filepath.Join(t.TempDir(), "bundles")})
	if err != nil {
		t.Fatal(err)
	}
	svc.SetIsolateBundleStore(bundleStore)
	return svc
}

func TestCreateAndGetJSBundle(t *testing.T) {
	svc := newBundleService(t)
	ctx := context.Background()

	got, err := svc.CreateJSBundle(ctx, models.CreateJSBundleRequest{Name: "hook", Source: jsBundleSrc})
	if err != nil {
		t.Fatal(err)
	}
	if got.Digest == "" || got.ModuleRef != "sha256:"+got.Digest || got.Name != "hook" {
		t.Fatalf("created = %+v", got)
	}
	// Idempotent re-create → same digest.
	again, err := svc.CreateJSBundle(ctx, models.CreateJSBundleRequest{Name: "hook", Source: jsBundleSrc})
	if err != nil || again.Digest != got.Digest {
		t.Fatalf("re-create digest %s != %s (err=%v)", again.Digest, got.Digest, err)
	}
	// Get by digest and by sha256: form.
	for _, id := range []string{got.Digest, "sha256:" + got.Digest} {
		b, err := svc.GetJSBundle(ctx, id)
		if err != nil || b.Digest != got.Digest {
			t.Fatalf("get %q = %+v err=%v", id, b, err)
		}
	}
	if _, err := svc.GetJSBundle(ctx, "notadigest"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("get miss err = %v, want ErrNotFound", err)
	}
}

func TestCreateJSBundleModulesForm(t *testing.T) {
	svc := newBundleService(t)
	b, err := svc.CreateJSBundle(context.Background(), models.CreateJSBundleRequest{
		MainModule: "entry.js",
		Modules:    map[string]string{"entry.js": jsBundleSrc, "util.js": "export const x = 1;"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if b.MainModule != "entry.js" {
		t.Fatalf("main = %q", b.MainModule)
	}
	// Both source and modules set → rejected.
	_, err = svc.CreateJSBundle(context.Background(), models.CreateJSBundleRequest{Source: jsBundleSrc, Modules: map[string]string{"a.js": "x"}})
	if err == nil {
		t.Fatal("want error when both source and modules set")
	}
}

func TestJSBundleOwnerScoping(t *testing.T) {
	svc := newBundleService(t)
	acme := userCtx("acme")
	other := userCtx("other")

	created, err := svc.CreateJSBundle(acme, models.CreateJSBundleRequest{Name: "hook", Source: jsBundleSrc})
	if err != nil {
		t.Fatal(err)
	}
	// Owner sees it; a different tenant does not (404, not 403).
	if _, err := svc.GetJSBundle(acme, created.Digest); err != nil {
		t.Fatalf("owner get: %v", err)
	}
	if _, err := svc.GetJSBundle(other, created.Digest); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("cross-tenant get = %v, want ErrNotFound", err)
	}
	// List is owner-scoped.
	acmeList, _ := svc.ListJSBundles(acme)
	otherList, _ := svc.ListJSBundles(other)
	if len(acmeList) != 1 || len(otherList) != 0 {
		t.Fatalf("acme=%d other=%d, want 1/0", len(acmeList), len(otherList))
	}
	// A different tenant cannot delete it.
	if err := svc.DeleteJSBundle(other, created.Digest); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("cross-tenant delete = %v, want ErrNotFound", err)
	}
}

func TestDeleteJSBundleRefusesWhenReferenced(t *testing.T) {
	svc := newBundleService(t)
	ctx := context.Background()
	created, err := svc.CreateJSBundle(ctx, models.CreateJSBundleRequest{Source: jsBundleSrc})
	if err != nil {
		t.Fatal(err)
	}
	// Persist a sandbox that pins this bundle digest.
	if err := svc.store.Create(ctx, &models.Sandbox{
		ID:           "sb-iso",
		Runtime:      models.RuntimeIsolate,
		ModuleDigest: created.Digest,
	}); err != nil {
		t.Fatal(err)
	}
	if err := svc.DeleteJSBundle(ctx, created.Digest); !errors.Is(err, store.ErrJSBundleInUse) {
		t.Fatalf("delete referenced = %v, want ErrJSBundleInUse", err)
	}
	// Remove the sandbox → delete now succeeds.
	if err := svc.store.Delete(ctx, "sb-iso"); err != nil {
		t.Fatal(err)
	}
	if err := svc.DeleteJSBundle(ctx, created.Digest); err != nil {
		t.Fatalf("delete after unref: %v", err)
	}
}

func TestJSBundleMethodsErrorWithoutStore(t *testing.T) {
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	// No SetIsolateBundleStore.
	if _, err := svc.CreateJSBundle(context.Background(), models.CreateJSBundleRequest{Source: jsBundleSrc}); !errors.Is(err, models.ErrRuntimeNotImplemented) {
		t.Fatalf("create w/o store = %v, want ErrRuntimeNotImplemented", err)
	}
	if _, err := svc.ListJSBundles(context.Background()); !errors.Is(err, models.ErrRuntimeNotImplemented) {
		t.Fatalf("list w/o store = %v", err)
	}
}

// A create that names an uploaded bundle resolves it owner-scoped and pins the
// digest before the driver runs (the end-to-end reason the catalogue exists).
func TestCreateIsolateResolvesUploadedBundleName(t *testing.T) {
	svc := newBundleService(t)
	driver := &recordingRuntime{createErr: errors.New("driver reached")}
	svc.SetIsolateRuntime(driver)
	acme := userCtx("acme")

	created, err := svc.CreateJSBundle(acme, models.CreateJSBundleRequest{Name: "hook", Source: jsBundleSrc})
	if err != nil {
		t.Fatal(err)
	}
	_, err = svc.CreateSandbox(acme, models.CreateSandboxRequest{Runtime: models.RuntimeIsolate, ModuleRef: "hook"})
	if err == nil || err.Error() == "" {
		t.Fatalf("expected the driver error, got %v", err)
	}
	// The driver saw the pinned digest, not the bare name.
	if driver.lastCreateReq.ModuleRef != "sha256:"+created.Digest {
		t.Fatalf("driver saw module_ref %q, want the pinned digest sha256:%s", driver.lastCreateReq.ModuleRef, created.Digest)
	}
}

// TestCreateJSBundleClusterReplication covers the isolate-on-cluster fix: a
// normal upload fans out to peers exactly once, while a peer's replicated write
// stores under the explicit owner and does NOT fan out again (loop guard).
func TestCreateJSBundleClusterReplication(t *testing.T) {
	svc := newBundleService(t)
	ctx := context.Background()

	var replicatedNames []string
	svc.SetJSBundleReplicator(func(_ context.Context, owner string, req models.CreateJSBundleRequest) error {
		replicatedNames = append(replicatedNames, req.Name)
		return nil
	})

	// Normal upload → replicator invoked once.
	if _, err := svc.CreateJSBundle(ctx, models.CreateJSBundleRequest{Name: "a", Source: jsBundleSrc}); err != nil {
		t.Fatal(err)
	}
	if len(replicatedNames) != 1 || replicatedNames[0] != "a" {
		t.Fatalf("replicator calls = %v, want [a]", replicatedNames)
	}

	// A replicated write (peer fan-out) must NOT re-replicate, and must store
	// under the explicit owner carried in ctx (not the caller's scope).
	rctx := WithReplicatedJSBundleOwner(ctx, "tenant-z")
	got, err := svc.CreateJSBundle(rctx, models.CreateJSBundleRequest{Name: "b", Source: `export default { async fetch(){ return new Response("z"); } };`})
	if err != nil {
		t.Fatal(err)
	}
	if len(replicatedNames) != 1 {
		t.Fatalf("replicated write re-replicated (calls=%v); loop guard failed", replicatedNames)
	}
	if !svc.isolateBundles.TenantOwns("tenant-z", got.Digest) {
		t.Error("replicated bundle not stored under explicit owner tenant-z")
	}
}
