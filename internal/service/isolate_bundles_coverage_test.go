package service

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	storepkg "github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/jsbundle"
	"github.com/aerol-ai/microvm/pkg/models"
)

func TestDeleteJSBundleCoverageBranches(t *testing.T) {
	ctx := context.Background()

	t.Run("nil_store", func(t *testing.T) {
		svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
		svc.isolateBundles = nil
		err := svc.DeleteJSBundle(ctx, "deadbeef")
		if err == nil || !errors.Is(err, models.ErrRuntimeNotImplemented) {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("scoped_foreign", func(t *testing.T) {
		svc := newBundleService(t)
		got, err := svc.CreateJSBundle(ctx, models.CreateJSBundleRequest{Name: "hook", Source: jsBundleSrc})
		if err != nil {
			t.Fatal(err)
		}
		err = svc.DeleteJSBundle(userCtx("other"), got.Digest)
		if !errors.Is(err, storepkg.ErrNotFound) {
			t.Fatalf("err = %v, want not found", err)
		}
	})

	t.Run("in_use", func(t *testing.T) {
		svc := newBundleService(t)
		got, err := svc.CreateJSBundle(ctx, models.CreateJSBundleRequest{Name: "hook", Source: jsBundleSrc})
		if err != nil {
			t.Fatal(err)
		}
		if err := svc.store.Create(ctx, &models.Sandbox{
			ID: "sb-pin", Runtime: models.RuntimeIsolate, ModuleDigest: got.Digest,
			Image: "sha256:" + got.Digest, Status: models.SandboxStatusStarted,
			CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(), LastActiveAt: time.Now().UTC(),
		}); err != nil {
			t.Fatalf("Create: %v", err)
		}
		err = svc.DeleteJSBundle(ctx, "sha256:"+got.Digest)
		if !errors.Is(err, storepkg.ErrJSBundleInUse) {
			t.Fatalf("err = %v, want in use", err)
		}
	})

	t.Run("list_runtime_fail", func(t *testing.T) {
		svc, st, _ := newServiceRuntimeHarnessAllowStoreClose(t, &recordingRuntime{})
		svc.cfg.EnableIsolate = true
		bundleStore, err := jsbundle.NewStore(jsbundle.StoreConfig{Dir: filepath.Join(t.TempDir(), "b")})
		if err != nil {
			t.Fatal(err)
		}
		svc.SetIsolateBundleStore(bundleStore)
		_ = st.Close()
		err = svc.DeleteJSBundle(ctx, "abcd")
		if err == nil || !strings.Contains(err.Error(), "check bundle references") {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("delete_ok", func(t *testing.T) {
		svc := newBundleService(t)
		got, err := svc.CreateJSBundle(ctx, models.CreateJSBundleRequest{Name: "hook", Source: jsBundleSrc})
		if err != nil {
			t.Fatal(err)
		}
		if err := svc.DeleteJSBundle(ctx, got.Digest); err != nil {
			t.Fatalf("DeleteJSBundle: %v", err)
		}
		if err := svc.DeleteJSBundle(ctx, got.Digest); !errors.Is(err, storepkg.ErrNotFound) {
			t.Fatalf("second delete = %v, want not found", err)
		}
	})
}

func TestGetJSBundleNilAndScopedMiss(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	if _, err := svc.GetJSBundle(ctx, "x"); err == nil || !errors.Is(err, models.ErrRuntimeNotImplemented) {
		t.Fatalf("nil bundles: %v", err)
	}
	svc = newBundleService(t)
	got, err := svc.CreateJSBundle(ctx, models.CreateJSBundleRequest{Name: "hook", Source: jsBundleSrc})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.GetJSBundle(userCtx("other"), got.Digest); !errors.Is(err, storepkg.ErrNotFound) {
		t.Fatalf("scoped miss = %v", err)
	}
}

func TestCreateJSBundleModulesPath(t *testing.T) {
	svc := newBundleService(t)
	_, err := svc.CreateJSBundle(context.Background(), models.CreateJSBundleRequest{
		Name:       "multi",
		MainModule: "index.js",
		Modules:    map[string]string{"index.js": `export default { async fetch(){ return new Response("ok"); } };`},
	})
	if err != nil {
		t.Fatalf("CreateJSBundle modules: %v", err)
	}
}

func TestBundleFromCreateRequestDefaultMainCompat(t *testing.T) {
	_, err := bundleFromCreateRequest(models.CreateJSBundleRequest{
		Modules: map[string]string{jsbundle.DefaultMainModule: `export default { async fetch(){ return new Response("ok"); } };`},
	})
	if err != nil {
		t.Fatalf("bundleFromCreateRequest: %v", err)
	}
	_, err = bundleFromCreateRequest(models.CreateJSBundleRequest{
		Source:  "not both",
		Modules: map[string]string{"a": "b"},
	})
	if err == nil {
		t.Fatal("expected exactly-one validation error")
	}
}
