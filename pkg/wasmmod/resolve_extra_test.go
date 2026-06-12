package wasmmod

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestResolveWithAuthOverride(t *testing.T) {
	mr := newTestModuleResolver(t)
	mr.Allowlist = map[string]struct{}{"registry.example": {}}

	const manifest = "sha256:override"
	restoreManifest := swapOCIFunc(&ociResolveManifestFunc, func(_ context.Context, auth ModuleAuth, _ string) (string, error) {
		if auth.PAT != "tenant-token" {
			t.Fatalf("auth override not applied: %+v", auth)
		}
		return manifest, nil
	})
	defer restoreManifest()
	restorePull := swapOCIFunc(&ociPullArtifactFunc, func(_ context.Context, _ ModuleAuth, _ string, dstDir string, _ int64) (string, error) {
		return WriteMinimalWasm(t, dstDir, moduleLayerName), nil
	})
	defer restorePull()

	override := &ModuleAuth{PAT: "tenant-token"}
	got, err := mr.ResolveWithAuth(context.Background(), "oci://registry.example/org/mod:v1", override)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got.Digest == "" {
		t.Fatal("expected digest")
	}
}

func TestResolveNormalizesMissingFileToNotFound(t *testing.T) {
	mr := newTestModuleResolver(t)
	_, err := mr.Resolve(context.Background(), "missing.wasm")
	if !errors.Is(err, ErrModuleNotFound) {
		t.Fatalf("want ErrModuleNotFound, got %v", err)
	}
}

func TestResolveCatalogueInvalidWasm(t *testing.T) {
	mr := newTestModuleResolver(t)
	bad := filepath.Join(t.TempDir(), "bad.wasm")
	if err := os.WriteFile(bad, []byte("not wasm"), 0o600); err != nil {
		t.Fatal(err)
	}
	mr.CatalogueLookup = func(_ context.Context, id string) (string, string, bool) {
		if id == "cat-1" {
			return bad, "d", true
		}
		return "", "", false
	}
	_, err := mr.Resolve(context.Background(), "cat-1")
	if err == nil {
		t.Fatal("expected validation error")
	}
}

func TestResolveBareFilePropagatesValidationError(t *testing.T) {
	mr := newTestModuleResolver(t)
	component := filepath.Join(mr.file.ModulesDir, "comp.wasm")
	if err := os.WriteFile(component, []byte{0x00, 0x61, 0x73, 0x6d, 0x0d, 0x00, 0x01, 0x00}, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := mr.Resolve(context.Background(), "comp.wasm")
	if !errors.Is(err, ErrComponentModelUnsupported) {
		t.Fatalf("want component error, got %v", err)
	}
}

func TestResolveEmptyRef(t *testing.T) {
	mr := newTestModuleResolver(t)
	_, err := mr.ResolveWithAuth(context.Background(), "  ", nil)
	if !errors.Is(err, ErrModuleNotFound) {
		t.Fatalf("want ErrModuleNotFound, got %v", err)
	}
}

func TestValidateFileMissingPath(t *testing.T) {
	if err := ValidateFile(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("expected stat error")
	}
}

func TestWriteManifestPointerSuccess(t *testing.T) {
	mr := newTestModuleResolver(t)
	if err := os.MkdirAll(mr.CacheDir, 0o700); err != nil {
		t.Fatal(err)
	}
	src := WriteMinimalWasm(t, t.TempDir(), "m.wasm")
	digest, _, err := fileDigest(src)
	if err != nil {
		t.Fatal(err)
	}
	mr.writeManifestPointer("sha256:manifestok", digest)
	if _, ok := mr.lookupByManifest("sha256:manifestok"); ok {
		t.Fatal("pointer without content file should miss")
	}
	copyFile(t, src, filepath.Join(mr.CacheDir, digest+".wasm"))
	got, ok := mr.lookupByManifest("sha256:manifestok")
	if !ok {
		t.Fatal("expected pointer hit after content file present")
	}
	if got.Digest != digest {
		t.Fatalf("digest = %q", got.Digest)
	}
}

func TestPullAndPublishMkdirTempFailure(t *testing.T) {
	mr := newTestModuleResolver(t)
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	mr.CacheDir = blocker
	_, err := mr.pullAndPublish(context.Background(), "registry.example/org/mod:v1", "sha256:mkdir", ModuleAuth{})
	if err == nil {
		t.Fatal("expected mkdir temp failure")
	}
}

func TestPullAndPublishRenameFailsWhenFinalPathBlocks(t *testing.T) {
	mr := newTestModuleResolver(t)
	if err := os.MkdirAll(mr.CacheDir, 0o700); err != nil {
		t.Fatal(err)
	}
	probe := WriteMinimalWasm(t, t.TempDir(), "probe.wasm")
	digest, _, err := fileDigest(probe)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(mr.CacheDir, digest+".wasm"), 0o700); err != nil {
		t.Fatal(err)
	}
	restorePull := swapOCIFunc(&ociPullArtifactFunc, func(_ context.Context, _ ModuleAuth, _ string, dstDir string, _ int64) (string, error) {
		return WriteMinimalWasm(t, dstDir, moduleLayerName), nil
	})
	defer restorePull()

	_, err = mr.pullAndPublish(context.Background(), "registry.example/org/mod:v1", "sha256:blocked", ModuleAuth{})
	if err == nil {
		t.Fatal("expected rename failure when final path is blocked")
	}
}

func TestPullAndPublishRenameRaceUsesExistingFile(t *testing.T) {
	mr := newTestModuleResolver(t)
	if err := os.MkdirAll(mr.CacheDir, 0o700); err != nil {
		t.Fatal(err)
	}
	src := WriteMinimalWasm(t, t.TempDir(), "m.wasm")
	digest, _, err := fileDigest(src)
	if err != nil {
		t.Fatal(err)
	}
	final := filepath.Join(mr.CacheDir, digest+".wasm")

	restorePull := swapOCIFunc(&ociPullArtifactFunc, func(_ context.Context, _ ModuleAuth, _ string, dstDir string, _ int64) (string, error) {
		pulled := WriteMinimalWasm(t, dstDir, moduleLayerName)
		// Simulate a concurrent publisher winning the rename race.
		copyFile(t, src, final)
		return pulled, nil
	})
	defer restorePull()

	got, err := mr.pullAndPublish(context.Background(), "registry.example/org/mod:v1", "sha256:renamerace", ModuleAuth{})
	if err != nil {
		t.Fatalf("pullAndPublish: %v", err)
	}
	if got.Path != final {
		t.Fatalf("path = %q want %q", got.Path, final)
	}
}
