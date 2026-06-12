package wasmmod

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func swapOCIFunc[T any](target *T, stub T) func() {
	prev := *target
	*target = stub
	return func() { *target = prev }
}

// P0: manifest resolve happens before any blob download; a warm manifest
// pointer must short-circuit resolveOCI without calling the pull transport.
func TestResolveOCISkipsPullWhenManifestPointerWarm(t *testing.T) {
	mr := newTestModuleResolver(t)
	mr.Allowlist = map[string]struct{}{"registry.example": {}}

	src := WriteMinimalWasm(t, t.TempDir(), "m.wasm")
	digest, _, err := fileDigest(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(mr.CacheDir, 0o700); err != nil {
		t.Fatal(err)
	}
	copyFile(t, src, filepath.Join(mr.CacheDir, digest+".wasm"))

	const manifest = "sha256:warmmanifest"
	mr.writeManifestPointer(manifest, digest)

	var pulls int32
	restoreManifest := swapOCIFunc(&ociResolveManifestFunc, func(context.Context, ModuleAuth, string) (string, error) {
		return manifest, nil
	})
	defer restoreManifest()
	restorePull := swapOCIFunc(&ociPullArtifactFunc, func(context.Context, ModuleAuth, string, string, int64) (string, error) {
		atomic.AddInt32(&pulls, 1)
		return "", errors.New("pull should not run")
	})
	defer restorePull()

	got, err := mr.Resolve(context.Background(), "oci://registry.example/org/mod:v1")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if pulls != 0 {
		t.Fatalf("expected zero pulls on manifest cache hit, got %d", pulls)
	}
	if got.Digest != digest || got.Path != filepath.Join(mr.CacheDir, digest+".wasm") {
		t.Fatalf("unexpected resolved module: %+v", got)
	}
	if got.Ref != "oci://registry.example/org/mod:v1" {
		t.Fatalf("ref = %q", got.Ref)
	}
}

// P0: concurrent resolves of the same manifest digest must single-flight the
// blob pull so only one download runs.
func TestResolveOCISingleFlightCollapsesConcurrentPulls(t *testing.T) {
	mr := newTestModuleResolver(t)
	mr.Allowlist = map[string]struct{}{"registry.example": {}}

	const manifest = "sha256:singleflight"
	var pulls int32
	var gate sync.WaitGroup
	gate.Add(1)

	restoreManifest := swapOCIFunc(&ociResolveManifestFunc, func(context.Context, ModuleAuth, string) (string, error) {
		return manifest, nil
	})
	defer restoreManifest()
	restorePull := swapOCIFunc(&ociPullArtifactFunc, func(_ context.Context, _ ModuleAuth, _ string, dstDir string, _ int64) (string, error) {
		if atomic.AddInt32(&pulls, 1) == 1 {
			gate.Done()
			time.Sleep(30 * time.Millisecond)
		} else {
			t.Fatal("pull invoked more than once")
		}
		return WriteMinimalWasm(t, dstDir, moduleLayerName), nil
	})
	defer restorePull()

	const workers = 16
	var wg sync.WaitGroup
	wg.Add(workers)
	errs := make(chan error, workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			_, err := mr.Resolve(context.Background(), "oci://registry.example/org/mod:v1")
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
	}
	if pulls != 1 {
		t.Fatalf("expected exactly 1 pull, got %d", pulls)
	}
}

// P0: a credentialed manifest resolve failure must abort before any pull.
func TestResolveOCIManifestAuthFailureSkipsPull(t *testing.T) {
	mr := newTestModuleResolver(t)
	mr.Allowlist = map[string]struct{}{"registry.example": {}}

	var pulls int32
	restoreManifest := swapOCIFunc(&ociResolveManifestFunc, func(context.Context, ModuleAuth, string) (string, error) {
		return "", fmt.Errorf("%w: denied", ErrRegistryAuth)
	})
	defer restoreManifest()
	restorePull := swapOCIFunc(&ociPullArtifactFunc, func(context.Context, ModuleAuth, string, string, int64) (string, error) {
		atomic.AddInt32(&pulls, 1)
		return "", nil
	})
	defer restorePull()

	_, err := mr.Resolve(context.Background(), "oci://registry.example/org/mod:v1")
	if !errors.Is(err, ErrRegistryAuth) {
		t.Fatalf("want ErrRegistryAuth, got %v", err)
	}
	if pulls != 0 {
		t.Fatalf("pull ran after manifest auth failure")
	}
}

func TestResolveOCIRejectsMissingHost(t *testing.T) {
	mr := newTestModuleResolver(t)
	mr.Allowlist = map[string]struct{}{"": {}}
	_, err := mr.Resolve(context.Background(), "oci://")
	if !errors.Is(err, ErrModuleNotFound) {
		t.Fatalf("want ErrModuleNotFound, got %v", err)
	}
}

func TestPullAndPublishPublishesAndRecordsManifestPointer(t *testing.T) {
	mr := newTestModuleResolver(t)
	if err := os.MkdirAll(mr.CacheDir, 0o700); err != nil {
		t.Fatal(err)
	}

	const manifest = "sha256:publishmanifest"
	restorePull := swapOCIFunc(&ociPullArtifactFunc, func(_ context.Context, _ ModuleAuth, _ string, dstDir string, _ int64) (string, error) {
		return WriteMinimalWasm(t, dstDir, moduleLayerName), nil
	})
	defer restorePull()

	got, err := mr.pullAndPublish(context.Background(), "registry.example/org/mod:v1", manifest, ModuleAuth{})
	if err != nil {
		t.Fatalf("pullAndPublish: %v", err)
	}
	if _, err := os.Stat(got.Path); err != nil {
		t.Fatalf("published file missing: %v", err)
	}
	if _, ok := mr.lookupByManifest(manifest); !ok {
		t.Fatal("manifest pointer not written after publish")
	}
}

func TestPullAndPublishReusesExistingContentFile(t *testing.T) {
	mr := newTestModuleResolver(t)
	src := WriteMinimalWasm(t, t.TempDir(), "m.wasm")
	digest, _, err := fileDigest(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(mr.CacheDir, 0o700); err != nil {
		t.Fatal(err)
	}
	final := filepath.Join(mr.CacheDir, digest+".wasm")
	copyFile(t, src, final)

	const manifest = "sha256:reusecontent"
	restorePull := swapOCIFunc(&ociPullArtifactFunc, func(_ context.Context, _ ModuleAuth, _ string, dstDir string, _ int64) (string, error) {
		// Return different temp bytes with the same digest path already present.
		return WriteMinimalWasm(t, dstDir, moduleLayerName), nil
	})
	defer restorePull()

	got, err := mr.pullAndPublish(context.Background(), "registry.example/org/mod:v1", manifest, ModuleAuth{})
	if err != nil {
		t.Fatalf("pullAndPublish: %v", err)
	}
	if got.Path != final {
		t.Fatalf("path = %q, want %q", got.Path, final)
	}
	if _, ok := mr.lookupByManifest(manifest); !ok {
		t.Fatal("manifest pointer should be recorded on content cache hit")
	}
}

func TestFsyncFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "sync.wasm")
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := fsyncFile(p); err != nil {
		t.Fatalf("fsyncFile: %v", err)
	}
	if err := fsyncFile(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestSanitizeDigest(t *testing.T) {
	if got := sanitizeDigest("sha256:abc"); got != "sha256-abc" {
		t.Fatalf("sanitizeDigest = %q", got)
	}
}

func TestNewModuleResolverDefaultCacheDir(t *testing.T) {
	modules := t.TempDir()
	mr := NewModuleResolver(modules, "")
	if mr.CacheDir != filepath.Join(modules, "cache") {
		t.Fatalf("CacheDir = %q, want %q", mr.CacheDir, filepath.Join(modules, "cache"))
	}
}

func TestResolveOCIAppliesPullTimeout(t *testing.T) {
	mr := newTestModuleResolver(t)
	mr.Allowlist = map[string]struct{}{"registry.example": {}}
	mr.PullTimeout = time.Millisecond

	restoreManifest := swapOCIFunc(&ociResolveManifestFunc, func(ctx context.Context, _ ModuleAuth, _ string) (string, error) {
		<-ctx.Done()
		return "", ctx.Err()
	})
	defer restoreManifest()

	_, err := mr.Resolve(context.Background(), "oci://registry.example/org/mod:v1")
	if err == nil {
		t.Fatal("expected timeout/cancel error")
	}
}

func TestResolveOCIMkdirCacheFailure(t *testing.T) {
	mr := newTestModuleResolver(t)
	mr.Allowlist = map[string]struct{}{"registry.example": {}}
	blocker := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	mr.CacheDir = filepath.Join(blocker, "cache")

	restoreManifest := swapOCIFunc(&ociResolveManifestFunc, func(context.Context, ModuleAuth, string) (string, error) {
		return "sha256:never", nil
	})
	defer restoreManifest()

	_, err := mr.Resolve(context.Background(), "oci://registry.example/org/mod:v1")
	if err == nil {
		t.Fatal("expected mkdir failure")
	}
}

func TestPullAndPublishPullTransportError(t *testing.T) {
	mr := newTestModuleResolver(t)
	if err := os.MkdirAll(mr.CacheDir, 0o700); err != nil {
		t.Fatal(err)
	}
	restorePull := swapOCIFunc(&ociPullArtifactFunc, func(context.Context, ModuleAuth, string, string, int64) (string, error) {
		return "", errors.New("network down")
	})
	defer restorePull()

	_, err := mr.pullAndPublish(context.Background(), "registry.example/org/mod:v1", "sha256:net", ModuleAuth{})
	if err == nil || !strings.Contains(err.Error(), "network down") {
		t.Fatalf("pull error = %v", err)
	}
}

func TestPullAndPublishRejectsInvalidArtifact(t *testing.T) {
	mr := newTestModuleResolver(t)
	if err := os.MkdirAll(mr.CacheDir, 0o700); err != nil {
		t.Fatal(err)
	}
	restorePull := swapOCIFunc(&ociPullArtifactFunc, func(_ context.Context, _ ModuleAuth, _ string, dstDir string, _ int64) (string, error) {
		p := filepath.Join(dstDir, moduleLayerName)
		if err := os.WriteFile(p, []byte("not wasm"), 0o600); err != nil {
			t.Fatal(err)
		}
		return p, nil
	})
	defer restorePull()

	_, err := mr.pullAndPublish(context.Background(), "registry.example/org/mod:v1", "sha256:bad", ModuleAuth{})
	if err == nil {
		t.Fatal("expected validation error")
	}
}

// Inside single-flight, a waiter must observe a manifest pointer written by the
// leader without issuing its own pull.
func TestPullAndPublishConcurrentPublishRace(t *testing.T) {
	mr := newTestModuleResolver(t)
	if err := os.MkdirAll(mr.CacheDir, 0o700); err != nil {
		t.Fatal(err)
	}
	const manifest = "sha256:race"
	restorePull := swapOCIFunc(&ociPullArtifactFunc, func(_ context.Context, _ ModuleAuth, _ string, dstDir string, _ int64) (string, error) {
		return WriteMinimalWasm(t, dstDir, moduleLayerName), nil
	})
	defer restorePull()

	var wg sync.WaitGroup
	wg.Add(2)
	errs := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() {
			defer wg.Done()
			_, err := mr.pullAndPublish(context.Background(), "registry.example/org/mod:v1", manifest, ModuleAuth{})
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("pullAndPublish: %v", err)
		}
	}
	if _, ok := mr.lookupByManifest(manifest); !ok {
		t.Fatal("manifest pointer missing after concurrent publish")
	}
}

func TestWriteManifestPointerBestEffortOnReadOnlyDir(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root can write through read-only dirs on some platforms")
	}
	mr := newTestModuleResolver(t)
	dir := filepath.Join(mr.CacheDir, ".manifest")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	// Must not panic; a failed write only costs a future re-pull.
	mr.writeManifestPointer("sha256:readonly", "sha256:content")
}

func TestResolveOCISingleFlightWaitsOnLeaderPublish(t *testing.T) {
	mr := newTestModuleResolver(t)
	mr.Allowlist = map[string]struct{}{"registry.example": {}}

	const manifest = "sha256:leaderpublish"
	var pulls int32
	start := make(chan struct{})

	restoreManifest := swapOCIFunc(&ociResolveManifestFunc, func(context.Context, ModuleAuth, string) (string, error) {
		return manifest, nil
	})
	defer restoreManifest()
	restorePull := swapOCIFunc(&ociPullArtifactFunc, func(_ context.Context, _ ModuleAuth, _ string, dstDir string, _ int64) (string, error) {
		if atomic.AddInt32(&pulls, 1) != 1 {
			t.Fatal("only leader may pull")
		}
		close(start)
		time.Sleep(40 * time.Millisecond)
		return WriteMinimalWasm(t, dstDir, moduleLayerName), nil
	})
	defer restorePull()

	errs := make(chan error, 2)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, err := mr.Resolve(context.Background(), "oci://registry.example/org/mod:v1")
		errs <- err
	}()
	<-start
	go func() {
		defer wg.Done()
		_, err := mr.Resolve(context.Background(), "oci://registry.example/org/mod:v2")
		errs <- err
	}()
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
	}
	if pulls != 1 {
		t.Fatalf("pulls = %d, want 1", pulls)
	}
}
