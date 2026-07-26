package wasmmod

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func TestNewDigestCacheDefaultMode(t *testing.T) {
	c := newDigestCache("")
	if c == nil || c.mode != moduleDigestModeOnce {
		t.Fatalf("expected default once mode, got %+v", c)
	}
	always := newDigestCache("ALWAYS")
	if always == nil || always.mode != moduleDigestModeAlways {
		t.Fatalf("expected always mode, got %+v", always)
	}
}

func TestDigestCacheNilAndAlwaysMode(t *testing.T) {
	var c *digestCache
	if _, _, err := c.digestFor(WriteMinimalWasm(t, t.TempDir(), "m.wasm")); err != nil {
		t.Fatalf("nil cache should delegate to fileDigest: %v", err)
	}
	c.dropPath("/unused") // no-op on nil

	dir := t.TempDir()
	path := WriteMinimalWasm(t, dir, "m.wasm")
	c = newDigestCache(moduleDigestModeAlways)
	var calls atomic.Int32
	old := fileDigestHasher
	fileDigestHasher = func(p string) (string, int64, error) {
		calls.Add(1)
		return old(p)
	}
	t.Cleanup(func() { fileDigestHasher = old })

	if _, _, err := c.digestFor(path); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.digestFor(path); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 {
		t.Fatalf("always mode hash calls = %d, want 2", calls.Load())
	}
}

func TestDigestCacheConcurrentWaiters(t *testing.T) {
	dir := t.TempDir()
	path := WriteMinimalWasm(t, dir, "m.wasm")
	c := newDigestCache(moduleDigestModeOnce)

	var calls atomic.Int32
	old := fileDigestHasher
	fileDigestHasher = func(p string) (string, int64, error) {
		calls.Add(1)
		return old(p)
	}
	t.Cleanup(func() { fileDigestHasher = old })

	errCh := make(chan error, 2)
	go func() { _, _, err := c.digestFor(path); errCh <- err }()
	go func() { _, _, err := c.digestFor(path); errCh <- err }()
	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil {
			t.Fatalf("digestFor: %v", err)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("hash calls = %d, want 1 (single-flight within cache)", calls.Load())
	}
}

func TestFileIdentityForStatError(t *testing.T) {
	if _, err := fileIdentityFor(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("expected stat error")
	}
}

func TestResolverSetDigestModeNil(t *testing.T) {
	var r *Resolver
	r.SetDigestMode(moduleDigestModeAlways) // no-op
	if _, _, err := r.digestFor(WriteMinimalWasm(t, t.TempDir(), "m.wasm")); err != nil {
		t.Fatalf("nil resolver cache should still hash: %v", err)
	}
}

func TestModuleResolverSetDigestMode(t *testing.T) {
	mr := newTestModuleResolver(t)
	mr.SetDigestMode(moduleDigestModeAlways)
	dir := t.TempDir()
	path := WriteMinimalWasm(t, dir, "m.wasm")
	var calls atomic.Int32
	old := fileDigestHasher
	fileDigestHasher = func(p string) (string, int64, error) {
		calls.Add(1)
		return old(p)
	}
	t.Cleanup(func() { fileDigestHasher = old })

	ctx := context.Background()
	if _, err := mr.file.Resolve(ctx, path); err != nil {
		t.Fatal(err)
	}
	if _, err := mr.file.Resolve(ctx, path); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 {
		t.Fatalf("hash calls = %d, want 2 via ModuleResolver.SetDigestMode", calls.Load())
	}

	var nilMR *ModuleResolver
	nilMR.SetDigestMode(moduleDigestModeAlways) // no-op
}

func TestValidateFileOpenError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "locked.wasm")
	if err := os.WriteFile(path, []byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00}, 0o000); err != nil {
		t.Fatal(err)
	}
	if err := ValidateFile(path); err == nil {
		t.Fatal("expected open error for unreadable file")
	}
}

func TestPullAndPublishFsyncFailure(t *testing.T) {
	mr := newTestModuleResolver(t)
	if err := os.MkdirAll(mr.CacheDir, 0o700); err != nil {
		t.Fatal(err)
	}
	restorePull := swapOCIFunc(&ociPullArtifactFunc, func(_ context.Context, _ ModuleAuth, _ string, dstDir string, _ int64) (string, error) {
		p := WriteMinimalWasm(t, dstDir, moduleLayerName)
		if err := os.Chmod(p, 0o000); err != nil {
			t.Fatal(err)
		}
		return p, nil
	})
	defer restorePull()

	_, err := mr.pullAndPublish(context.Background(), "registry.example/org/mod:v1", "sha256:fsyncfail", ModuleAuth{})
	if err == nil {
		t.Fatal("expected fsync/open failure")
	}
}

func TestPullAndPublishDigestFailure(t *testing.T) {
	mr := newTestModuleResolver(t)
	if err := os.MkdirAll(mr.CacheDir, 0o700); err != nil {
		t.Fatal(err)
	}
	restorePull := swapOCIFunc(&ociPullArtifactFunc, func(_ context.Context, _ ModuleAuth, _ string, dstDir string, _ int64) (string, error) {
		return WriteMinimalWasm(t, dstDir, moduleLayerName), nil
	})
	defer restorePull()
	old := fileDigestHasher
	fileDigestHasher = func(string) (string, int64, error) {
		return "", 0, errors.New("hash boom")
	}
	t.Cleanup(func() { fileDigestHasher = old })

	_, err := mr.pullAndPublish(context.Background(), "registry.example/org/mod:v1", "sha256:hashfail", ModuleAuth{})
	if err == nil || err.Error() != "hash boom" {
		t.Fatalf("pullAndPublish err = %v", err)
	}
}

func TestLookupByManifestEmptyPointer(t *testing.T) {
	mr := newTestModuleResolver(t)
	if err := os.MkdirAll(filepath.Join(mr.CacheDir, ".manifest"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mr.manifestPointer("sha256:empty"), []byte("  \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok := mr.lookupByManifest("sha256:empty"); ok {
		t.Fatal("blank pointer should miss")
	}
}

func TestResolveOCICacheHitInsideSingleFlight(t *testing.T) {
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
	const manifest = "sha256:ingroup"
	mr.writeManifestPointer(manifest, digest)

	var pulls int32
	restoreManifest := swapOCIFunc(&ociResolveManifestFunc, func(context.Context, ModuleAuth, string) (string, error) {
		return manifest, nil
	})
	defer restoreManifest()
	restorePull := swapOCIFunc(&ociPullArtifactFunc, func(context.Context, ModuleAuth, string, string, int64) (string, error) {
		atomic.AddInt32(&pulls, 1)
		return "", errors.New("should not pull on in-group cache hit")
	})
	defer restorePull()

	got, err := mr.Resolve(context.Background(), "oci://registry.example/org/mod:v1")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if pulls != 0 {
		t.Fatalf("pulls = %d, want 0", pulls)
	}
	if got.Digest != digest {
		t.Fatalf("digest = %q", got.Digest)
	}
}

func TestResolveOCIPullGroupPropagatesError(t *testing.T) {
	mr := newTestModuleResolver(t)
	mr.Allowlist = map[string]struct{}{"registry.example": {}}
	restoreManifest := swapOCIFunc(&ociResolveManifestFunc, func(context.Context, ModuleAuth, string) (string, error) {
		return "sha256:pullerr", nil
	})
	defer restoreManifest()
	restorePull := swapOCIFunc(&ociPullArtifactFunc, func(context.Context, ModuleAuth, string, string, int64) (string, error) {
		return "", errors.New("pull failed")
	})
	defer restorePull()

	_, err := mr.Resolve(context.Background(), "oci://registry.example/org/mod:v1")
	if err == nil || err.Error() != "pull failed" {
		t.Fatalf("resolve err = %v", err)
	}
}

func TestDigestCacheMissingFileFallsBackToHash(t *testing.T) {
	c := newDigestCache(moduleDigestModeOnce)
	_, _, err := c.digestFor(filepath.Join(t.TempDir(), "missing.wasm"))
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestWriteManifestPointerMkdirAllFailure(t *testing.T) {
	mr := newTestModuleResolver(t)
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	mr.CacheDir = filepath.Join(blocker, "cache")
	mr.writeManifestPointer("sha256:mkfail", "digest") // best-effort no-op
}

func TestWriteManifestPointerRenameFailure(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root can write through read-only dirs on some platforms")
	}
	mr := newTestModuleResolver(t)
	manifestDir := filepath.Join(mr.CacheDir, ".manifest")
	if err := os.MkdirAll(manifestDir, 0o700); err != nil {
		t.Fatal(err)
	}
	// Block the final pointer path so rename fails after writing the temp file.
	target := mr.manifestPointer("sha256:renamefail")
	if err := os.Mkdir(target, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(target, 0o700); _ = os.RemoveAll(target) })
	mr.writeManifestPointer("sha256:renamefail", "digest")
}

func TestPullSnapshotArtifactMissingConfigAfterCopy(t *testing.T) {
	reg := startTestOCIRegistry(t, "cluster/wasm-checkpoints/broken-pull")
	defer reg.close()

	patFile := filepath.Join(t.TempDir(), "pat")
	if err := os.WriteFile(patFile, []byte("cluster-pat"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := ORASPullConfig{Host: "h", ClusterID: "c1", PATPath: patFile}
	ref := reg.ref("latest")

	// Push a module artifact (no snapshot config.json) so copy succeeds but
	// snapshotDirExists fails afterward.
	src := WriteMinimalWasm(t, t.TempDir(), "m.wasm")
	if _, err := PushModuleArtifact(context.Background(), ModuleAuth{PAT: "cluster-pat"}, src, ref); err != nil {
		t.Fatalf("push setup: %v", err)
	}

	dst := t.TempDir()
	err := PullSnapshotArtifact(context.Background(), cfg, ref, dst)
	if err == nil || !strings.Contains(err.Error(), "missing config.json") {
		t.Fatalf("want missing config error, got %v", err)
	}
}

func TestDeleteSnapshotRefSecondDeleteSucceeds(t *testing.T) {
	reg := startTestOCIRegistry(t, "cluster/wasm-checkpoints/del-twice")
	defer reg.close()

	patFile := filepath.Join(t.TempDir(), "pat")
	if err := os.WriteFile(patFile, []byte("cluster-pat"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := ORASPushConfig{Host: "h", ClusterID: "c1", PATPath: patFile}
	ref := reg.ref("latest")
	ctx := context.Background()

	if _, err := PushSnapshotArtifact(ctx, cfg, writeTestSnapshotDir(t), ref); err != nil {
		t.Fatalf("push: %v", err)
	}
	if err := DeleteSnapshotRef(ctx, cfg, ref); err != nil {
		t.Fatalf("first delete: %v", err)
	}
	if err := DeleteSnapshotRef(ctx, cfg, ref); err != nil {
		t.Fatalf("second delete (missing manifest) should succeed: %v", err)
	}
}

func TestPullModuleArtifactMkdirDstFailure(t *testing.T) {
	reg := startTestOCIRegistry(t, "tenant/mkdir")
	defer reg.close()
	ref := reg.ref("latest")
	src := WriteMinimalWasm(t, t.TempDir(), "m.wasm")
	if _, err := PushModuleArtifact(context.Background(), ModuleAuth{PAT: "tok"}, src, ref); err != nil {
		t.Fatal(err)
	}
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(blocker, "dst")
	_, err := PullModuleArtifact(context.Background(), ModuleAuth{PAT: "tok"}, ref, dst, maxModuleBytes)
	if err == nil {
		t.Fatal("expected mkdir failure for dst dir")
	}
}

func TestDeleteSnapshotRefValidateFailure(t *testing.T) {
	if err := DeleteSnapshotRef(context.Background(), ORASPushConfig{ClusterID: "c1"}, "host/repo:tag"); err == nil {
		t.Fatal("expected validate error")
	}
}

func TestPullSnapshotArtifactValidateAndCopyFailures(t *testing.T) {
	if err := PullSnapshotArtifact(context.Background(), ORASPullConfig{}, "ref", t.TempDir()); err == nil {
		t.Fatal("expected validate error")
	}

	reg := startTestOCIRegistry(t, "cluster/wasm-checkpoints/copyfail")
	patFile := filepath.Join(t.TempDir(), "pat")
	if err := os.WriteFile(patFile, []byte("cluster-pat"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := ORASPullConfig{Host: "h", ClusterID: "c1", PATPath: patFile}
	ref := reg.ref("latest")
	if _, err := PushSnapshotArtifact(context.Background(), ORASPushConfig{Host: "h", ClusterID: "c1", PATPath: patFile}, writeTestSnapshotDir(t), ref); err != nil {
		t.Fatalf("push setup: %v", err)
	}
	reg.close()
	if err := PullSnapshotArtifact(context.Background(), cfg, ref, t.TempDir()); err == nil {
		t.Fatal("expected copy failure after registry closed")
	}
}

func TestPushSnapshotArtifactCopyFailure(t *testing.T) {
	reg := startTestOCIRegistry(t, "cluster/wasm-checkpoints/pushcopyfail")
	patFile := filepath.Join(t.TempDir(), "pat")
	if err := os.WriteFile(patFile, []byte("cluster-pat"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := ORASPushConfig{Host: "h", ClusterID: "c1", PATPath: patFile}
	ref := reg.ref("latest")
	reg.close()
	if _, err := PushSnapshotArtifact(context.Background(), cfg, writeTestSnapshotDir(t), ref); err == nil {
		t.Fatal("expected push copy failure after registry closed")
	}
}

func TestPullModuleArtifactCopyAndFetchFailures(t *testing.T) {
	reg := startTestOCIRegistry(t, "tenant/modcopyfail")
	ref := reg.ref("latest")
	src := WriteMinimalWasm(t, t.TempDir(), "m.wasm")
	if _, err := PushModuleArtifact(context.Background(), ModuleAuth{PAT: "tok"}, src, ref); err != nil {
		t.Fatal(err)
	}
	reg.close()
	if _, err := PullModuleArtifact(context.Background(), ModuleAuth{PAT: "tok"}, ref, t.TempDir(), maxModuleBytes); err == nil {
		t.Fatal("expected pull failure after registry closed")
	}

	reg2 := startTestOCIRegistry(t, "tenant/preflightfail")
	defer reg2.close()
	ref2 := reg2.ref("latest")
	if _, err := PushModuleArtifact(context.Background(), ModuleAuth{PAT: "tok"}, src, ref2); err != nil {
		t.Fatal(err)
	}
	reg2.close()
	if _, err := PullModuleArtifact(context.Background(), ModuleAuth{PAT: "tok"}, ref2, t.TempDir(), maxModuleBytes); err == nil {
		t.Fatal("expected preflight/copy failure with closed registry")
	}
}

func TestPullAndPublishRenameFailureWithoutExistingFile(t *testing.T) {
	mr := newTestModuleResolver(t)
	if err := os.MkdirAll(mr.CacheDir, 0o700); err != nil {
		t.Fatal(err)
	}
	restorePull := swapOCIFunc(&ociPullArtifactFunc, func(_ context.Context, _ ModuleAuth, _ string, dstDir string, _ int64) (string, error) {
		return WriteMinimalWasm(t, dstDir, moduleLayerName), nil
	})
	defer restorePull()

	// Make the final content path a read-only directory so rename fails and no
	// existing file is present for the race-recovery branch.
	probe := WriteMinimalWasm(t, t.TempDir(), "probe.wasm")
	digest, _, err := fileDigest(probe)
	if err != nil {
		t.Fatal(err)
	}
	final := filepath.Join(mr.CacheDir, digest+".wasm")
	if err := os.Mkdir(final, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(final, 0o700); _ = os.RemoveAll(final) })

	_, err = mr.pullAndPublish(context.Background(), "registry.example/org/mod:v1", "sha256:norace", ModuleAuth{})
	if err == nil {
		t.Fatal("expected rename failure when final path blocks and no file exists")
	}
}

func TestDigestCacheInitializesNilMap(t *testing.T) {
	c := &digestCache{mode: moduleDigestModeOnce}
	path := WriteMinimalWasm(t, t.TempDir(), "m.wasm")
	if _, _, err := c.digestFor(path); err != nil {
		t.Fatalf("digestFor: %v", err)
	}
	if c.byKey == nil {
		t.Fatal("expected byKey to be initialized")
	}
}

func TestFileDigestHasherReadError(t *testing.T) {
	path := WriteMinimalWasm(t, t.TempDir(), "m.wasm")
	old := fileDigestHasher
	fileDigestHasher = func(string) (string, int64, error) {
		return "", 0, errors.New("read failed")
	}
	t.Cleanup(func() { fileDigestHasher = old })
	if _, _, err := fileDigest(path); err == nil || err.Error() != "read failed" {
		t.Fatalf("fileDigest err = %v", err)
	}
}

func TestFileDigestIOCopyErrorOnDirectory(t *testing.T) {
	_, _, err := fileDigest(t.TempDir())
	if err == nil {
		t.Fatal("expected io.Copy error when path is a directory")
	}
}

func TestPushSnapshotArtifactValidateAndBadRepo(t *testing.T) {
	dir := writeTestSnapshotDir(t)
	if _, err := PushSnapshotArtifact(context.Background(), ORASPushConfig{}, dir, "host/repo:tag"); err == nil {
		t.Fatal("expected validate error")
	}
	patFile := filepath.Join(t.TempDir(), "pat")
	if err := os.WriteFile(patFile, []byte("tok"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := ORASPushConfig{Host: "h", ClusterID: "c", PATPath: patFile}
	if _, err := PushSnapshotArtifact(context.Background(), cfg, dir, "http://\x00bad"); err == nil {
		t.Fatal("expected newAuthedRepo error")
	}
}

func TestPushModuleArtifactStagingFailures(t *testing.T) {
	ctx := context.Background()
	auth := ModuleAuth{PAT: "tok"}
	wasm := WriteMinimalWasm(t, t.TempDir(), "m.wasm")

	if _, err := PushModuleArtifact(ctx, auth, wasm, "http://\x00bad"); err == nil {
		t.Fatal("expected newAuthedRepo error")
	}

	reg := startTestOCIRegistry(t, "tenant/badlayer")
	defer reg.close()
	ref := reg.ref("latest")
	if _, err := PushModuleArtifact(ctx, auth, filepath.Join(t.TempDir(), "missing.wasm"), ref); err == nil {
		t.Fatal("expected add layer error for missing wasm")
	}
}

func TestPullSnapshotArtifactFileStoreFailure(t *testing.T) {
	reg := startTestOCIRegistry(t, "cluster/wasm-checkpoints/filestore")
	defer reg.close()
	patFile := filepath.Join(t.TempDir(), "pat")
	if err := os.WriteFile(patFile, []byte("cluster-pat"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := ORASPullConfig{Host: "h", ClusterID: "c1", PATPath: patFile}
	ref := reg.ref("latest")
	if _, err := PushSnapshotArtifact(context.Background(), ORASPushConfig{Host: "h", ClusterID: "c1", PATPath: patFile}, writeTestSnapshotDir(t), ref); err != nil {
		t.Fatalf("push setup: %v", err)
	}
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(blocker, "dst")
	if err := PullSnapshotArtifact(context.Background(), cfg, ref, dst); err == nil {
		t.Fatal("expected mkdir/file store failure")
	}
}

func TestPushModuleArtifactMkdirTempFailure(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", blocker)
	_, err := PushModuleArtifact(
		context.Background(),
		ModuleAuth{PAT: "tok"},
		WriteMinimalWasm(t, t.TempDir(), "m.wasm"),
		"127.0.0.1:1/repo:tag",
	)
	if err == nil {
		t.Fatal("expected mkdir temp failure")
	}
}

func TestPushSnapshotArtifactMkdirTempFailure(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", blocker)
	patFile := filepath.Join(t.TempDir(), "pat")
	if err := os.WriteFile(patFile, []byte("tok"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := ORASPushConfig{Host: "h", ClusterID: "c", PATPath: patFile}
	_, err := PushSnapshotArtifact(context.Background(), cfg, writeTestSnapshotDir(t), "127.0.0.1:1/repo:tag")
	if err == nil {
		t.Fatal("expected mkdir temp failure")
	}
}

func TestPullSnapshotArtifactDstFileNotDirectory(t *testing.T) {
	reg := startTestOCIRegistry(t, "cluster/wasm-checkpoints/dstfile")
	defer reg.close()
	patFile := filepath.Join(t.TempDir(), "pat")
	if err := os.WriteFile(patFile, []byte("cluster-pat"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := ORASPullConfig{Host: "h", ClusterID: "c1", PATPath: patFile}
	ref := reg.ref("latest")
	if _, err := PushSnapshotArtifact(context.Background(), ORASPushConfig{Host: "h", ClusterID: "c1", PATPath: patFile}, writeTestSnapshotDir(t), ref); err != nil {
		t.Fatalf("push setup: %v", err)
	}
	dstFile := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(dstFile, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := PullSnapshotArtifact(context.Background(), cfg, ref, dstFile); err == nil {
		t.Fatal("expected file store error when dst is a file")
	}
}

func TestDeleteSnapshotRefDeleteFailure(t *testing.T) {
	reg := startTestOCIRegistry(t, "cluster/wasm-checkpoints/delfail")
	reg.deleteFail = true
	defer reg.close()

	patFile := filepath.Join(t.TempDir(), "pat")
	if err := os.WriteFile(patFile, []byte("cluster-pat"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := ORASPushConfig{Host: "h", ClusterID: "c1", PATPath: patFile}
	ref := reg.ref("latest")
	if _, err := PushSnapshotArtifact(context.Background(), cfg, writeTestSnapshotDir(t), ref); err != nil {
		t.Fatalf("push: %v", err)
	}
	if err := DeleteSnapshotRef(context.Background(), cfg, ref); err == nil {
		t.Fatal("expected delete failure")
	}
}

func TestPullAndPublishRenameRaceRecoversExistingFile(t *testing.T) {
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
		copyFile(t, src, final)
		return pulled, nil
	})
	defer restorePull()

	got, err := mr.pullAndPublish(context.Background(), "registry.example/org/mod:v1", "sha256:renrecover", ModuleAuth{})
	if err != nil {
		t.Fatalf("pullAndPublish: %v", err)
	}
	if got.Path != final {
		t.Fatalf("path = %q want %q", got.Path, final)
	}
}

func TestValidateFileReadErrorOnDirectory(t *testing.T) {
	if err := ValidateFile(t.TempDir()); err == nil {
		t.Fatal("expected read error when path is a directory")
	}
}

func TestPushSnapshotArtifactUnreadableConfig(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfgPath, []byte(`{"schema_version":1}`), 0o000); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"memory.zstd", "globals.cbor", "wasi-state.cbor"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	patFile := filepath.Join(t.TempDir(), "pat")
	if err := os.WriteFile(patFile, []byte("tok"), 0o600); err != nil {
		t.Fatal(err)
	}
	pushCfg := ORASPushConfig{Host: "h", ClusterID: "c", PATPath: patFile}
	_, err := PushSnapshotArtifact(context.Background(), pushCfg, dir, "127.0.0.1:1/repo:tag")
	if err == nil || !strings.Contains(err.Error(), "add config") {
		t.Fatalf("want add config error, got %v", err)
	}
}
