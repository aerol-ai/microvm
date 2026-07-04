package firecracker

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
)

func writeVerifyCacheFiles(t *testing.T, dir string, mem, state string) (string, string, string) {
	t.Helper()
	memPath := filepath.Join(dir, "snapshot.memory")
	statePath := filepath.Join(dir, "snapshot.state")
	if err := writeFile(memPath, []byte(mem)); err != nil {
		t.Fatalf("write memory: %v", err)
	}
	if err := writeFile(statePath, []byte(state)); err != nil {
		t.Fatalf("write state: %v", err)
	}
	return memPath, statePath, "sha256:mem|sha256:state"
}

func writeFile(path string, b []byte) error {
	return os.WriteFile(path, b, 0o600)
}

func TestVerifyCache_SecondLoadSkipsHash(t *testing.T) {
	memPath, statePath, checksum := writeVerifyCacheFiles(t, t.TempDir(), "mem", "state")
	d := New(Config{SnapshotVerifyOnLoad: true}, nil)
	var calls int32
	d.snapshotVerifier = func(_, _, _ string) error {
		atomic.AddInt32(&calls, 1)
		return nil
	}

	for i := 0; i < 2; i++ {
		if err := d.verifySnapshotForLoad("tpl-cache", memPath, statePath, checksum); err != nil {
			t.Fatalf("verify %d: %v", i, err)
		}
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("verifier calls = %d, want 1", got)
	}
}

func TestVerifyCache_SingleFlight(t *testing.T) {
	memPath, statePath, checksum := writeVerifyCacheFiles(t, t.TempDir(), "mem", "state")
	d := New(Config{SnapshotVerifyOnLoad: true}, nil)
	started := make(chan struct{})
	release := make(chan struct{})
	var closeStarted sync.Once
	var calls int32
	d.snapshotVerifier = func(_, _, _ string) error {
		atomic.AddInt32(&calls, 1)
		closeStarted.Do(func() { close(started) })
		<-release
		return nil
	}

	const workers = 8
	errs := make(chan error, workers)
	for i := 0; i < workers; i++ {
		go func() {
			errs <- d.verifySnapshotForLoad("tpl-cache", memPath, statePath, checksum)
		}()
	}
	<-started
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("verifier calls while first verify is blocked = %d, want 1", got)
	}
	close(release)
	for i := 0; i < workers; i++ {
		if err := <-errs; err != nil {
			t.Fatalf("worker %d verify error: %v", i, err)
		}
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("verifier calls after waiters returned = %d, want 1", got)
	}
}

func TestVerifyCache_FailureNotCached(t *testing.T) {
	memPath, statePath, checksum := writeVerifyCacheFiles(t, t.TempDir(), "mem", "state")
	d := New(Config{SnapshotVerifyOnLoad: true}, nil)
	var calls int32
	d.snapshotVerifier = func(_, _, _ string) error {
		if atomic.AddInt32(&calls, 1) == 1 {
			return models.ErrSnapshotCorrupt
		}
		return nil
	}

	if err := d.verifySnapshotForLoad("tpl-cache", memPath, statePath, checksum); !errors.Is(err, models.ErrSnapshotCorrupt) {
		t.Fatalf("first verify error = %v, want ErrSnapshotCorrupt", err)
	}
	if err := d.verifySnapshotForLoad("tpl-cache", memPath, statePath, checksum); err != nil {
		t.Fatalf("second verify: %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Fatalf("verifier calls = %d, want 2", got)
	}
}

func TestVerifyCache_InvalidatesOnFileChange(t *testing.T) {
	dir := t.TempDir()
	memPath, statePath, checksum := writeVerifyCacheFiles(t, dir, "mem", "state")
	d := New(Config{SnapshotVerifyOnLoad: true}, nil)
	var calls int32
	d.snapshotVerifier = func(_, _, _ string) error {
		atomic.AddInt32(&calls, 1)
		return nil
	}

	if err := d.verifySnapshotForLoad("tpl-cache", memPath, statePath, checksum); err != nil {
		t.Fatalf("first verify: %v", err)
	}
	if err := os.WriteFile(memPath, []byte("mem-new-size"), 0o600); err != nil {
		t.Fatalf("rewrite memory: %v", err)
	}
	if err := d.verifySnapshotForLoad("tpl-cache", memPath, statePath, checksum); err != nil {
		t.Fatalf("second verify: %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Fatalf("verifier calls = %d, want 2 after file identity changed", got)
	}
}

func TestVerifyCache_CorruptNotificationInvalidates(t *testing.T) {
	memPath, statePath, checksum := writeVerifyCacheFiles(t, t.TempDir(), "mem", "state")
	d := New(Config{SnapshotVerifyOnLoad: true}, nil)
	var calls int32
	d.snapshotVerifier = func(_, _, _ string) error {
		atomic.AddInt32(&calls, 1)
		return nil
	}

	if err := d.verifySnapshotForLoad("tpl-cache", memPath, statePath, checksum); err != nil {
		t.Fatalf("first verify: %v", err)
	}
	d.notifyCorrupt(context.Background(), "tpl-cache", "test invalidation")
	if err := d.verifySnapshotForLoad("tpl-cache", memPath, statePath, checksum); err != nil {
		t.Fatalf("second verify: %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Fatalf("verifier calls = %d, want 2 after corrupt invalidation", got)
	}
}

func TestVerifyCache_ModeAlways(t *testing.T) {
	memPath, statePath, checksum := writeVerifyCacheFiles(t, t.TempDir(), "mem", "state")
	d := New(Config{SnapshotVerifyOnLoad: true, SnapshotVerifyMode: snapshotVerifyModeAlways}, nil)
	var calls int32
	d.snapshotVerifier = func(_, _, _ string) error {
		atomic.AddInt32(&calls, 1)
		return nil
	}

	for i := 0; i < 2; i++ {
		if err := d.verifySnapshotForLoad("tpl-cache", memPath, statePath, checksum); err != nil {
			t.Fatalf("verify %d: %v", i, err)
		}
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Fatalf("verifier calls = %d, want 2 in always mode", got)
	}
}

// TestVerifyCache_WarmSpawnShares drives BOTH production call sites —
// WarmSpawn (the pool's refill goroutine) and a snapshot-load Create
// (configureVMMForLoad) — against one template and asserts they share
// a single cache entry: one hash total. Guards against the two call
// sites drifting onto separate caches (or one dropping the cache).
func TestVerifyCache_WarmSpawnShares(t *testing.T) {
	f := newDriverFixture(t)
	f.driver.cfg.SnapshotVerifyOnLoad = true
	var calls int32
	f.driver.snapshotVerifier = func(_, _, _ string) error {
		atomic.AddInt32(&calls, 1)
		return nil
	}

	tplDir := t.TempDir()
	rootfs := filepath.Join(tplDir, "rootfs.ext4")
	if err := writeFile(rootfs, []byte("ROOTFS")); err != nil {
		t.Fatalf("write rootfs: %v", err)
	}
	memPath, statePath, checksum := writeVerifyCacheFiles(t, tplDir, "mem", "state")
	f.driver.SetTemplateResolver(&fakeTemplateResolver{
		rootfsPath:         rootfs,
		hasSnapshot:        true,
		snapshotMemoryPath: memPath,
		snapshotStatePath:  statePath,
		snapshotChecksum:   checksum,
		snapshotVsockCID:   200,
	})

	if _, err := f.driver.WarmSpawn(context.Background(), WarmSpawnRequest{
		SlotID:             "vmms-warm-share",
		TemplateID:         "tpl-share",
		SnapshotMemoryPath: memPath,
		SnapshotStatePath:  statePath,
		SnapshotChecksum:   checksum,
		VsockCID:           200,
	}); err != nil {
		t.Fatalf("WarmSpawn: %v", err)
	}
	if _, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{
		Image: "alpine:3.20", CPU: 1, MemoryMB: 128, TemplateID: "tpl-share",
	}, "sb-verify-share", "tok", nil); err != nil {
		t.Fatalf("Create snapshot-load: %v", err)
	}

	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("verifier calls = %d, want 1 shared across WarmSpawn and Create", got)
	}
}

func TestVerifyCache_DisabledSkipsEntirely(t *testing.T) {
	memPath, statePath, checksum := writeVerifyCacheFiles(t, t.TempDir(), "mem", "state")
	d := New(Config{SnapshotVerifyOnLoad: false}, nil)
	d.snapshotVerifier = func(_, _, _ string) error {
		t.Fatal("snapshot verifier should not be called when verify-on-load is disabled")
		return nil
	}

	if err := d.verifySnapshotForLoad("tpl-cache", memPath, statePath, checksum); err != nil {
		t.Fatalf("verify disabled: %v", err)
	}
	if len(d.verifiedSnapshots) != 0 {
		t.Fatalf("verifiedSnapshots len = %d, want 0", len(d.verifiedSnapshots))
	}
}
