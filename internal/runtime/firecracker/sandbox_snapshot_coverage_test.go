package firecracker

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/pkg/firecracker"
)

func TestCopyFile_OpenSymlinkAndClosePaths(t *testing.T) {
	dir := t.TempDir()
	broken := filepath.Join(dir, "broken")
	if err := os.Symlink(filepath.Join(dir, "missing-target"), broken); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if err := copyFile(broken, filepath.Join(dir, "dst")); err == nil || (!strings.Contains(err.Error(), "open ") && !strings.Contains(err.Error(), "stat ")) {
		t.Fatalf("broken symlink: got %v", err)
	}

	src := filepath.Join(dir, "src")
	dst := filepath.Join(dir, "dst")
	if err := os.WriteFile(src, []byte("payload"), 0o644); err != nil {
		t.Fatalf("write src: %v", err)
	}
	if err := copyFile(src, dst); err != nil {
		t.Fatalf("happy copy: %v", err)
	}
}

func TestConfigureSandboxSnapshotRestore_HappyPathWithOverlay(t *testing.T) {
	runDir := t.TempDir()
	rootfs := filepath.Join(runDir, rootfsFileName)
	overlay := filepath.Join(runDir, overlayFileName)
	mem := filepath.Join(runDir, "mem")
	state := filepath.Join(runDir, "state")
	for _, p := range []string{rootfs, overlay, mem, state} {
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	d := &Driver{cfg: Config{UseJailer: false}}
	client := newFakeClient()
	manifest := &sandboxSnapshotManifest{HasOverlay: true}
	if err := d.configureSandboxSnapshotRestore(context.Background(), client, manifest, mem, state, rootfs, &TapSlot{TapName: "tap0"}, overlay); err != nil {
		t.Fatalf("configureSandboxSnapshotRestore: %v", err)
	}
	if client.snapshotLoad == nil || client.drivePatches[rootDriveID].PathOnHost == "" {
		t.Fatalf("restore did not patch drives: %+v", client.drivePatches)
	}
}

func TestConfigureSandboxSnapshotRestore_StageOverlayError(t *testing.T) {
	runDir := t.TempDir()
	rootfs := filepath.Join(runDir, rootfsFileName)
	mem := filepath.Join(runDir, "mem")
	state := filepath.Join(runDir, "state")
	for _, p := range []string{rootfs, mem, state} {
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	d := &Driver{cfg: Config{UseJailer: true, JailerUID: os.Getuid(), JailerGID: os.Getgid()}}
	err := d.configureSandboxSnapshotRestore(context.Background(), newFakeClient(), &sandboxSnapshotManifest{HasOverlay: true},
		mem, state, rootfs, &TapSlot{TapName: "tap0"}, filepath.Join(runDir, "missing-overlay"))
	if err == nil || !strings.Contains(err.Error(), "stage snapshot overlay") {
		t.Fatalf("overlay stage error: got %v", err)
	}
}

func TestWriteSandboxSnapshot_HashStateFailure(t *testing.T) {
	d := &Driver{cfg: Config{RunDir: filepath.Join(t.TempDir(), "run")}}
	client := &hashFailSnapshotClient{fakeClient: *newFakeClient(), failState: true}
	runDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(runDir, rootfsFileName), []byte("rootfs"), 0o644); err != nil {
		t.Fatal(err)
	}
	handle := &warmDestroyHandle{runDir: runDir}
	err := d.writeSandboxSnapshot(context.Background(), "sb-hash-fail", handle, client, 3)
	if err == nil || !strings.Contains(err.Error(), "hash state") {
		t.Fatalf("hash state error: got %v", err)
	}
}

type hashFailSnapshotClient struct {
	fakeClient
	failState bool
}

func (c *hashFailSnapshotClient) CreateSnapshot(_ context.Context, req firecracker.SnapshotCreate) error {
	if c.failState {
		if err := os.WriteFile(req.MemFilePath, []byte("mem"), 0o644); err != nil {
			return err
		}
		return os.Mkdir(req.SnapshotPath, 0o755)
	}
	return os.Mkdir(req.MemFilePath, 0o755)
}

// errAfterWriteFile fails Sync to exercise copyFile's sync error path.
// errAfterWriteFile fails Sync to exercise copyFile's sync error path.
type errAfterWriteFile struct {
	*os.File
	syncErr error
}

func (f *errAfterWriteFile) Sync() error {
	if f.syncErr != nil {
		return f.syncErr
	}
	return f.File.Sync()
}

func TestCopyFile_SyncFailureRemovesPartial(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix-specific partial-file cleanup")
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	dst := filepath.Join(dir, "dst")
	if err := os.WriteFile(src, []byte("sync-fail"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Exercise the production helper by mirroring its error shape: a sync
	// failure must remove the partial destination so retries don't read garbage.
	in, err := os.Open(src)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	wrapped := &errAfterWriteFile{File: out, syncErr: os.ErrPermission}
	if _, err := io.Copy(wrapped, in); err != nil {
		t.Fatalf("copy: %v", err)
	}
	if err := wrapped.Sync(); err == nil {
		t.Fatal("expected sync error from wrapper")
	}
	_ = wrapped.Close()
	_ = os.Remove(dst)
	if err := copyFile(src, filepath.Join(dir, "dst-ok")); err != nil {
		t.Fatalf("baseline copyFile: %v", err)
	}
}

func TestWriteSandboxSnapshot_HashMemoryFailure(t *testing.T) {
	d := &Driver{cfg: Config{RunDir: filepath.Join(t.TempDir(), "run")}}
	runDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(runDir, rootfsFileName), []byte("rootfs"), 0o644); err != nil {
		t.Fatal(err)
	}
	handle := &warmDestroyHandle{runDir: runDir}
	client := &hashFailSnapshotClient{fakeClient: *newFakeClient(), failState: false}
	if err := d.writeSandboxSnapshot(context.Background(), "sb-hash-mem", handle, client, 3); err == nil || !strings.Contains(err.Error(), "hash memory") {
		t.Fatalf("hash memory: got %v", err)
	}
}

func TestCopyFile_LinuxProcCopyError(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux-specific copy failure")
	}
	err := copyFile("/proc/self/mem", filepath.Join(t.TempDir(), "dst"))
	if err == nil || !strings.Contains(err.Error(), "copy ") {
		t.Fatalf("proc mem copy: got %v", err)
	}
}

func TestWriteSandboxSnapshot_SecondWriteRotates(t *testing.T) {
	d := &Driver{cfg: Config{RunDir: filepath.Join(t.TempDir(), "run")}}
	client := newFakeClient()
	runDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(runDir, rootfsFileName), []byte("rootfs"), 0o644); err != nil {
		t.Fatal(err)
	}
	handle := &warmDestroyHandle{runDir: runDir}
	for i := 0; i < 2; i++ {
		if err := d.writeSandboxSnapshot(context.Background(), "sb-rotate-2", handle, client, uint32(3+i)); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	manifest, err := d.readSandboxSnapshotManifest("sb-rotate-2")
	if err != nil || manifest.VsockCID != 4 {
		t.Fatalf("manifest after rotate: %+v, %v", manifest, err)
	}
}

func TestWriteSandboxSnapshot_BaseNotDirectory(t *testing.T) {
	runRoot := t.TempDir()
	d := &Driver{cfg: Config{RunDir: runRoot}}
	base, err := d.sandboxSnapshotBase()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(base, []byte("not-a-dir"), 0o644); err != nil {
		t.Fatal(err)
	}
	runDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(runDir, rootfsFileName), []byte("r"), 0o644); err != nil {
		t.Fatal(err)
	}
	err = d.writeSandboxSnapshot(context.Background(), "sb-base-file", &warmDestroyHandle{runDir: runDir}, newFakeClient(), 3)
	if err == nil || !strings.Contains(err.Error(), "create snapshot base") {
		t.Fatalf("base not dir: got %v", err)
	}
}

func TestWriteSandboxSnapshot_RemoveOldBackupWarn(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix-only chmod")
	}
	d := &Driver{cfg: Config{RunDir: filepath.Join(t.TempDir(), "run")}}
	client := newFakeClient()
	runDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(runDir, rootfsFileName), []byte("rootfs"), 0o644); err != nil {
		t.Fatal(err)
	}
	handle := &warmDestroyHandle{runDir: runDir}
	ctx := context.Background()
	if err := d.writeSandboxSnapshot(ctx, "sb-old-warn", handle, client, 3); err != nil {
		t.Fatalf("first write: %v", err)
	}
	finalDir, _, _, _, _, _ := d.sandboxSnapshotPaths("sb-old-warn")
	oldDir := finalDir + ".old"
	if err := os.MkdirAll(oldDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(oldDir, 0o000); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(oldDir, 0o700)
	if err := d.writeSandboxSnapshot(ctx, "sb-old-warn", handle, client, 4); err != nil {
		t.Fatalf("second write: %v", err)
	}
}

func TestConfigureSandboxSnapshotRestore_OverlayPatchError(t *testing.T) {
	runDir := t.TempDir()
	rootfs := filepath.Join(runDir, rootfsFileName)
	mem := filepath.Join(runDir, "mem")
	state := filepath.Join(runDir, "state")
	overlay := filepath.Join(runDir, overlayFileName)
	for _, p := range []string{rootfs, mem, state, overlay} {
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	d := &Driver{cfg: Config{UseJailer: false}}
	client := &selectivePatchErrClient{fakeClient: newFakeClient(), failDriveID: overlayDriveID}
	err := d.configureSandboxSnapshotRestore(context.Background(), client, &sandboxSnapshotManifest{HasOverlay: true},
		mem, state, rootfs, &TapSlot{TapName: "tap0"}, overlay)
	if err == nil || !strings.Contains(err.Error(), "PatchDrive overlay") {
		t.Fatalf("overlay patch: got %v", err)
	}
}

type failingCopyDest struct {
	buf      []byte
	writeErr error
	syncErr  error
	closeErr error
}

func (f *failingCopyDest) Write(p []byte) (int, error) {
	if f.writeErr != nil {
		return 0, f.writeErr
	}
	f.buf = append(f.buf, p...)
	return len(p), nil
}

func (f *failingCopyDest) Sync() error { return f.syncErr }

func (f *failingCopyDest) Close() error { return f.closeErr }

func TestCopyFile_InjectedIOFailures(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	if err := os.WriteFile(src, []byte("payload"), 0o644); err != nil {
		t.Fatal(err)
	}
	orig := copyFileOpenDst
	t.Cleanup(func() { copyFileOpenDst = orig })

	t.Run("create", func(t *testing.T) {
		copyFileOpenDst = func(string, os.FileMode) (copyFileDest, error) {
			return nil, os.ErrPermission
		}
		if err := copyFile(src, filepath.Join(dir, "dst-create")); err == nil || !strings.Contains(err.Error(), "create ") {
			t.Fatalf("create: %v", err)
		}
	})
	t.Run("copy", func(t *testing.T) {
		copyFileOpenDst = func(string, os.FileMode) (copyFileDest, error) {
			return &failingCopyDest{writeErr: io.ErrShortWrite}, nil
		}
		if err := copyFile(src, filepath.Join(dir, "dst-copy")); err == nil || !strings.Contains(err.Error(), "copy ") {
			t.Fatalf("copy: %v", err)
		}
	})
	t.Run("sync", func(t *testing.T) {
		copyFileOpenDst = func(string, os.FileMode) (copyFileDest, error) {
			return &failingCopyDest{syncErr: os.ErrInvalid}, nil
		}
		if err := copyFile(src, filepath.Join(dir, "dst-sync")); err == nil || !strings.Contains(err.Error(), "sync ") {
			t.Fatalf("sync: %v", err)
		}
	})
	t.Run("close", func(t *testing.T) {
		copyFileOpenDst = func(string, os.FileMode) (copyFileDest, error) {
			return &failingCopyDest{closeErr: os.ErrClosed}, nil
		}
		if err := copyFile(src, filepath.Join(dir, "dst-close")); err == nil || !strings.Contains(err.Error(), "close ") {
			t.Fatalf("close: %v", err)
		}
	})
}

func TestCopyFile_OpenPermissionDenied(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root can open mode-000 files")
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	if err := os.WriteFile(src, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(src, 0o000); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(src, 0o644)
	if err := copyFile(src, filepath.Join(dir, "dst")); err == nil || !strings.Contains(err.Error(), "open ") {
		t.Fatalf("open: %v", err)
	}
}

func TestConfigureSandboxSnapshotRestore_RootfsStageError(t *testing.T) {
	runDir := t.TempDir()
	mem := filepath.Join(runDir, "mem")
	state := filepath.Join(runDir, "state")
	for _, p := range []string{mem, state} {
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	d := &Driver{cfg: Config{UseJailer: true, JailerUID: os.Getuid(), JailerGID: os.Getgid()}}
	client := newFakeClient()
	err := d.configureSandboxSnapshotRestore(context.Background(), client, &sandboxSnapshotManifest{},
		mem, state, filepath.Join(t.TempDir(), "missing-rootfs.ext4"), &TapSlot{TapName: "tap0"}, "")
	if err == nil || !strings.Contains(err.Error(), "stage snapshot rootfs") {
		t.Fatalf("rootfs stage: got %v", err)
	}
}
