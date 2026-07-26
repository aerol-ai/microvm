package mounts

import (
	"context"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts/adapters"
)

type envKernelAdapter struct{}

func (envKernelAdapter) Build(_ string, _ int, _ models.MountSpec, _, _ string) (adapters.Plan, error) {
	return adapters.Plan{
		Argv:          []string{"true"},
		IsKernelMount: true,
		Env:           []string{"MOUNT_TEST_ENV=1"},
	}, nil
}

func TestMountAllEmptyMounts(t *testing.T) {
	m := newTestManager(t, map[models.MountType]adapters.Adapter{})
	binds, err := m.MountAll(context.Background(), "sb-empty", nil)
	if err != nil {
		t.Fatalf("MountAll(nil): %v", err)
	}
	if binds != nil {
		t.Fatalf("binds = %#v, want nil", binds)
	}
}

func TestCloseIdempotent(t *testing.T) {
	m := newTestManager(t, map[models.MountType]adapters.Adapter{})
	m.Close()
	m.Close() // second close must not panic
}

func TestSweepSkipsNonDirEntries(t *testing.T) {
	root := t.TempDir()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	m, err := New(logger, Config{RootDir: root, CredDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "not-a-sandbox"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	m.Sweep(map[string]struct{}{})
}

func TestCleanupOrphanDirRemoveAllFailure(t *testing.T) {
	root := t.TempDir()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	m, err := New(logger, Config{RootDir: root, CredDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	orphan := filepath.Join(root, "orphan-rm-fail")
	if err := os.MkdirAll(orphan, 0o700); err != nil {
		t.Fatal(err)
	}
	blocker := filepath.Join(orphan, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o444); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(orphan, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(orphan, 0o700) })
	m.cleanupOrphanDir(orphan)
}

func TestMountOneHostPathMkdirFailure(t *testing.T) {
	m := newTestManager(t, map[models.MountType]adapters.Adapter{
		models.MountTypeS3: fakeAdapter{},
	})
	sandboxDir := filepath.Join(m.rootDir, "sb-mkdir-fail")
	if err := os.MkdirAll(sandboxDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sandboxDir, "0"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := m.MountAll(context.Background(), "sb-mkdir-fail", []models.MountSpec{
		{Type: models.MountTypeS3, Source: "s3://a", Target: "/a"},
	})
	if err == nil {
		t.Fatal("expected mkdir failure when mount index path is a file")
	}
}

func TestMountOneKernelMountWithEnv(t *testing.T) {
	oldProbe := waitForMountProbe
	waitForMountProbe = func(string, time.Duration) error { return nil }
	t.Cleanup(func() { waitForMountProbe = oldProbe })

	m := newTestManager(t, map[models.MountType]adapters.Adapter{
		models.MountTypeNFS: envKernelAdapter{},
	})
	_, err := m.MountAll(context.Background(), "sb-kernel-env", []models.MountSpec{
		{Type: models.MountTypeNFS, Source: "host:/x", Target: "/mnt"},
	})
	if err != nil {
		t.Fatalf("MountAll: %v", err)
	}
}

func TestSuperviseExitNilCmdAndDisabled(t *testing.T) {
	m := newTestManager(t, map[models.MountType]adapters.Adapter{})
	m.superviseExit(&mountState{sandboxID: "none", cmd: nil})

	hostPath := filepath.Join(m.rootDir, "sb-disabled", "0")
	if err := os.MkdirAll(hostPath, 0o700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("true")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	state := &mountState{
		sandboxID: "sb-disabled",
		index:     0,
		hostPath:  hostPath,
		plan:      adapters.Plan{Argv: []string{"true"}},
		cmd:       cmd,
		disabled:  true,
	}
	m.mu.Lock()
	m.state["sb-disabled"] = []*mountState{state}
	m.mu.Unlock()
	m.superviseExit(state)
}

func TestCapturedOutputTailTruncation(t *testing.T) {
	out := &capturedOutput{}
	payload := strings.Repeat("x", maxCapturedMountBytes+512)
	if n, err := out.Write([]byte(payload)); err != nil || n != len(payload) {
		t.Fatalf("Write = %d, %v", n, err)
	}
	out.mu.Lock()
	bufLen := len(out.buf)
	out.mu.Unlock()
	if bufLen != maxCapturedMountBytes {
		t.Fatalf("buffer len = %d, want %d", bufLen, maxCapturedMountBytes)
	}
}

func TestSpawnMountProcessWithEnv(t *testing.T) {
	cmd, out, err := spawnMountProcess(adapters.Plan{
		Argv: []string{"true"},
		Env:  []string{"MOUNT_SPAWN_ENV=1"},
	})
	if err != nil {
		t.Fatalf("spawnMountProcess: %v", err)
	}
	t.Cleanup(func() { _ = killMount(cmd) })
	if out == nil {
		t.Fatal("expected captured output")
	}
}

func TestUnmountTreeSkipsNonDirEntries(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	root := t.TempDir()
	child := filepath.Join(root, "child")
	if err := os.MkdirAll(child, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(child, "file.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	unmountTree(logger, root)
}

func TestKillMountSIGKILLAfterTermIgnored(t *testing.T) {
	cmd := exec.Command("sh", "-c", "trap '' TERM; sleep 60")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Skip("cannot start subprocess:", err)
	}
	if err := killMount(cmd); err != nil {
		t.Fatalf("killMount: %v", err)
	}
}

func TestWaitForMountStatParentFailure(t *testing.T) {
	if err := waitForMount("/nonexistent/parent/child", 50*time.Millisecond); err == nil {
		t.Fatal("expected stat parent failure")
	}
}

func TestMountOneCredFileWriteFailure(t *testing.T) {
	oldProbe := waitForMountProbe
	waitForMountProbe = func(string, time.Duration) error { return nil }
	t.Cleanup(func() { waitForMountProbe = oldProbe })

	credDir := t.TempDir()
	blocker := filepath.Join(credDir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	m := newTestManager(t, map[models.MountType]adapters.Adapter{
		models.MountTypeS3: adapterFunc(func(sandboxID string, index int, spec models.MountSpec, hostTarget, dir string) (adapters.Plan, error) {
			return adapters.Plan{
				Argv:          []string{"true"},
				IsKernelMount: true,
				CredFile:      filepath.Join(blocker, "nested", "cred.json"),
				CredBody:      []byte("secret"),
			}, nil
		}),
	})
	m.credDir = credDir

	_, err := m.MountAll(context.Background(), "sb-cred-fail", []models.MountSpec{
		{Type: models.MountTypeS3, Source: "s3://a", Target: "/a"},
	})
	if err == nil {
		t.Fatal("expected cred file write failure")
	}
}

type adapterFunc func(string, int, models.MountSpec, string, string) (adapters.Plan, error)

func (f adapterFunc) Build(sandboxID string, index int, spec models.MountSpec, hostTarget, credDir string) (adapters.Plan, error) {
	return f(sandboxID, index, spec, hostTarget, credDir)
}
