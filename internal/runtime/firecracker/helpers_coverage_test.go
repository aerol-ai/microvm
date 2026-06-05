package firecracker

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	vmmpool "github.com/aerol-ai/microvm/internal/pool/vmm"
	"github.com/aerol-ai/microvm/pkg/models"
)

func TestFromDaemonConfig(t *testing.T) {
	c := config.Config{
		FirecrackerBinary:               "/usr/local/bin/firecracker",
		JailerBinary:                    "/usr/local/bin/jailer",
		FirecrackerKernelImage:          "/var/lib/vmlinux",
		FirecrackerRunDir:               "/run/fc",
		FirecrackerTemplatesDir:         "/var/lib/templates",
		UseJailer:                       true,
		JailerChrootBase:                "/srv/jailer",
		JailerUID:                       1000,
		JailerGID:                       1001,
		FirecrackerSnapshotVerifyOnLoad: true,
		FirecrackerOverlayEnabled:       true,
		FirecrackerMkfs4Bin:             "/sbin/mkfs.ext4",
	}
	got := FromDaemonConfig(c)
	if got.FirecrackerBinary != c.FirecrackerBinary ||
		got.KernelImage != c.FirecrackerKernelImage ||
		got.RunDir != c.FirecrackerRunDir ||
		got.TemplatesDir != c.FirecrackerTemplatesDir ||
		!got.UseJailer ||
		got.JailerUID != 1000 || got.JailerGID != 1001 ||
		!got.SnapshotVerifyOnLoad || !got.OverlayEnabled {
		t.Fatalf("FromDaemonConfig mismatch: %+v", got)
	}
}

func TestStatusFromInstanceState(t *testing.T) {
	cases := map[string]models.SandboxStatus{
		"Running":     models.SandboxStatusStarted,
		"Paused":      models.SandboxStatusStopped,
		"Not started": models.SandboxStatusStopped,
		"weird":       models.SandboxStatusStarted, // default
	}
	for state, want := range cases {
		if got := statusFromInstanceState(state); got != want {
			t.Fatalf("statusFromInstanceState(%q) = %q, want %q", state, got, want)
		}
	}
}

func TestLinkOrCopyRootfs(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src.ext4")
	if err := os.WriteFile(src, []byte("rootfs-bytes"), 0o600); err != nil {
		t.Fatalf("write src: %v", err)
	}

	// Same-filesystem link succeeds.
	dst := filepath.Join(dir, "dst.ext4")
	if err := linkOrCopyRootfs(src, dst); err != nil {
		t.Fatalf("linkOrCopyRootfs: %v", err)
	}
	got, err := os.ReadFile(dst)
	if err != nil || string(got) != "rootfs-bytes" {
		t.Fatalf("dst contents = %q, %v", got, err)
	}

	// Missing source surfaces a real error (link target already exists OR
	// source missing — either way a non-EXDEV failure).
	if err := linkOrCopyRootfs(filepath.Join(dir, "nope.ext4"), filepath.Join(dir, "dst2.ext4")); err == nil {
		t.Fatal("expected error linking a missing source")
	}
}

func TestNonLinuxStubsAndWarmDestroyHandle(t *testing.T) {
	t.Run("rss_sampler_stub", func(t *testing.T) {
		pages, err := readRSSPagesForPID(123)
		if err != nil || pages != 0 {
			t.Fatalf("readRSSPagesForPID() = (%d,%v), want (0,nil)", pages, err)
		}
	})

	t.Run("vsock_stub", func(t *testing.T) {
		dialer := NewLinuxVsockDialer()
		if dialer == nil {
			t.Fatal("NewLinuxVsockDialer() returned nil")
		}
		conn, err := dialer.Dial(context.Background(), 3, 52)
		if conn != nil || err == nil {
			t.Fatalf("Dial() = (%v,%v), want nil + error", conn, err)
		}
	})

	t.Run("warm_destroy_handle_delegates", func(t *testing.T) {
		spawned := &stubSpawnedHandle{pid: 42}
		h := &warmDestroyHandle{spawned: spawned, apiSocket: "/tmp/api.sock", runDir: "/tmp/run"}
		if got := h.APISocket(); got != "/tmp/api.sock" {
			t.Fatalf("APISocket() = %q", got)
		}
		if got := h.RunDir(); got != "/tmp/run" {
			t.Fatalf("RunDir() = %q", got)
		}
		if got := h.Pid(); got != 42 {
			t.Fatalf("Pid() = %d", got)
		}
		if err := h.Start(context.Background()); err != nil {
			t.Fatalf("Start() error = %v", err)
		}
		if err := h.WaitSocket(context.Background(), time.Second); err != nil {
			t.Fatalf("WaitSocket() error = %v", err)
		}
		if err := h.Shutdown(context.Background(), 2*time.Second); err != nil {
			t.Fatalf("Shutdown() error = %v", err)
		}
		if spawned.shutdownCalls != 1 || spawned.lastGrace != 2*time.Second {
			t.Fatalf("spawned shutdown calls = %d grace=%v", spawned.shutdownCalls, spawned.lastGrace)
		}
		if err := h.Kill(); err != nil {
			t.Fatalf("Kill() error = %v", err)
		}
		if err := h.Cleanup(); err != nil {
			t.Fatalf("Cleanup() error = %v", err)
		}
		if got := h.StderrTail(); got != "" {
			t.Fatalf("StderrTail() = %q, want empty", got)
		}
	})
}

type stubSpawnedHandle struct {
	pid           int
	shutdownCalls int
	lastGrace     time.Duration
	shutdownErr   error
}

func (s *stubSpawnedHandle) APISocket() string { return "/tmp/spawned.sock" }
func (s *stubSpawnedHandle) RunDir() string    { return "/tmp/spawned" }
func (s *stubSpawnedHandle) Pid() int          { return s.pid }
func (s *stubSpawnedHandle) Shutdown(_ context.Context, grace time.Duration) error {
	s.shutdownCalls++
	s.lastGrace = grace
	return s.shutdownErr
}

var _ vmmpool.SpawnedHandle = (*stubSpawnedHandle)(nil)

func TestWarmHandleShutdownCoverage(t *testing.T) {
	driver := &Driver{sampler: NewRSSSampler(nil)}
	driver.rssRegister("slot-1", 999)

	base := &stubWarmBaseHandle{}
	h := &warmHandle{driver: driver, handle: base, slotID: "slot-1"}
	if err := h.Shutdown(context.Background(), time.Second); err != nil {
		t.Fatalf("Shutdown() error = %v", err)
	}
	if base.shutdownCalls != 1 || base.cleanupCalls != 1 {
		t.Fatalf("base calls shutdown=%d cleanup=%d", base.shutdownCalls, base.cleanupCalls)
	}

	base = &stubWarmBaseHandle{cleanupErr: errors.New("cleanup failed")}
	h = &warmHandle{driver: driver, handle: base, slotID: "slot-2"}
	if err := h.Shutdown(context.Background(), time.Second); err == nil {
		t.Fatal("expected cleanup error")
	}

	base = &stubWarmBaseHandle{shutdownErr: io.EOF}
	h = &warmHandle{driver: driver, handle: base, slotID: "slot-3"}
	if err := h.Shutdown(context.Background(), time.Second); !errors.Is(err, io.EOF) {
		t.Fatalf("expected shutdown error, got %v", err)
	}
}

type stubWarmBaseHandle struct {
	shutdownCalls int
	cleanupCalls  int
	shutdownErr   error
	cleanupErr    error
}

func (s *stubWarmBaseHandle) APISocket() string { return "/tmp/warm.sock" }
func (s *stubWarmBaseHandle) RunDir() string    { return "/tmp/warm" }
func (s *stubWarmBaseHandle) Pid() int          { return 7 }
func (s *stubWarmBaseHandle) Start(context.Context) error {
	return nil
}
func (s *stubWarmBaseHandle) WaitSocket(context.Context, time.Duration) error {
	return nil
}
func (s *stubWarmBaseHandle) Shutdown(_ context.Context, _ time.Duration) error {
	s.shutdownCalls++
	return s.shutdownErr
}
func (s *stubWarmBaseHandle) Kill() error { return nil }
func (s *stubWarmBaseHandle) Cleanup() error {
	s.cleanupCalls++
	return s.cleanupErr
}
func (s *stubWarmBaseHandle) StderrTail() string { return "" }
