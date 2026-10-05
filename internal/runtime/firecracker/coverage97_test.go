package firecracker

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type cov97TapPool struct{}

func (cov97TapPool) Allocate(context.Context, string, time.Time) (*TapSlot, error) {
	return nil, errors.New("pool full")
}
func (cov97TapPool) Transfer(context.Context, string, string, time.Time) (*TapSlot, error) {
	return nil, errors.New("pool full")
}
func (cov97TapPool) Release(context.Context, string) error { return errors.New("release") }
func (cov97TapPool) Get(context.Context, string) (*TapSlot, error) {
	return nil, errors.New("missing")
}

type cov97ReleasePool struct{}

func (cov97ReleasePool) Allocate(context.Context, string, time.Time) (*TapSlot, error) {
	return &TapSlot{TapName: "tap0"}, nil
}
func (cov97ReleasePool) Transfer(context.Context, string, string, time.Time) (*TapSlot, error) {
	return nil, errors.New("pool full")
}
func (cov97ReleasePool) Release(context.Context, string) error { return errors.New("release") }
func (cov97ReleasePool) Get(context.Context, string) (*TapSlot, error) {
	return nil, errors.New("missing")
}

type cov97Vsock struct{}

func (cov97Vsock) Dial(context.Context, string, uint32, uint32) (io.ReadWriteCloser, error) {
	return nil, errors.New("no vsock")
}

func TestCoverage97SnapshotAllocateFails(t *testing.T) {
	d := &Driver{
		cfg:    Config{KernelImage: "/kernel"},
		pool:   cov97TapPool{},
		logger: slog.New(slog.DiscardHandler),
	}
	d.SetTapHost(&fakeTapHost{})
	d.SetVsockDialer(cov97Vsock{})
	_, err := d.SnapshotTemplate(context.Background(), TemplateSnapshotRequest{
		TemplateID:    "tpl",
		RootfsPath:    "/rootfs",
		OutMemoryPath: "/mem",
		OutStatePath:  "/state",
		GuestCID:      3,
	})
	if err == nil || !strings.Contains(err.Error(), "tap allocate") {
		t.Fatalf("SnapshotTemplate = %v", err)
	}
}

func TestCoverage97SnapshotSpawnFailsAfterAllocate(t *testing.T) {
	parent := t.TempDir()
	blocker := filepath.Join(parent, "not-a-dir")
	if err := os.WriteFile(blocker, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	handle := &fakeVMM{runDir: filepath.Join(blocker, "run"), cleanupErr: errors.New("cleanup")}
	d := &Driver{
		cfg:    Config{KernelImage: "/kernel"},
		pool:   cov97ReleasePool{},
		logger: slog.New(slog.DiscardHandler),
	}
	d.SetTapHost(&fakeTapHost{})
	d.SetVsockDialer(cov97Vsock{})
	d.SetSpawner(func(Config, string) (VMMHandle, error) { return handle, nil })
	_, err := d.SnapshotTemplate(context.Background(), TemplateSnapshotRequest{
		TemplateID:    "tpl",
		RootfsPath:    "/rootfs",
		OutMemoryPath: "/mem",
		OutStatePath:  "/state",
		GuestCID:      3,
	})
	if err == nil {
		t.Fatal("snapshot succeeded")
	}
}
