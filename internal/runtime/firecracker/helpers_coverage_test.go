package firecracker

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/aerol-ai/microvm/internal/config"
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
