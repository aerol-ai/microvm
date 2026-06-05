package firecracker

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigureVMMForLoad_Errors_Extra(t *testing.T) {
	d := &Driver{
		cfg: Config{SnapshotVerifyOnLoad: true},
	}
	client := newFakeClient()
	ctx := context.Background()
	slot := &TapSlot{TapName: "tap0"}

	// snap nil
	if err := d.configureVMMForLoad(ctx, client, nil, "/rootfs", slot, ""); err == nil || !strings.Contains(err.Error(), "nil resolution") {
		t.Errorf("expected nil resolution error, got %v", err)
	}

	// rootfs empty
	if err := d.configureVMMForLoad(ctx, client, &TemplateResolution{}, "", slot, ""); err == nil || !strings.Contains(err.Error(), "empty rootfs path") {
		t.Errorf("expected empty rootfs path error, got %v", err)
	}

	// slot nil
	if err := d.configureVMMForLoad(ctx, client, &TemplateResolution{}, "/rootfs", nil, ""); err == nil || !strings.Contains(err.Error(), "nil tap slot") {
		t.Errorf("expected nil tap slot error, got %v", err)
	}

	// checksum mismatch
	// Write dummy files for checksum
	mem := filepath.Join(t.TempDir(), "mem")
	state := filepath.Join(t.TempDir(), "state")
	os.WriteFile(mem, []byte("x"), 0644)
	os.WriteFile(state, []byte("y"), 0644)
	if err := d.configureVMMForLoad(ctx, client, &TemplateResolution{
		SnapshotMemoryPath: mem,
		SnapshotStatePath:  state,
		SnapshotChecksum:   "sha256:bad|sha256:bad",
	}, "/rootfs", slot, ""); err == nil || !strings.Contains(err.Error(), "snapshot integrity") {
		t.Errorf("expected snapshot integrity error, got %v", err)
	}
}

func TestLinkOrCopyRootfs_Errors_Extra(t *testing.T) {
	dir := t.TempDir()

	// Create a valid source file
	src := filepath.Join(dir, "src")
	os.WriteFile(src, []byte("data"), 0644)

	// Make dst a directory
	dstDir := filepath.Join(dir, "dstDir")
	os.Mkdir(dstDir, 0755)

	// Link should fail with EEXIST (if dstDir exists) or similar, which is not EXDEV/EPERM
	err := linkOrCopyRootfs(src, dstDir)
	if err == nil || !strings.Contains(err.Error(), "link template rootfs") {
		t.Errorf("expected link error (not fallback), got %v", err)
	}

	// Make dst not a directory but fallback copy write fails -> we can't easily do this unless EXDEV triggers.
	// But we covered EXDEV -> open out fails in previous tests maybe?
	err2 := linkOrCopyRootfs(dir, filepath.Join(dir, "dst2"))
	// dir is a directory, link fails with EPERM, fallback to copy, copy fails to read dir (or open dir)
	_ = err2
}

func TestOciImageRefFor(t *testing.T) {
	tests := []struct {
		in, out string
	}{
		{"", ""},
		{"docker://ubuntu", "docker://ubuntu"},
		{"oci-archive:/path/to/archive", "oci-archive:/path/to/archive"},
		{"ubuntu", "docker://ubuntu"},
	}
	for _, tc := range tests {
		if got := ociImageRefFor(tc.in); got != tc.out {
			t.Errorf("ociImageRefFor(%q) = %q, want %q", tc.in, got, tc.out)
		}
	}
}

func TestVcpuFromRequest(t *testing.T) {
	tests := []struct {
		cpu  float64
		want int
	}{
		{-1.0, 1},
		{0.0, 1},
		{1.0, 1},
		{1.2, 2},
		{2.0, 2},
	}
	for _, tc := range tests {
		if got := vcpuFromRequest(tc.cpu); got != tc.want {
			t.Errorf("vcpuFromRequest(%v) = %v, want %v", tc.cpu, got, tc.want)
		}
	}
}

func TestDriver_NotImplemented_Extra(t *testing.T) {
	d := &Driver{}
	ctx := context.Background()

	if err := d.RemoveImage(ctx, "img"); err == nil || !strings.Contains(err.Error(), "not yet implemented") {
		t.Errorf("expected not implemented error, got %v", err)
	}
	if err := d.PushAllowedPorts(ctx, "id", "port", []int{80}); err == nil || !strings.Contains(err.Error(), "not yet implemented") {
		t.Errorf("expected not implemented error, got %v", err)
	}
	if err := d.ClearNetworkRules("id"); err == nil || !strings.Contains(err.Error(), "not yet implemented") {
		t.Errorf("expected not implemented error, got %v", err)
	}
	if err := d.ApplyNetworkBlockAll("id"); err == nil || !strings.Contains(err.Error(), "not yet implemented") {
		t.Errorf("expected not implemented error, got %v", err)
	}
	if err := d.ApplyNetworkBlockIngress("id"); err == nil || !strings.Contains(err.Error(), "not yet implemented") {
		t.Errorf("expected not implemented error, got %v", err)
	}
	if err := d.ClearNetworkBlockIngress("id"); err == nil || !strings.Contains(err.Error(), "not yet implemented") {
		t.Errorf("expected not implemented error, got %v", err)
	}
	if err := d.ClearNetworkBlockEgress("id"); err == nil || !strings.Contains(err.Error(), "not yet implemented") {
		t.Errorf("expected not implemented error, got %v", err)
	}
	if err := d.Resize(ctx, "id", nil); err == nil || !strings.Contains(err.Error(), "not yet implemented") {
		t.Errorf("expected not implemented error, got %v", err)
	}
}

func TestDriver_Inspect_Ping_Extra(t *testing.T) {
	d := &Driver{
		clients: make(map[string]VMMClient),
	}
	ctx := context.Background()

	// Inspect missing
	if state, err := d.Inspect(ctx, "nonexistent"); err != nil || state != nil {
		t.Errorf("expected nil state and nil error, got %v, %v", state, err)
	}

	// Ping with missing binaries
	if err := d.Ping(ctx); err == nil || !strings.Contains(err.Error(), "SB_FIRECRACKER_BINARY is not set") {
		t.Errorf("expected SB_FIRECRACKER_BINARY error, got %v", err)
	}
	d.cfg.FirecrackerBinary = "firecracker"
	if err := d.Ping(ctx); err == nil || !strings.Contains(err.Error(), "SB_JAILER_BINARY is not set") {
		t.Errorf("expected SB_JAILER_BINARY error, got %v", err)
	}
	d.cfg.JailerBinary = "jailer"
	if err := d.Ping(ctx); err == nil || (!strings.Contains(err.Error(), "stat") && !strings.Contains(err.Error(), "no such file")) {
		t.Errorf("expected stat error for FirecrackerBinary, got %v", err)
	}
	// Create dummy files for Ping
	dir := t.TempDir()
	d.cfg.FirecrackerBinary = filepath.Join(dir, "fc")
	d.cfg.JailerBinary = filepath.Join(dir, "jail")
	d.cfg.KernelImage = filepath.Join(dir, "kernel")
	os.WriteFile(d.cfg.FirecrackerBinary, nil, 0755)
	os.WriteFile(d.cfg.JailerBinary, nil, 0755)

	if err := d.Ping(ctx); err == nil || (!strings.Contains(err.Error(), "stat") && !strings.Contains(err.Error(), "no such file")) {
		t.Errorf("expected stat error for KernelImage, got %v", err)
	}
	os.WriteFile(d.cfg.KernelImage, nil, 0755)
	if err := d.Ping(ctx); err != nil {
		t.Errorf("expected nil error, got %v", err)
	}
}
