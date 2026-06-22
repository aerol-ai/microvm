package firecracker

import (
	"os"
	"path/filepath"
	"testing"
)

// TestChrootFilePath_DirectMode: with UseJailer=false there is no chroot, so the
// helper must return the absolute source path unchanged and stage nothing. This
// is the property that keeps the dev/CI direct-spawn path (and every existing
// fakeVMM test) behaving exactly as before the jailer fix.
func TestChrootFilePath_DirectMode(t *testing.T) {
	d := &Driver{cfg: Config{UseJailer: false}}
	runDir := t.TempDir()
	src := filepath.Join(t.TempDir(), "vmlinux-host")
	if err := os.WriteFile(src, []byte("k"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := d.chrootFilePath(runDir, src, kernelFileName)
	if err != nil {
		t.Fatalf("chrootFilePath: %v", err)
	}
	if got != src {
		t.Errorf("direct mode path = %q, want absolute src %q", got, src)
	}
	if _, err := os.Stat(filepath.Join(runDir, kernelFileName)); !os.IsNotExist(err) {
		t.Errorf("direct mode must not stage into runDir (stat err = %v)", err)
	}
}

// TestChrootFilePath_JailerStagesAndReturnsRelative: a source that lives outside
// the chroot (the shared kernel) must be hardlinked/copied in and referenced by
// its bare relative name — the exact failure that produced "kernel file cannot
// be opened" once the OCI rootfs build started succeeding (UC-24/88).
func TestChrootFilePath_JailerStagesAndReturnsRelative(t *testing.T) {
	d := &Driver{cfg: Config{UseJailer: true}}
	runDir := t.TempDir()
	src := filepath.Join(t.TempDir(), "vmlinux-host")
	if err := os.WriteFile(src, []byte("kernel-bytes"), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := d.chrootFilePath(runDir, src, kernelFileName)
	if err != nil {
		t.Fatalf("chrootFilePath: %v", err)
	}
	if got != kernelFileName {
		t.Errorf("jailer path = %q, want relative %q", got, kernelFileName)
	}
	staged := filepath.Join(runDir, kernelFileName)
	b, err := os.ReadFile(staged)
	if err != nil {
		t.Fatalf("kernel not staged into chroot: %v", err)
	}
	if string(b) != "kernel-bytes" {
		t.Errorf("staged kernel content = %q, want original bytes", string(b))
	}
}

// TestChrootFilePath_JailerInPlaceIsNoop: the rootfs and overlay are built
// directly into runDir, so src already equals runDir/destName. The helper must
// NOT try to link a file onto itself (which would fail EEXIST) — it just returns
// the basename.
func TestChrootFilePath_JailerInPlaceIsNoop(t *testing.T) {
	d := &Driver{cfg: Config{UseJailer: true}}
	runDir := t.TempDir()
	inPlace := filepath.Join(runDir, rootfsFileName)
	if err := os.WriteFile(inPlace, []byte("rootfs"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := d.chrootFilePath(runDir, inPlace, rootfsFileName)
	if err != nil {
		t.Fatalf("chrootFilePath in-place: %v", err)
	}
	if got != rootfsFileName {
		t.Errorf("in-place path = %q, want %q", got, rootfsFileName)
	}
	// The file must be untouched (same bytes, still present).
	if b, err := os.ReadFile(inPlace); err != nil || string(b) != "rootfs" {
		t.Errorf("in-place file disturbed: bytes=%q err=%v", string(b), err)
	}
}

// TestChrootFilePath_JailerOverwritesStaleStage: a leftover file from a previous
// attempt must not make staging fail with EEXIST — the helper removes it first
// so a retried Create is idempotent.
func TestChrootFilePath_JailerOverwritesStaleStage(t *testing.T) {
	d := &Driver{cfg: Config{UseJailer: true}}
	runDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(runDir, kernelFileName), []byte("stale"), 0o644); err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(t.TempDir(), "vmlinux-host")
	if err := os.WriteFile(src, []byte("fresh"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := d.chrootFilePath(runDir, src, kernelFileName); err != nil {
		t.Fatalf("chrootFilePath over stale: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(runDir, kernelFileName)); string(b) != "fresh" {
		t.Errorf("stale stage not replaced: %q", string(b))
	}
}
