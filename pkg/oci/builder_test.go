package oci

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeFake drops a shell script at <dir>/<name> implementing the script
// body. The script is marked executable. Returns the path.
//
// We use shell scripts (not Go subprocess helpers) because the tests need
// to assert *behavior* — that the right args land at the right tool, and
// that each stage produces the file/directory the next stage consumes.
// A Go helper would obscure the shape behind a shared TestMain.
func writeFake(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatalf("write fake %s: %v", name, err)
	}
	return p
}

// happyConfig wires fakes that produce the artifacts each subsequent
// stage expects, so the whole pipeline can run end-to-end in a TempDir.
func happyConfig(t *testing.T) (Config, string) {
	t.Helper()
	dir := t.TempDir()
	bins := filepath.Join(dir, "bins")
	work := filepath.Join(dir, "work")
	if err := os.MkdirAll(bins, 0o755); err != nil {
		t.Fatalf("mkdir bins: %v", err)
	}

	// Fake skopeo: arg parser pulls out the last arg ("oci:<dir>:<tag>"),
	// strips the prefix and tag, mkdir -p that path. Real skopeo
	// materializes an OCI layout (blobs/, index.json, oci-layout) but
	// the next stage's fake doesn't care about contents, only that the
	// directory exists.
	skopeo := writeFake(t, bins, "skopeo", `
last="$1"
while [ $# -gt 1 ]; do shift; last="$1"; done
case "$last" in
  oci:*) path="${last#oci:}"; path="${path%:*}"; mkdir -p "$path/blobs" "$path"; echo '{}' > "$path/index.json" ;;
esac
`)

	// Fake umoci: argv contains "<dir> ... <bundleDir>" at the end. We
	// pluck out the bundle (last arg) and the image (--image <val>), then
	// create bundle/rootfs/ with a sentinel file so mkfs has something to
	// copy in.
	umoci := writeFake(t, bins, "umoci", `
img=""
last="$1"
while [ $# -gt 0 ]; do
  case "$1" in
    --image) img="$2"; shift 2 ;;
    *) last="$1"; shift ;;
  esac
done
mkdir -p "$last/rootfs/bin" "$last/rootfs/etc"
echo "fake-binary" > "$last/rootfs/bin/sh"
echo "img=$img" > "$last/rootfs/etc/oci-meta"
`)

	// Fake mkfs.ext4: writes a sparse file of size derived from the
	// "<size>M" arg if present, else a fixed small file. Touches the
	// path with content so Build's stat() reports a sensible size.
	mkfs := writeFake(t, bins, "mkfs.ext4", `
out=""
size=""
while [ $# -gt 0 ]; do
  case "$1" in
    -d) shift 2 ;;
    -F) shift ;;
    *)
      if [ -z "$out" ]; then out="$1"; else size="$1"; fi
      shift
      ;;
  esac
done
if [ -n "$size" ]; then
  # Strip trailing "M" — fake just writes a short file; the size knob
  # being passed at all is what the test asserts.
  printf 'fake-ext4-image\n' > "$out"
else
  printf 'fake-ext4-image-no-size\n' > "$out"
fi
`)

	return Config{
		SkopeoBin: skopeo,
		UmociBin:  umoci,
		Mkfs4Bin:  mkfs,
		WorkDir:   work,
	}, work
}

func TestNew_Validation(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  Config
	}{
		{"no skopeo", Config{UmociBin: "u", Mkfs4Bin: "m", WorkDir: "/w"}},
		{"no umoci", Config{SkopeoBin: "s", Mkfs4Bin: "m", WorkDir: "/w"}},
		{"no mkfs", Config{SkopeoBin: "s", UmociBin: "u", WorkDir: "/w"}},
		{"no workdir", Config{SkopeoBin: "s", UmociBin: "u", Mkfs4Bin: "m"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := New(tc.cfg); err == nil {
				t.Fatal("expected error for missing field")
			}
		})
	}
	t.Run("ok", func(t *testing.T) {
		if _, err := New(Config{SkopeoBin: "s", UmociBin: "u", Mkfs4Bin: "m", WorkDir: "/w"}); err != nil {
			t.Fatal(err)
		}
	})
}

// TestBuild_HappyPath drives the whole three-stage pipeline through
// fakes. Asserts: each stage runs, the next stage sees the previous
// stage's outputs, the result struct reports the right paths/size.
func TestBuild_HappyPath(t *testing.T) {
	cfg, _ := happyConfig(t)
	b, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	out := filepath.Join(t.TempDir(), "rootfs.ext4")
	res, err := b.Build(context.Background(), BuildRequest{
		ImageRef: "docker://python:3.11",
		OutPath:  out,
		Tag:      "latest",
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if res.RootfsPath != out {
		t.Errorf("RootfsPath = %q, want %q", res.RootfsPath, out)
	}
	if res.StagingDir == "" {
		t.Errorf("StagingDir empty")
	}
	if res.SizeBytes <= 0 {
		t.Errorf("SizeBytes = %d", res.SizeBytes)
	}
	// Confirm the staging tree shows each stage ran.
	if _, err := os.Stat(filepath.Join(res.StagingDir, "image", "index.json")); err != nil {
		t.Errorf("skopeo stage did not produce index.json: %v", err)
	}
	if _, err := os.Stat(filepath.Join(res.StagingDir, "bundle", "rootfs", "bin", "sh")); err != nil {
		t.Errorf("umoci stage did not produce rootfs: %v", err)
	}
	if err := res.CleanupDir(); err != nil {
		t.Errorf("CleanupDir: %v", err)
	}
	if _, err := os.Stat(res.StagingDir); !os.IsNotExist(err) {
		t.Errorf("StagingDir still present after Cleanup: %v", err)
	}
}

// TestBuild_PassesMinSizeMiB confirms the size knob reaches mkfs.ext4
// when set. The fake distinguishes "no size" vs. "size given" by
// writing different content; we read it back.
func TestBuild_PassesMinSizeMiB(t *testing.T) {
	cfg, _ := happyConfig(t)
	b, _ := New(cfg)
	out := filepath.Join(t.TempDir(), "rootfs.ext4")
	res, err := b.Build(context.Background(), BuildRequest{
		ImageRef:   "docker://ubuntu:22.04",
		OutPath:    out,
		MinSizeMiB: 512,
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	defer res.CleanupDir()
	contents, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if !strings.Contains(string(contents), "fake-ext4-image\n") {
		t.Errorf("output marker missing; got %q", contents)
	}
	if strings.Contains(string(contents), "no-size") {
		t.Error("mkfs was called WITHOUT the size argument — knob not propagating")
	}
}

// TestBuild_StageFailure_SurfacesTail confirms a non-zero exit from any
// stage carries the binary's stderr in the returned error. Operators
// staring at a failed sandbox create need this; without it the only
// signal is "exit status 1".
func TestBuild_StageFailure_SurfacesTail(t *testing.T) {
	cfg, _ := happyConfig(t)
	// Replace skopeo with a fake that fails with a diagnostic.
	cfg.SkopeoBin = writeFake(t, t.TempDir(), "skopeo", `
echo "FATAL: unauthorized: authentication required" >&2
exit 1
`)
	b, _ := New(cfg)
	_, err := b.Build(context.Background(), BuildRequest{
		ImageRef: "docker://private/image:1.0",
		OutPath:  filepath.Join(t.TempDir(), "out.ext4"),
	})
	if err == nil {
		t.Fatal("expected error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "skopeo") {
		t.Errorf("error does not name the failing stage: %v", err)
	}
	if !strings.Contains(msg, "unauthorized") {
		t.Errorf("error does not surface stderr tail: %v", err)
	}
}

// TestBuild_RejectsEmptyInputs confirms the wrapper fails before
// touching any subprocess for missing fields. Defense against a buggy
// caller that builds a BuildRequest from a partial wire DTO.
func TestBuild_RejectsEmptyInputs(t *testing.T) {
	cfg, _ := happyConfig(t)
	b, _ := New(cfg)
	for _, tc := range []struct {
		name string
		req  BuildRequest
	}{
		{"no ref", BuildRequest{OutPath: "/x"}},
		{"no out", BuildRequest{ImageRef: "docker://x"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := b.Build(context.Background(), tc.req); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

// TestCappedBuffer_OciDuplicate confirms the local cappedBuffer behaves
// identically to the runtime/firecracker one. (The two are intentional
// duplicates to avoid an import cycle; this test pins their parity.)
func TestCappedBuffer_OciDuplicate(t *testing.T) {
	b := newCappedBuffer(4)
	_, _ = b.Write([]byte("ABCD"))
	_, _ = b.Write([]byte("EFGH"))
	got := b.String()
	if !strings.HasPrefix(got, "ABCD\n[... ") {
		t.Errorf("head-keep broke: %q", got)
	}
	if !strings.Contains(got, "4 more bytes dropped") {
		t.Errorf("drop counter broke: %q", got)
	}
}
