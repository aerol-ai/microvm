package containerd

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	cntr "github.com/containerd/containerd/v2/client"

	"github.com/aerol-ai/microvm/pkg/docker"
)

func TestNewBuildKitBuilderDefaults(t *testing.T) {
	b := NewBuildKitBuilder("", "", nil)
	if b.addr != DefaultBuildKitAddr {
		t.Fatalf("addr = %q, want default %q", b.addr, DefaultBuildKitAddr)
	}
	if b.buildct != "buildctl" {
		t.Fatalf("buildctl path = %q, want buildctl", b.buildct)
	}
	if b.logger == nil {
		t.Fatal("logger must default to slog.Default()")
	}
	custom := NewBuildKitBuilder("unix:///tmp/x.sock", "/opt/buildctl", nil)
	if custom.addr != "unix:///tmp/x.sock" || custom.buildct != "/opt/buildctl" {
		t.Fatalf("custom addr/path not honored: %q %q", custom.addr, custom.buildct)
	}
}

func TestBuildKitBuilderValidatesInput(t *testing.T) {
	b := NewBuildKitBuilder("", "", nil)
	if err := b.BuildImage(context.Background(), docker.BuildImageRequest{DockerfileContent: "FROM alpine"}); err == nil {
		t.Fatal("empty tag must error")
	}
	if err := b.BuildImage(context.Background(), docker.BuildImageRequest{Tag: "x:1"}); err == nil {
		t.Fatal("empty dockerfile must error")
	}
}

// writeFakeBuildctl writes an executable stand-in for buildctl that emits the
// given stderr lines and exits with code. Lets BuildImage's exec path (arg
// assembly, stderr tee, error wrapping) be exercised without a real buildkitd.
func writeFakeBuildctl(t *testing.T, stderr string, code int) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "buildctl")
	script := "#!/bin/sh\n"
	if stderr != "" {
		script += "printf '%s\\n' \"" + stderr + "\" 1>&2\n"
	}
	script += "exit " + strconv.Itoa(code) + "\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake buildctl: %v", err)
	}
	return path
}

func TestBuildKitBuilderRunsBuildctl(t *testing.T) {
	path := writeFakeBuildctl(t, "resolving dockerfile\nbuilding", 0)
	b := NewBuildKitBuilder("unix:///run/buildkit/buildkitd.sock", path, nil)
	var lines []string
	err := b.BuildImage(context.Background(), docker.BuildImageRequest{
		Tag:               "built:abc",
		DockerfileContent: "FROM alpine\nRUN true",
		OnLog:             func(l string) { lines = append(lines, l) },
	})
	if err != nil {
		t.Fatalf("BuildImage: %v", err)
	}
	if len(lines) == 0 {
		t.Fatal("OnLog should have received buildctl progress lines")
	}
}

func TestBuildKitBuilderReportsBuildctlFailure(t *testing.T) {
	path := writeFakeBuildctl(t, "frontend error: something broke", 1)
	b := NewBuildKitBuilder("", path, nil)
	err := b.BuildImage(context.Background(), docker.BuildImageRequest{
		Tag:               "built:def",
		DockerfileContent: "FROM alpine",
	})
	if err == nil {
		t.Fatal("expected error on buildctl exit 1")
	}
	if !strings.Contains(err.Error(), "something broke") {
		t.Fatalf("error should carry buildctl stderr, got: %v", err)
	}
}

func TestBuildKitBuilderExtractsContextTar(t *testing.T) {
	// A context tar should be materialized into the build dir and the build
	// should still run (fake buildctl). Prove extractTar is on the path.
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	_ = tw.WriteHeader(&tar.Header{Name: "app/main.go", Mode: 0o644, Size: 5, Typeflag: tar.TypeReg})
	_, _ = tw.Write([]byte("hello"))
	_ = tw.Close()

	path := writeFakeBuildctl(t, "", 0)
	b := NewBuildKitBuilder("", path, nil)
	err := b.BuildImage(context.Background(), docker.BuildImageRequest{
		Tag:               "built:ctx",
		DockerfileContent: "FROM scratch\nCOPY app/main.go /",
		ContextTar:        buf.Bytes(),
	})
	if err != nil {
		t.Fatalf("BuildImage with context: %v", err)
	}
}

func TestExtractTarRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	_ = tw.WriteHeader(&tar.Header{Name: "dir/", Mode: 0o755, Typeflag: tar.TypeDir})
	_ = tw.WriteHeader(&tar.Header{Name: "dir/file.txt", Mode: 0o644, Size: 3, Typeflag: tar.TypeReg})
	_, _ = tw.Write([]byte("abc"))
	_ = tw.Close()

	dir := t.TempDir()
	if err := extractTar(buf.Bytes(), dir); err != nil {
		t.Fatalf("extractTar: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "dir", "file.txt"))
	if err != nil || string(got) != "abc" {
		t.Fatalf("extracted file = %q err=%v, want abc", got, err)
	}
}

func TestExtractTarRejectsTraversal(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	_ = tw.WriteHeader(&tar.Header{Name: "../escape.txt", Mode: 0o644, Size: 1, Typeflag: tar.TypeReg})
	_, _ = tw.Write([]byte("x"))
	_ = tw.Close()

	if err := extractTar(buf.Bytes(), t.TempDir()); err == nil {
		t.Fatal("path traversal entry must be rejected")
	}
}

func TestLogLineWriter(t *testing.T) {
	var got []string
	w := logLineWriter(func(l string) { got = append(got, l) })
	n, err := w.Write([]byte("line1\nline2\n\n"))
	if err != nil || n != len("line1\nline2\n\n") {
		t.Fatalf("Write n=%d err=%v", n, err)
	}
	if len(got) != 2 || got[0] != "line1" || got[1] != "line2" {
		t.Fatalf("lines = %v, want [line1 line2]", got)
	}
}

func TestImageBuilderComposite(t *testing.T) {
	d := newTestDriver(t)
	tr := newFakeTransport()
	tr.getImageFn = func(_ context.Context, ref string) (cntr.Image, error) {
		if ref == "built:xyz" {
			return &fakeImage{name: ref}, nil
		}
		return nil, errors.New("missing")
	}
	d.SetClient(NewTestClient("aerolvm", tr))
	b := NewImageBuilder(d, NewBuildKitBuilder("", writeFakeBuildctl(t, "", 0), nil))

	// RefreshTag is a no-op on containerd.
	if err := b.RefreshTag(context.Background(), "anything"); err != nil {
		t.Fatalf("RefreshTag must be a no-op, got %v", err)
	}

	// ImageExists delegates to the driver's containerd store lookup.
	ok, err := b.ImageExists(context.Background(), "built:xyz")
	if err != nil || !ok {
		t.Fatalf("ImageExists(built:xyz) = %v,%v; want true,nil", ok, err)
	}
	if ok, _ := b.ImageExists(context.Background(), "absent:1"); ok {
		t.Fatal("ImageExists(absent) should be false")
	}

	// PushImage delegates to the pusher, whose validation rejects an empty req.
	if _, err := b.PushImage(context.Background(), docker.PushImageRequest{}); err == nil {
		t.Fatal("PushImage with empty request must error via the pusher")
	}

	// BuildImage delegates to the buildkit builder (fake buildctl exit 0).
	if err := b.BuildImage(context.Background(), docker.BuildImageRequest{Tag: "built:new", DockerfileContent: "FROM alpine"}); err != nil {
		t.Fatalf("BuildImage delegation: %v", err)
	}

	// RemoveImage delegates to the driver's image-delete seam.
	orig := removeImageFn
	t.Cleanup(func() { removeImageFn = orig })
	var removed string
	removeImageFn = func(_ context.Context, _ *Client, ref string) error {
		removed = ref
		return nil
	}
	if err := b.RemoveImage(context.Background(), "built:xyz"); err != nil {
		t.Fatalf("RemoveImage delegation: %v", err)
	}
	if removed != "built:xyz" {
		t.Fatalf("RemoveImage delegated ref = %q, want built:xyz", removed)
	}
}

func TestDriverImageExists(t *testing.T) {
	d := newTestDriver(t)
	tr := newFakeTransport()
	tr.getImageFn = func(_ context.Context, ref string) (cntr.Image, error) {
		// Only "snap:latest" resolves — proves tagless resolution via :latest.
		if ref == "snap:latest" {
			return &fakeImage{name: ref}, nil
		}
		return nil, errors.New("missing")
	}
	d.SetClient(NewTestClient("aerolvm", tr))

	if ok, _ := d.ImageExists(context.Background(), "snap:latest"); !ok {
		t.Fatal("exact ref should resolve")
	}
	if ok, _ := d.ImageExists(context.Background(), "snap"); !ok {
		t.Fatal("tagless ref should resolve via :latest")
	}
	if ok, _ := d.ImageExists(context.Background(), "nope:1"); ok {
		t.Fatal("absent ref should be false")
	}
	if ok, _ := d.ImageExists(context.Background(), "  "); ok {
		t.Fatal("blank ref should be false")
	}
}
