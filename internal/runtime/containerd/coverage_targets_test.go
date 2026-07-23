package containerd

// coverage_targets_test.go exercises the functions that were at 0%
// before this file was added:
//   - rawSnapshotBackend.unpack / createDiff / createImage / getImage /
//     baseManifestAndConfig / diffID / writeBlob  (all return an
//     "requires live containerd" error when Raw() is nil)
//   - recreateResumeReadySocket (all nil/zero-value spec branches)
//   - livePush (the nil-driver error path)

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	cntr "github.com/containerd/containerd"
	"github.com/containerd/containerd/errdefs"
	"github.com/containerd/containerd/images"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	runtimespecs "github.com/opencontainers/runtime-spec/specs-go"

	dockerpkg "github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
)

// -------------------------------------------------------------------
// rawSnapshotBackend nil-raw guard paths (0% before this file)
// -------------------------------------------------------------------

// newNilRawBackend builds a rawSnapshotBackend whose client has no live
// Raw() — triggering the "requires live containerd" guard in methods that
// call Raw().
func newNilRawBackend(t *testing.T) *rawSnapshotBackend {
	t.Helper()
	d := newTestDriver(t)
	// NewTestClient wraps a fakeTransport whose Raw() returns nil.
	client := NewTestClient("aerolvm", newFakeTransport())
	d.SetClient(client)
	return &rawSnapshotBackend{d: d, client: client}
}

func TestRawSnapshotBackend_CreateDiff_NilRaw(t *testing.T) {
	b := newNilRawBackend(t)
	_, err := b.createDiff(context.Background(), "snap-key", "overlayfs", nil)
	if err == nil || !strings.Contains(err.Error(), "live containerd") {
		t.Fatalf("createDiff nil-raw: err=%v", err)
	}
}

func TestRawSnapshotBackend_CreateImage_NilRaw(t *testing.T) {
	b := newNilRawBackend(t)
	_, err := b.createImage(context.Background(), images.Image{Name: "test:v1"})
	if err == nil || !strings.Contains(err.Error(), "live containerd") {
		t.Fatalf("createImage nil-raw: err=%v", err)
	}
}

func TestRawSnapshotBackend_GetImage_NilRaw(t *testing.T) {
	b := newNilRawBackend(t)
	_, err := b.getImage(context.Background(), "test:v1")
	if err == nil || !strings.Contains(err.Error(), "live containerd") {
		t.Fatalf("getImage nil-raw: err=%v", err)
	}
}

func TestRawSnapshotBackend_BaseManifestAndConfig_NilRaw(t *testing.T) {
	b := newNilRawBackend(t)
	_, _, err := b.baseManifestAndConfig(context.Background(), ocispec.Descriptor{})
	if err == nil || !strings.Contains(err.Error(), "live containerd") {
		t.Fatalf("baseManifestAndConfig nil-raw: err=%v", err)
	}
}

func TestRawSnapshotBackend_DiffID_NilRaw(t *testing.T) {
	b := newNilRawBackend(t)
	_, err := b.diffID(context.Background(), ocispec.Descriptor{})
	if err == nil || !strings.Contains(err.Error(), "live containerd") {
		t.Fatalf("diffID nil-raw: err=%v", err)
	}
}

func TestRawSnapshotBackend_WriteBlob_NilRaw(t *testing.T) {
	b := newNilRawBackend(t)
	_, err := b.writeBlob(context.Background(), "application/octet-stream", []byte("data"), nil)
	if err == nil || !strings.Contains(err.Error(), "live containerd") {
		t.Fatalf("writeBlob nil-raw: err=%v", err)
	}
}

// unpack goes via GetImage, not via Raw(); error comes from the image missing.
func TestRawSnapshotBackend_Unpack_MissingImage(t *testing.T) {
	d := newTestDriver(t)
	tr := newFakeTransport()
	tr.getImageFn = func(_ context.Context, _ string) (cntr.Image, error) {
		return nil, errdefs.ErrNotFound
	}
	client := NewTestClient("aerolvm", tr)
	d.SetClient(client)
	b := &rawSnapshotBackend{d: d, client: client}

	err := b.unpack(context.Background(), "nonexistent:latest", "overlayfs")
	if err == nil {
		t.Fatal("unpack should fail when image is not in fake transport")
	}
}

// unpack succeeds when the image exists (fakeImage.Unpack is a no-op).
func TestRawSnapshotBackend_Unpack_ImageExists(t *testing.T) {
	d := newTestDriver(t)
	tr := newFakeTransport()
	// fakeTransport returns its .image for every GetImage call by default.
	client := NewTestClient("aerolvm", tr)
	d.SetClient(client)
	b := &rawSnapshotBackend{d: d, client: client}

	err := b.unpack(context.Background(), "alpine:3.20", "overlayfs")
	if err != nil {
		t.Fatalf("unpack with existing image: %v", err)
	}
}

// -------------------------------------------------------------------
// recreateResumeReadySocket (0% before this file)
// -------------------------------------------------------------------

func TestRecreateResumeReadySocket_NilSpec(t *testing.T) {
	d := newTestDriver(t)
	if rl := d.recreateResumeReadySocket(nil); rl != nil {
		t.Fatal("nil spec should return nil listener")
	}
}

func TestRecreateResumeReadySocket_NilProcess(t *testing.T) {
	d := newTestDriver(t)
	spec := &runtimespecs.Spec{Process: nil}
	if rl := d.recreateResumeReadySocket(spec); rl != nil {
		t.Fatal("nil Process should return nil listener")
	}
}

func TestRecreateResumeReadySocket_NoReadyMount(t *testing.T) {
	d := newTestDriver(t)
	spec := &runtimespecs.Spec{
		Process: &runtimespecs.Process{Env: []string{"SB_TOOLBOX_TOKEN=tok"}},
		Mounts:  nil,
	}
	if rl := d.recreateResumeReadySocket(spec); rl != nil {
		t.Fatal("spec with no ready mount should return nil listener")
	}
}

func TestRecreateResumeReadySocket_MissingToken(t *testing.T) {
	d := newTestDriver(t)
	d.cfg.ReadyDir = shortReadyDir(t)
	spec := &runtimespecs.Spec{
		Process: &runtimespecs.Process{Env: nil},
		Mounts: []runtimespecs.Mount{
			{Destination: dockerpkg.GuestReadySocketPath, Source: filepath.Join(d.cfg.ReadyDir, "sb-1.nonce123.sock")},
		},
	}
	if rl := d.recreateResumeReadySocket(spec); rl != nil {
		t.Fatal("spec without SB_TOOLBOX_TOKEN should return nil listener")
	}
}

func TestRecreateResumeReadySocket_BadSourceFormat(t *testing.T) {
	d := newTestDriver(t)
	d.cfg.ReadyDir = shortReadyDir(t)
	spec := &runtimespecs.Spec{
		Process: &runtimespecs.Process{Env: []string{"SB_TOOLBOX_TOKEN=tok"}},
		Mounts: []runtimespecs.Mount{
			// basename has no dot → nonce extraction returns "" → returns nil
			{Destination: dockerpkg.GuestReadySocketPath, Source: filepath.Join(d.cfg.ReadyDir, "nodot.sock")},
		},
	}
	if rl := d.recreateResumeReadySocket(spec); rl != nil {
		t.Fatal("bad source format (no nonce dot separator) should return nil")
	}
}

func TestRecreateResumeReadySocket_HappyPath(t *testing.T) {
	d := newTestDriver(t)
	d.cfg.ReadyDir = shortReadyDir(t)
	if err := os.MkdirAll(d.cfg.ReadyDir, 0o700); err != nil {
		t.Fatal(err)
	}
	nonce := "abc123"
	sockName := "sb-resume." + nonce + ".sock"
	spec := &runtimespecs.Spec{
		Process: &runtimespecs.Process{Env: []string{"SB_TOOLBOX_TOKEN=tok"}},
		Mounts: []runtimespecs.Mount{
			{Destination: dockerpkg.GuestReadySocketPath, Source: filepath.Join(d.cfg.ReadyDir, sockName)},
		},
	}
	rl := d.recreateResumeReadySocket(spec)
	if rl == nil {
		t.Fatal("expected a non-nil ReadyListener for valid spec")
	}
	_ = rl.Close()
}

// -------------------------------------------------------------------
// livePush error paths (0% before this file)
// -------------------------------------------------------------------

func TestLivePush_NilDriver(t *testing.T) {
	p := &RegistryPusher{driver: nil}
	_, err := p.livePush(context.Background(), "src:tag", "dst:tag", models.RegistryAuth{})
	if err == nil || !strings.Contains(err.Error(), "driver is nil") {
		t.Fatalf("livePush with nil driver: err=%v", err)
	}
}

// livePush with a wired driver but no live containerd hits the ensureClient error.
func TestLivePush_NoClient(t *testing.T) {
	d := newTestDriver(t)
	d.SetClient(nil)
	p := &RegistryPusher{driver: d}
	_, err := p.livePush(context.Background(), "src:tag", "dst:tag", models.RegistryAuth{Username: "u", Password: "p"})
	if err == nil {
		t.Fatal("livePush with no client should error")
	}
}

// -------------------------------------------------------------------
// resolveSnapshotBackend coverage
// -------------------------------------------------------------------

func TestResolveSnapshotBackend_NilClient(t *testing.T) {
	d := newTestDriver(t)
	if b := resolveSnapshotBackend(d, nil); b != nil {
		t.Fatalf("nil client should yield nil backend, got %T", b)
	}
}

func TestResolveSnapshotBackend_TestSeam(t *testing.T) {
	d := newTestDriver(t)
	seam := newNilRawBackend(t)
	orig := testSnapshotBackend
	testSnapshotBackend = seam
	defer func() { testSnapshotBackend = orig }()

	b := resolveSnapshotBackend(d, d.client)
	if b != seam {
		t.Fatal("resolveSnapshotBackend should return testSnapshotBackend when set")
	}
}

// -------------------------------------------------------------------
// rawSnapshotBackend.loadContainer
// -------------------------------------------------------------------

func TestRawSnapshotBackend_LoadContainer_NotFound(t *testing.T) {
	b := newNilRawBackend(t)
	_, err := b.loadContainer(context.Background(), b.client, "nonexistent-sb")
	if err == nil {
		t.Fatal("loadContainer should fail for a non-existent sandbox")
	}
}

func TestRawSnapshotBackend_LoadContainer_Found(t *testing.T) {
	d := newTestDriver(t)
	tr := newFakeTransport()
	tr.containers["sb-real"] = &fakeContainer{id: "sb-real"}
	client := NewTestClient("aerolvm", tr)
	d.SetClient(client)
	b := &rawSnapshotBackend{d: d, client: client}

	c, err := b.loadContainer(context.Background(), client, "sb-real")
	if err != nil || c == nil || c.ID() != "sb-real" {
		t.Fatalf("loadContainer found: c=%v err=%v", c, err)
	}
}
