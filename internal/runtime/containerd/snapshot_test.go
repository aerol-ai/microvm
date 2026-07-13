package containerd

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	cntr "github.com/containerd/containerd"
	"github.com/containerd/containerd/errdefs"
	"github.com/containerd/containerd/images"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/aerol-ai/microvm/pkg/models"
)

func TestSplitSnapshotImageRef(t *testing.T) {
	repo, tag, err := splitSnapshotImageRef("ghcr.io/org/app:v1")
	if err != nil || repo != "ghcr.io/org/app" || tag != "v1" {
		t.Fatalf("got %q %q err=%v", repo, tag, err)
	}
	if _, _, err := splitSnapshotImageRef("bad@sha256:abc"); err == nil {
		t.Fatal("digest should be rejected")
	}
}

func TestFormatSnapshotImageRefAddsLatest(t *testing.T) {
	got, err := formatSnapshotImageRef("local/snap")
	if err != nil || got != "local/snap:latest" {
		t.Fatalf("got %q err=%v", got, err)
	}
}

func TestCreateSnapshotValidation(t *testing.T) {
	d := New(Config{}, nil, nil)
	if _, err := d.CreateSnapshot(context.Background(), "", "snap:v1"); err == nil {
		t.Fatal("want container ref error")
	}
	if _, err := d.CreateSnapshot(context.Background(), "sb-1", ""); err == nil {
		t.Fatal("want image ref error")
	}
	d = newTestDriver(t)
	tr := newFakeTransport()
	tr.containers["sb-1"] = &fakeContainer{id: "sb-1", task: &fakeTask{status: cntr.Running}}
	d.SetClient(NewTestClient("aerolvm", tr))
	_, err := d.CreateSnapshot(context.Background(), "sb-1", "snap:v1")
	if err == nil || !strings.Contains(err.Error(), "live containerd") {
		t.Fatalf("err=%v", err)
	}
}

func TestCreateSnapshotFakeCommitHook(t *testing.T) {
	d := newTestDriver(t)
	d.SetClient(NewTestClient("aerolvm", newFakeTransport()))
	orig := snapshotCommitFn
	snapshotCommitFn = func(_ *Driver, _ context.Context, _ *Client, _, imageRef string) (string, error) {
		return "sha256:deadbeef", nil
	}
	t.Cleanup(func() { snapshotCommitFn = orig })

	got, err := d.CreateSnapshot(context.Background(), "sb-1", "snap:v1")
	if err != nil || got != "sha256:deadbeef" {
		t.Fatalf("got=%q err=%v", got, err)
	}
}

func TestContainerdRuntimeNameRunsc(t *testing.T) {
	if got := containerdRuntimeName("runsc"); got != runscShimName {
		t.Fatalf("got %q", got)
	}
	if got := containerdRuntimeName(models.RuntimeDocker); got != models.RuntimeDocker {
		t.Fatalf("got %q", got)
	}
}

func TestEnsureRunscConfigWritesHostUDS(t *testing.T) {
	tmp := t.TempDir()
	d := New(Config{RunDir: tmp}, nil, nil)
	path, err := d.ensureRunscConfig()
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), `host-uds = "open"`) {
		t.Fatalf("config=%q", body)
	}
	opt, err := d.runscRuntimeOpts()
	if err != nil {
		t.Fatal(err)
	}
	ro, ok := opt.(*runscShimOptions)
	if !ok || ro.ConfigPath != path {
		t.Fatalf("opts=%T %+v", opt, opt)
	}
}

func TestRawSnapshotBackendWithoutLiveClient(t *testing.T) {
	d := newTestDriver(t)
	tr := newFakeTransport()
	tr.containers["sb-1"] = &fakeContainer{id: "sb-1", task: &fakeTask{status: cntr.Running}}
	d.SetClient(NewTestClient("aerolvm", tr))
	b := &rawSnapshotBackend{d: d, client: d.client}
	c, err := b.loadContainer(context.Background(), d.client, "sb-1")
	if err != nil || c.ID() != "sb-1" {
		t.Fatalf("c=%v err=%v", c, err)
	}
	if _, err := b.createDiff(context.Background(), "key", "overlayfs", c); err == nil {
		t.Fatal("want live error")
	}
	if _, err := b.createImage(context.Background(), images.Image{Name: "x"}); err == nil {
		t.Fatal("want live error")
	}
	if _, err := b.getImage(context.Background(), "x"); err == nil {
		t.Fatal("want live error")
	}
}

func TestNilClientContentAccessors(t *testing.T) {
	var c *Client
	if c.ContentStore() != nil || c.contentProvider() != nil {
		t.Fatal("nil client should return nil stores")
	}
	c = &Client{}
	if c.ContentStore() != nil || c.contentProvider() != nil {
		t.Fatal("nil transport should return nil stores")
	}
}

type fakeSnapshotBackend struct {
	container    cntr.Container
	diffDesc     ocispec.Descriptor
	baseManifest ocispec.Manifest
	baseConfig   ocispec.Image
	diffIDVal    digest.Digest
	blobLabels   map[string]map[string]string // blob digest -> gc labels
	blobTypes    map[string]string            // blob digest -> media type
	createErr    error
	created      images.Image
	createdArg   images.Image
	getImg       images.Image
	getErr       error
}

func (f *fakeSnapshotBackend) loadContainer(context.Context, *Client, string) (cntr.Container, error) {
	if f.container == nil {
		return nil, errdefs.ErrNotFound
	}
	return f.container, nil
}
func (f *fakeSnapshotBackend) createDiff(context.Context, string, string, cntr.Container) (ocispec.Descriptor, error) {
	return f.diffDesc, nil
}
func (f *fakeSnapshotBackend) baseManifestAndConfig(context.Context, ocispec.Descriptor) (ocispec.Manifest, ocispec.Image, error) {
	return f.baseManifest, f.baseConfig, nil
}
func (f *fakeSnapshotBackend) diffID(context.Context, ocispec.Descriptor) (digest.Digest, error) {
	return f.diffIDVal, nil
}
func (f *fakeSnapshotBackend) writeBlob(_ context.Context, mediaType string, data []byte, labels map[string]string) (ocispec.Descriptor, error) {
	if f.blobLabels == nil {
		f.blobLabels = map[string]map[string]string{}
		f.blobTypes = map[string]string{}
	}
	desc := ocispec.Descriptor{MediaType: mediaType, Digest: digest.FromBytes(data), Size: int64(len(data))}
	f.blobLabels[desc.Digest.String()] = labels
	f.blobTypes[desc.Digest.String()] = mediaType
	return desc, nil
}
func (f *fakeSnapshotBackend) createImage(_ context.Context, img images.Image) (images.Image, error) {
	f.createdArg = img
	if f.createErr != nil {
		return images.Image{}, f.createErr
	}
	if f.created.Name != "" {
		return f.created, nil
	}
	return img, nil
}
func (f *fakeSnapshotBackend) getImage(context.Context, string) (images.Image, error) {
	if f.getErr != nil {
		return images.Image{}, f.getErr
	}
	return f.getImg, nil
}

// baseFixture returns a backend seeded with a base image (one config + one
// layer) plus the new diff, so the commit can assemble a real manifest.
func baseFixture(task *fakeTask) *fakeSnapshotBackend {
	layer := ocispec.Descriptor{MediaType: ocispec.MediaTypeImageLayerGzip, Digest: digest.Digest("sha256:" + strings.Repeat("1", 64))}
	return &fakeSnapshotBackend{
		container: &fakeContainer{id: "sb-1", task: task},
		diffDesc:  ocispec.Descriptor{MediaType: ocispec.MediaTypeImageLayerGzip, Digest: digest.Digest("sha256:" + strings.Repeat("2", 64))},
		diffIDVal: digest.Digest("sha256:" + strings.Repeat("3", 64)),
		baseManifest: ocispec.Manifest{
			MediaType: ocispec.MediaTypeImageManifest,
			Config:    ocispec.Descriptor{MediaType: ocispec.MediaTypeImageConfig, Digest: digest.Digest("sha256:" + strings.Repeat("4", 64))},
			Layers:    []ocispec.Descriptor{layer},
		},
		baseConfig: ocispec.Image{RootFS: ocispec.RootFS{Type: "layers", DiffIDs: []digest.Digest{digest.Digest("sha256:" + strings.Repeat("5", 64))}}},
	}
}

func TestCommitContainerSnapshotLiveFakeBackend(t *testing.T) {
	d := newTestDriver(t)
	backend := baseFixture(&fakeTask{status: cntr.Running})
	testSnapshotBackend = backend
	t.Cleanup(func() { testSnapshotBackend = nil })

	got, err := d.commitContainerSnapshotLive(context.Background(), d.client, "sb-1", "snap:v1")
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	// Returned digest must be the assembled MANIFEST, and createImage must have
	// been handed a manifest target (not the bare diff layer).
	if got == "" || got != string(backend.createdArg.Target.Digest) {
		t.Fatalf("returned digest %q != created image target %q", got, backend.createdArg.Target.Digest)
	}
	if backend.createdArg.Target.MediaType != ocispec.MediaTypeImageManifest {
		t.Fatalf("image target media type = %q, want manifest", backend.createdArg.Target.MediaType)
	}
	// The manifest blob must carry gc.ref labels for the config + every layer.
	labels := backend.blobLabels[got]
	if labels["containerd.io/gc.ref.content.config"] == "" {
		t.Fatalf("manifest missing gc.ref config label: %v", labels)
	}
	if labels["containerd.io/gc.ref.content.l.0"] == "" || labels["containerd.io/gc.ref.content.l.1"] == "" {
		t.Fatalf("manifest missing gc.ref layer labels (base + diff): %v", labels)
	}
}

func TestCommitContainerSnapshotAlreadyExists(t *testing.T) {
	d := newTestDriver(t)
	dgst := digest.Digest("sha256:" + strings.Repeat("d", 64))
	backend := baseFixture(&fakeTask{status: cntr.Running})
	backend.createErr = errdefs.ErrAlreadyExists
	backend.getImg = images.Image{Target: ocispec.Descriptor{Digest: dgst}}
	testSnapshotBackend = backend
	t.Cleanup(func() { testSnapshotBackend = nil })

	got, err := d.commitContainerSnapshotLive(context.Background(), d.client, "sb-1", "snap:v1")
	if err != nil || got != string(dgst) {
		t.Fatalf("got=%q err=%v", got, err)
	}
}

func TestCommitContainerSnapshotStoppedTask(t *testing.T) {
	d := newTestDriver(t)
	backend := baseFixture(&fakeTask{status: cntr.Stopped})
	testSnapshotBackend = backend
	t.Cleanup(func() { testSnapshotBackend = nil })

	got, err := d.commitContainerSnapshotLive(context.Background(), d.client, "sb-1", "snap:v1")
	if err != nil || got == "" {
		t.Fatalf("got=%q err=%v", got, err)
	}
}

func TestAssembleCommittedImageExtendsConfigAndManifest(t *testing.T) {
	backend := baseFixture(nil)
	img, err := assembleCommittedImage(context.Background(), backend, backend.baseManifest.Config, backend.diffDesc, "snap:v1", time.Unix(0, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	if img.Name != "snap:v1" || img.Target.MediaType != ocispec.MediaTypeImageManifest {
		t.Fatalf("assembled image wrong: %+v", img.Target)
	}
	if img.Labels["containerd.io/gc.root"] == "" {
		t.Fatal("assembled image missing gc.root label")
	}
	// Two blobs must have been written: the new config and the manifest.
	if len(backend.blobTypes) != 2 {
		t.Fatalf("expected config+manifest blobs, wrote %d", len(backend.blobTypes))
	}
}
