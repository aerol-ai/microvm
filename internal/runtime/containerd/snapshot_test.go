package containerd

import (
	"context"
	"os"
	"strings"
	"testing"

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
	container cntr.Container
	desc      ocispec.Descriptor
	created   images.Image
	createErr error
	getImg    images.Image
	getErr    error
}

func (f *fakeSnapshotBackend) loadContainer(context.Context, *Client, string) (cntr.Container, error) {
	if f.container == nil {
		return nil, errdefs.ErrNotFound
	}
	return f.container, nil
}
func (f *fakeSnapshotBackend) createDiff(context.Context, string, string, cntr.Container) (ocispec.Descriptor, error) {
	return f.desc, nil
}
func (f *fakeSnapshotBackend) createImage(_ context.Context, img images.Image) (images.Image, error) {
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

func TestCommitContainerSnapshotLiveFakeBackend(t *testing.T) {
	d := newTestDriver(t)
	dgst := digest.Digest("sha256:" + strings.Repeat("c", 64))
	backend := &fakeSnapshotBackend{
		container: &fakeContainer{id: "sb-1", task: &fakeTask{status: cntr.Running}},
		desc:      ocispec.Descriptor{Digest: dgst},
		created:   images.Image{Name: "snap:v1", Target: ocispec.Descriptor{Digest: dgst}},
	}
	testSnapshotBackend = backend
	t.Cleanup(func() { testSnapshotBackend = nil })

	got, err := d.commitContainerSnapshotLive(context.Background(), d.client, "sb-1", "snap:v1")
	if err != nil || got != string(dgst) {
		t.Fatalf("got=%q err=%v", got, err)
	}
}

func TestCommitContainerSnapshotAlreadyExists(t *testing.T) {
	d := newTestDriver(t)
	dgst := digest.Digest("sha256:" + strings.Repeat("d", 64))
	backend := &fakeSnapshotBackend{
		container: &fakeContainer{id: "sb-1", task: &fakeTask{status: cntr.Running}},
		desc:      ocispec.Descriptor{Digest: dgst},
		createErr: errdefs.ErrAlreadyExists,
		getImg:    images.Image{Target: ocispec.Descriptor{Digest: dgst}},
	}
	testSnapshotBackend = backend
	t.Cleanup(func() { testSnapshotBackend = nil })

	got, err := d.commitContainerSnapshotLive(context.Background(), d.client, "sb-1", "snap:v1")
	if err != nil || got != string(dgst) {
		t.Fatalf("got=%q err=%v", got, err)
	}
}

func TestCommitContainerSnapshotStoppedTask(t *testing.T) {
	d := newTestDriver(t)
	dgst := digest.Digest("sha256:" + strings.Repeat("e", 64))
	backend := &fakeSnapshotBackend{
		container: &fakeContainer{id: "sb-1", task: &fakeTask{status: cntr.Stopped}},
		desc:      ocispec.Descriptor{Digest: dgst},
		created:   images.Image{Target: ocispec.Descriptor{Digest: dgst}},
	}
	testSnapshotBackend = backend
	t.Cleanup(func() { testSnapshotBackend = nil })

	got, err := d.commitContainerSnapshotLive(context.Background(), d.client, "sb-1", "snap:v1")
	if err != nil || got != string(dgst) {
		t.Fatalf("got=%q err=%v", got, err)
	}
}
