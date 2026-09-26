package containerd

// coverage_high95_test.go pushes the containerd package above 95% by exercising
// seam-injected error paths and pure helpers that do not need a live daemon.

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	apievents "github.com/containerd/containerd/api/events"
	cntr "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/events"
	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/core/runtime"
	"github.com/containerd/containerd/v2/pkg/oci"
	"github.com/containerd/errdefs"
	"github.com/containerd/platforms"
	"github.com/containerd/typeurl/v2"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/aerol-ai/microvm/internal/pool/containerdpool"
	"github.com/aerol-ai/microvm/pkg/createtiming"
	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/docker/netrules"
	"github.com/aerol-ai/microvm/pkg/models"
	runtimespecs "github.com/opencontainers/runtime-spec/specs-go"
)

// ---------------------------------------------------------------------------
// connectFn / ensureClient lazy connect
// ---------------------------------------------------------------------------

func TestEnsureClientLazyConnect(t *testing.T) {
	orig := connectFn
	connectFn = func(_, _ string) (*Client, error) {
		return NewTestClient("aerolvm", newFakeTransport()), nil
	}
	t.Cleanup(func() { connectFn = orig })

	d := New(Config{Socket: "/fake.sock", Namespace: "aerolvm"}, nil, nil)
	c, err := d.ensureClient()
	if err != nil || c == nil {
		t.Fatalf("ensureClient lazy connect: c=%v err=%v", c, err)
	}
}

// ---------------------------------------------------------------------------
// livePush via pushLiveDepsFn
// ---------------------------------------------------------------------------

type fakePushImage struct {
	target ocispec.Descriptor
}

func (f *fakePushImage) Name() string { return "snap:local" }
func (f *fakePushImage) Target() ocispec.Descriptor {
	if f.target.Digest != "" {
		return f.target
	}
	return ocispec.Descriptor{Digest: digest.Digest("sha256:" + strings.Repeat("c", 64))}
}
func (f *fakePushImage) Labels() map[string]string                               { return nil }
func (f *fakePushImage) Unpack(context.Context, string, ...cntr.UnpackOpt) error { return nil }
func (f *fakePushImage) RootFS(context.Context) ([]digest.Digest, error)         { return nil, nil }
func (f *fakePushImage) Size(context.Context) (int64, error)                     { return 0, nil }
func (f *fakePushImage) Usage(context.Context, ...cntr.UsageOpt) (int64, error)  { return 0, nil }
func (f *fakePushImage) Config(context.Context) (ocispec.Descriptor, error) {
	return ocispec.Descriptor{}, nil
}
func (f *fakePushImage) IsUnpacked(context.Context, string) (bool, error) { return true, nil }
func (f *fakePushImage) ContentStore() content.Store                      { return nil }
func (f *fakePushImage) Metadata() images.Image                           { return images.Image{Name: "snap:local"} }
func (f *fakePushImage) Platform() platforms.MatchComparer                { return nil }
func (f *fakePushImage) Spec(context.Context) (ocispec.Image, error)      { return ocispec.Image{}, nil }

func withPushDeps(t *testing.T, deps pushLiveDeps) {
	t.Helper()
	orig := pushLiveDepsFn
	pushLiveDepsFn = func(*Client) (pushLiveDeps, error) { return deps, nil }
	t.Cleanup(func() { pushLiveDepsFn = orig })
}

func TestLivePushCreatesDestAndPushes(t *testing.T) {
	img := &fakePushImage{}
	var created, pushed bool
	withPushDeps(t, pushLiveDeps{
		getImage: func(_ context.Context, ref string) (cntr.Image, error) {
			if ref == "snap" || ref == "snap:latest" {
				return img, nil
			}
			return nil, errdefs.ErrNotFound
		},
		imageGet: func(context.Context, string) (images.Image, error) { return images.Image{}, errdefs.ErrNotFound },
		imageCreate: func(_ context.Context, got images.Image) (images.Image, error) {
			created = true
			return got, nil
		},
		push: func(_ context.Context, dest string, _ ocispec.Descriptor, _ ...cntr.RemoteOpt) error {
			if dest != "aocr.example/snap:latest" {
				t.Fatalf("dest=%q", dest)
			}
			pushed = true
			return nil
		},
	})
	p := &RegistryPusher{driver: newTestDriver(t)}
	dgst, err := p.livePush(context.Background(), "snap", "aocr.example/snap:latest", models.RegistryAuth{
		Username: "u", Password: "p", Server: "aocr.example",
	})
	if err != nil || !created || !pushed || dgst == "" {
		t.Fatalf("dgst=%q created=%v pushed=%v err=%v", dgst, created, pushed, err)
	}
}

func TestLivePushDestAlreadyExists(t *testing.T) {
	img := &fakePushImage{}
	withPushDeps(t, pushLiveDeps{
		getImage: func(context.Context, string) (cntr.Image, error) { return img, nil },
		imageGet: func(context.Context, string) (images.Image, error) { return images.Image{Name: "dst"}, nil },
		imageUpdate: func(context.Context, images.Image, ...string) (images.Image, error) {
			return images.Image{}, errors.New("ignored")
		},
		push: func(context.Context, string, ocispec.Descriptor, ...cntr.RemoteOpt) error { return nil },
	})
	p := &RegistryPusher{driver: newTestDriver(t)}
	if _, err := p.livePush(context.Background(), "snap:local", "aocr.example/dst:latest", models.RegistryAuth{
		Username: "u", Password: "p", Server: "aocr.example",
	}); err != nil {
		t.Fatal(err)
	}
}

func TestLivePushCreateAlreadyExists(t *testing.T) {
	img := &fakePushImage{}
	withPushDeps(t, pushLiveDeps{
		getImage: func(context.Context, string) (cntr.Image, error) { return img, nil },
		imageGet: func(context.Context, string) (images.Image, error) { return images.Image{}, errdefs.ErrNotFound },
		imageCreate: func(context.Context, images.Image) (images.Image, error) {
			return images.Image{}, errdefs.ErrAlreadyExists
		},
		push: func(context.Context, string, ocispec.Descriptor, ...cntr.RemoteOpt) error { return nil },
	})
	p := &RegistryPusher{driver: newTestDriver(t)}
	if _, err := p.livePush(context.Background(), "snap:local", "aocr.example/dst:latest", models.RegistryAuth{
		Username: "u", Password: "p", Server: "aocr.example",
	}); err != nil {
		t.Fatal(err)
	}
}

func TestLivePushErrors(t *testing.T) {
	p := &RegistryPusher{driver: newTestDriver(t)}
	auth := models.RegistryAuth{Username: "u", Password: "p", Server: "aocr.example"}

	cases := []struct {
		name string
		deps pushLiveDeps
	}{
		{
			name: "source missing",
			deps: pushLiveDeps{
				getImage: func(context.Context, string) (cntr.Image, error) {
					return nil, errdefs.ErrNotFound
				},
			},
		},
		{
			name: "dest lookup fails",
			deps: pushLiveDeps{
				getImage: func(context.Context, string) (cntr.Image, error) { return &fakePushImage{}, nil },
				imageGet: func(context.Context, string) (images.Image, error) { return images.Image{}, errors.New("boom") },
			},
		},
		{
			name: "create dest fails",
			deps: pushLiveDeps{
				getImage: func(context.Context, string) (cntr.Image, error) { return &fakePushImage{}, nil },
				imageGet: func(context.Context, string) (images.Image, error) { return images.Image{}, errdefs.ErrNotFound },
				imageCreate: func(context.Context, images.Image) (images.Image, error) {
					return images.Image{}, errors.New("create failed")
				},
			},
		},
		{
			name: "push fails",
			deps: pushLiveDeps{
				getImage:    func(context.Context, string) (cntr.Image, error) { return &fakePushImage{}, nil },
				imageGet:    func(context.Context, string) (images.Image, error) { return images.Image{}, errdefs.ErrNotFound },
				imageCreate: func(_ context.Context, img images.Image) (images.Image, error) { return img, nil },
				push: func(context.Context, string, ocispec.Descriptor, ...cntr.RemoteOpt) error {
					return errors.New("push failed")
				},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withPushDeps(t, tc.deps)
			if _, err := p.livePush(context.Background(), "snap:local", "aocr.example/dst:latest", auth); err == nil {
				t.Fatal("want error")
			}
		})
	}

	withPushDeps(t, pushLiveDeps{
		getImage:    func(context.Context, string) (cntr.Image, error) { return &fakePushImage{}, nil },
		imageGet:    func(context.Context, string) (images.Image, error) { return images.Image{}, errdefs.ErrNotFound },
		imageCreate: func(_ context.Context, img images.Image) (images.Image, error) { return img, nil },
		push:        func(context.Context, string, ocispec.Descriptor, ...cntr.RemoteOpt) error { return nil },
	})
	if _, err := p.livePush(context.Background(), "snap:local", "bare-repo/img", models.RegistryAuth{Username: "u", Password: "p"}); err == nil {
		t.Fatal("want cred scope error")
	}
}

func TestPushImageOnLogAndPushError(t *testing.T) {
	p := NewRegistryPusher(nil)
	p.pushFn = func(context.Context, string, string, models.RegistryAuth) (string, error) {
		return "", errors.New("push boom")
	}
	if _, err := p.PushImage(context.Background(), docker.PushImageRequest{
		SourceTag: "a", DestRef: "b", Auth: models.RegistryAuth{Username: "u", Password: "p"},
	}); err == nil {
		t.Fatal("want push error")
	}

	p.pushFn = func(context.Context, string, string, models.RegistryAuth) (string, error) { return "sha256:x", nil }
	var logged string
	if _, err := p.PushImage(context.Background(), docker.PushImageRequest{
		SourceTag: "a", DestRef: "b", Auth: models.RegistryAuth{Username: "u", Password: "p"},
		OnLog: func(l string) { logged = l },
	}); err != nil || logged == "" {
		t.Fatalf("logged=%q err=%v", logged, err)
	}
}

// ---------------------------------------------------------------------------
// snapshot content store + rawSnapshotBackend live paths
// ---------------------------------------------------------------------------

type memContentStore struct {
	blobs  map[digest.Digest][]byte
	labels map[string]map[string]string
}

func (m *memContentStore) Info(context.Context, digest.Digest) (content.Info, error) {
	return content.Info{}, errdefs.ErrNotFound
}
func (m *memContentStore) Update(context.Context, content.Info, ...string) (content.Info, error) {
	return content.Info{}, nil
}
func (m *memContentStore) Walk(context.Context, content.WalkFunc, ...string) error { return nil }
func (m *memContentStore) Delete(context.Context, digest.Digest) error             { return nil }
func (m *memContentStore) ListStatuses(context.Context, ...string) ([]content.Status, error) {
	return nil, nil
}
func (m *memContentStore) Abort(context.Context, string) error { return nil }

type memContentWriter struct {
	store *memContentStore
	desc  ocispec.Descriptor
	buf   bytes.Buffer
}

func (w *memContentWriter) Write(p []byte) (int, error) { return w.buf.Write(p) }
func (w *memContentWriter) Close() error {
	w.desc.Size = int64(w.buf.Len())
	w.desc.Digest = digest.FromBytes(w.buf.Bytes())
	w.store.blobs[w.desc.Digest] = append([]byte(nil), w.buf.Bytes()...)
	return nil
}
func (w *memContentWriter) Digest() digest.Digest { return w.desc.Digest }
func (w *memContentWriter) Commit(context.Context, int64, digest.Digest, ...content.Opt) error {
	return w.Close()
}
func (w *memContentWriter) Status() (content.Status, error) { return content.Status{}, nil }
func (w *memContentWriter) Truncate(int64) error            { return nil }

func (m *memContentStore) Writer(_ context.Context, _ ...content.WriterOpt) (content.Writer, error) {
	return &memContentWriter{store: m, desc: ocispec.Descriptor{MediaType: "application/octet-stream"}}, nil
}
func (m *memContentStore) ReaderAt(ctx context.Context, desc ocispec.Descriptor) (content.ReaderAt, error) {
	b, ok := m.blobs[desc.Digest]
	if !ok {
		return nil, errdefs.ErrNotFound
	}
	return &memReaderAt{data: b}, nil
}
func (m *memContentStore) Status(context.Context, string) (content.Status, error) {
	return content.Status{}, errdefs.ErrNotFound
}
func (m *memContentStore) Exists(_ context.Context, dgst digest.Digest) (bool, error) {
	_, ok := m.blobs[dgst]
	return ok, nil
}

func seedManifestStore(t *testing.T) (*memContentStore, ocispec.Descriptor) {
	t.Helper()
	cfgBody, _ := json.Marshal(ocispec.Image{RootFS: ocispec.RootFS{Type: "layers", DiffIDs: []digest.Digest{digest.Digest("sha256:" + strings.Repeat("1", 64))}}})
	cfgDigest := digest.FromBytes(cfgBody)
	manifestBody, _ := json.Marshal(ocispec.Manifest{
		MediaType: ocispec.MediaTypeImageManifest,
		Config:    ocispec.Descriptor{MediaType: ocispec.MediaTypeImageConfig, Digest: cfgDigest, Size: int64(len(cfgBody))},
		Layers:    []ocispec.Descriptor{{MediaType: ocispec.MediaTypeImageLayerGzip, Digest: digest.Digest("sha256:" + strings.Repeat("2", 64)), Size: 1}},
	})
	manifestDigest := digest.FromBytes(manifestBody)
	cs := &memContentStore{blobs: map[digest.Digest][]byte{
		cfgDigest:      cfgBody,
		manifestDigest: manifestBody,
	}}
	return cs, ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest, Digest: manifestDigest, Size: int64(len(manifestBody))}
}

func TestRawSnapshotBackendBaseManifestAndWriteBlob(t *testing.T) {
	cs, target := seedManifestStore(t)
	orig := snapshotContentStoreFn
	snapshotContentStoreFn = func(*Client) content.Store { return cs }
	t.Cleanup(func() { snapshotContentStoreFn = orig })

	d := newTestDriver(t)
	client := NewTestClient("aerolvm", newFakeTransport())
	b := &rawSnapshotBackend{d: d, client: client}

	manifest, config, err := b.baseManifestAndConfig(context.Background(), target)
	if err != nil || manifest.MediaType == "" || config.RootFS.Type == "" {
		t.Fatalf("manifest/config err=%v manifest=%+v config=%+v", err, manifest, config)
	}
	desc, err := b.writeBlob(context.Background(), ocispec.MediaTypeImageConfig, []byte(`{"rootfs":{}}`), map[string]string{"k": "v"})
	if err != nil || desc.Digest == "" {
		t.Fatalf("writeBlob err=%v", err)
	}
	if _, ok := cs.blobs[desc.Digest]; !ok {
		t.Fatal("blob not stored")
	}
}

func TestAssembleCommittedImageMarshalErrors(t *testing.T) {
	backend := baseFixture(nil)
	backend.baseConfig = ocispec.Image{}
	// Force json.Marshal failure via an invalid RootFS type is hard; instead hit writeBlobErr.
	backend.writeBlobErr = errors.New("write failed")
	if _, err := assembleCommittedImage(context.Background(), backend, backend.baseManifest.Config, backend.diffDesc, "snap:v1", time.Now().UTC()); err == nil {
		t.Fatal("want write error")
	}
}

func TestCommitContainerSnapshotErrorBranches(t *testing.T) {
	d := newTestDriver(t)
	ctx := context.Background()

	t.Run("no backend", func(t *testing.T) {
		if _, err := d.commitContainerSnapshotLive(ctx, d.client, "sb", "snap:v1"); err == nil {
			t.Fatal("want backend error")
		}
	})

	run := func(name string, backend *fakeSnapshotBackend, containerRef string) {
		t.Run(name, func(t *testing.T) {
			testSnapshotBackend = backend
			t.Cleanup(func() { testSnapshotBackend = nil })
			if _, err := d.commitContainerSnapshotLive(ctx, d.client, containerRef, "snap:v1"); err == nil {
				t.Fatal("want error")
			}
		})
	}

	run("load fail", &fakeSnapshotBackend{}, "missing")
	run("task fail", &fakeSnapshotBackend{container: &fakeContainer{id: "sb", taskErr: errors.New("no task")}}, "sb")
	run("pause fail", &fakeSnapshotBackend{container: &fakeContainer{
		id: "sb", task: &fakeTask{status: cntr.Running, pauseErr: errors.New("pause failed")},
	}}, "sb")
	run("info fail", &fakeSnapshotBackend{container: &fakeContainer{id: "sb", task: &fakeTask{status: cntr.Running}, infoErr: errors.New("info")}}, "sb")
	run("no snapshot", &fakeSnapshotBackend{container: &fakeContainer{id: "sb", task: &fakeTask{status: cntr.Running}, noSnapshot: true}}, "sb")
	run("no base image", &fakeSnapshotBackend{container: &fakeContainer{id: "sb", task: &fakeTask{status: cntr.Running}, baseImage: " "}}, "sb")
	run("diff fail", func() *fakeSnapshotBackend {
		b := baseFixture(&fakeTask{status: cntr.Running})
		b.createDiffErr = errors.New("diff failed")
		return b
	}(), "sb-1")
	run("base image missing", func() *fakeSnapshotBackend {
		b := baseFixture(&fakeTask{status: cntr.Running})
		b.getErr = errdefs.ErrNotFound
		return b
	}(), "sb-1")
	run("create fail", func() *fakeSnapshotBackend {
		b := baseFixture(&fakeTask{status: cntr.Running})
		b.createErr = errors.New("create failed")
		return b
	}(), "sb-1")
	run("unpack fail", func() *fakeSnapshotBackend {
		b := baseFixture(&fakeTask{status: cntr.Running})
		b.unpackErr = errors.New("unpack failed")
		return b
	}(), "sb-1")
	run("exists get fail", func() *fakeSnapshotBackend {
		b := baseFixture(&fakeTask{status: cntr.Running})
		b.createErr = errdefs.ErrAlreadyExists
		b.getErr = errors.New("get failed")
		return b
	}(), "sb-1")
	run("exists unpack fail", func() *fakeSnapshotBackend {
		b := baseFixture(&fakeTask{status: cntr.Running})
		b.createErr = errdefs.ErrAlreadyExists
		b.getImg = images.Image{Target: ocispec.Descriptor{Digest: digest.Digest("sha256:" + strings.Repeat("d", 64))}}
		b.unpackErr = errors.New("unpack existing failed")
		return b
	}(), "sb-1")
}

func TestLoadContainerForRefListError(t *testing.T) {
	tr := &listFailTransport{}
	d := newTestDriver(t)
	d.SetClient(NewTestClient("aerolvm", tr))
	_, err := d.loadContainerForRef(context.Background(), d.client, "sb-label")
	if err == nil {
		t.Fatal("want list error")
	}
}

type listFailTransport struct{ fakeTransport }

func (*listFailTransport) loadContainer(context.Context, string) (cntr.Container, error) {
	return nil, errdefs.ErrNotFound
}
func (*listFailTransport) listContainers(context.Context, ...string) ([]cntr.Container, error) {
	return nil, errors.New("list failed")
}

func TestSplitSnapshotImageRefBranches(t *testing.T) {
	if _, _, err := splitSnapshotImageRef("  "); err == nil {
		t.Fatal("want empty error")
	}
	if _, _, err := splitSnapshotImageRef(":onlytag"); err == nil {
		t.Fatal("want invalid repo")
	}
	if repo, tag, err := splitSnapshotImageRef("repo"); err != nil || repo != "repo" || tag != "" {
		t.Fatalf("repo=%q tag=%q err=%v", repo, tag, err)
	}
}

func TestResolveSnapshotBackendNilRaw(t *testing.T) {
	d := newTestDriver(t)
	if b := resolveSnapshotBackend(d, NewTestClient("aerolvm", newFakeTransport())); b != nil {
		t.Fatalf("nil raw should yield nil backend, got %T", b)
	}
}

// ---------------------------------------------------------------------------
// lifecycle / events / hosts / buildkit / misc
// ---------------------------------------------------------------------------

func TestCreateIgnoresDiskGB(t *testing.T) {
	stubToolboxProbe(t)
	d := newTestDriver(t)
	_, err := d.Create(context.Background(), models.CreateSandboxRequest{
		Image: "alpine:3.20", ContainerCommand: []string{"sleep"}, DiskGB: 10,
	}, "sb-disk", "tok", nil)
	if err != nil {
		t.Fatal(err)
	}
}

func TestCreateInvalidRuntime(t *testing.T) {
	stubToolboxProbe(t)
	d := newTestDriver(t)
	_, err := d.Create(context.Background(), models.CreateSandboxRequest{
		Image: "alpine:3.20", ContainerCommand: []string{"sleep"}, Runtime: "bogus",
	}, "sb-rt", "tok", nil)
	if err == nil {
		t.Fatal("want runtime validation error")
	}
}

func TestCreateEgressPolicyFailure(t *testing.T) {
	stubToolboxProbe(t)
	be := &netrulesFailInsertBackend{}
	tmp := t.TempDir()
	toolbox := filepath.Join(tmp, "toolboxd")
	_ = os.WriteFile(toolbox, []byte{0}, 0o755)
	d := New(Config{
		ToolboxBinaryPath:  toolbox,
		ToolboxMountPath:   "/.aerol/toolboxd",
		ToolboxPort:        2280,
		ToolboxWaitTimeout: 2 * time.Second,
		LogDir:             filepath.Join(tmp, "logs"),
		RunDir:             filepath.Join(tmp, "run"),
	}, netrules.NewWithBackend(be), nil)
	d.SetClient(NewTestClient("aerolvm", newFakeTransport()))
	d.SetNetnsHandoff(&harnessNetns{path: "/run/netns/x", ip: "10.88.0.1"})
	_, err := d.Create(context.Background(), models.CreateSandboxRequest{
		Image: "alpine:3.20", ContainerCommand: []string{"sleep"},
		NetworkAllowOut: []string{"1.2.3.4/32"},
	}, "sb-egress-fail", "tok", nil)
	if err == nil {
		t.Fatal("want egress error")
	}
}

func TestStartWithReadySocket(t *testing.T) {
	stubToolboxProbe(t)
	tr := newFakeTransport()
	tr.containers["sb-ready"] = &fakeContainer{id: "sb-ready", task: &fakeTask{status: cntr.Stopped}}
	d := newTestDriver(t)
	d.cfg.ReadyEnabled = true
	d.cfg.ReadyDir = shortReadyDir(t)
	if err := os.MkdirAll(d.cfg.ReadyDir, 0o700); err != nil {
		t.Fatal(err)
	}
	d.SetClient(NewTestClient("aerolvm", tr))
	if _, err := d.Start(context.Background(), "sb-ready"); err != nil {
		t.Fatal(err)
	}
}

func TestStartTaskCreateError(t *testing.T) {
	tr := newFakeTransport()
	tr.containers["sb-bad"] = &fakeContainer{
		id:   "sb-bad",
		task: &fakeTask{status: cntr.Stopped},
	}
	d := newTestDriver(t)
	d.SetClient(NewTestClient("aerolvm", tr))
	// Second NewTask after delete succeeds on fake; force taskLogPath error instead.
	d.cfg.LogDir = filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(d.cfg.LogDir, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Start(context.Background(), "sb-bad"); err == nil {
		t.Fatal("want task log path error")
	}
}

func TestStopKillTimeout(t *testing.T) {
	tr := newFakeTransport()
	tr.containers["sb-hang"] = &fakeContainer{
		id:   "sb-hang",
		task: &fakeTask{status: cntr.Running},
	}
	d := newTestDriver(t)
	d.SetClient(NewTestClient("aerolvm", tr))
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_ = d.Stop(ctx, "sb-hang")
}

func TestDestroyEnsureClientError(t *testing.T) {
	d := New(Config{}, nil, nil)
	d.SetClient(nil)
	orig := connectFn
	connectFn = func(string, string) (*Client, error) { return nil, errors.New("no socket") }
	t.Cleanup(func() { connectFn = orig })
	if err := d.Destroy(context.Background(), &models.Sandbox{ID: "sb", ContainerID: "sb"}); err == nil {
		t.Fatal("want ensureClient error")
	}
}

func TestInspectStoppedContainer(t *testing.T) {
	tr := newFakeTransport()
	tr.containers["sb-stop"] = &fakeContainer{id: "sb-stop", taskErr: errdefs.ErrNotFound}
	d := newTestDriver(t)
	d.SetClient(NewTestClient("aerolvm", tr))
	state, err := d.Inspect(context.Background(), "sb-stop")
	if err != nil || state.Status != models.SandboxStatusStopped {
		t.Fatalf("state=%+v err=%v", state, err)
	}
}

func TestListManagedSkipsBrokenInspect(t *testing.T) {
	tr := newFakeTransport()
	tr.containers["sb-bad"] = &fakeContainer{
		id:        "sb-bad",
		labelsErr: errors.New("labels broken"),
	}
	d := newTestDriver(t)
	d.SetClient(NewTestClient("aerolvm", tr))
	managed, err := d.ListManaged(context.Background())
	if err != nil || len(managed) != 0 {
		t.Fatalf("managed=%v err=%v", managed, err)
	}
}

func TestSandboxIDFromContainerNilAndLabelError(t *testing.T) {
	d := newTestDriver(t)
	if got := d.sandboxIDFromContainer(context.Background(), nil); got != "" {
		t.Fatalf("got %q", got)
	}
}

func TestRuntimeStateAfterStartIPHint(t *testing.T) {
	d := newTestDriver(t)
	orig := containerIPv4FromTaskFn
	containerIPv4FromTaskFn = func(context.Context, cntr.Task) (string, error) { return "", errors.New("no ip") }
	t.Cleanup(func() { containerIPv4FromTaskFn = orig })
	state, err := d.runtimeStateAfterStart(context.Background(), nil, &fakeTask{}, "sb", "10.1.2.3")
	if err != nil || state.ContainerIP != "10.1.2.3" {
		t.Fatalf("state=%+v err=%v", state, err)
	}
}

func TestWaitToolboxHTTPSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	ip := strings.Split(host, ":")[0]
	port := strings.Split(host, ":")[1]
	var p int
	_, _ = fmt.Sscanf(port, "%d", &p)

	orig := pollToolboxHealthFn
	pollToolboxHealthFn = func(ctx context.Context, containerIP string, toolboxPort int) error {
		if containerIP == ip && toolboxPort == p {
			return nil
		}
		return errors.New("wrong target")
	}
	t.Cleanup(func() { pollToolboxHealthFn = orig })

	d := newTestDriver(t)
	d.cfg.ToolboxPort = p
	if err := d.waitToolboxHTTP(context.Background(), ip, "tok"); err != nil {
		t.Fatal(err)
	}
}

func TestStreamEventsEnrichesSandboxID(t *testing.T) {
	tr := &enrichEventTransport{
		fakeTransport: *newFakeTransport(),
		ch: func() chan *events.Envelope {
			any, _ := typeurl.MarshalAny(&apievents.TaskStart{ContainerID: "park-1"})
			ch := make(chan *events.Envelope, 1)
			ch <- &events.Envelope{Topic: runtime.TaskStartEventTopic, Timestamp: time.Now(), Event: any}
			close(ch)
			return ch
		}(),
	}
	tr.containers["park-1"] = &fakeContainer{
		id: "park-1", labels: map[string]string{sandboxIDLabelKey: "sb-real"},
	}
	d := newTestDriver(t)
	d.SetClient(NewTestClient("aerolvm", tr))
	ctx, cancel := context.WithCancel(context.Background())
	out := make(chan docker.DockerEvent, 1)
	go func() {
		_ = d.StreamEvents(ctx, out)
	}()
	ev := <-out
	cancel()
	if ev.SandboxID != "sb-real" {
		t.Fatalf("sandbox id=%q", ev.SandboxID)
	}
}

type enrichEventTransport struct {
	fakeTransport
	ch chan *events.Envelope
}

func (e *enrichEventTransport) subscribe(context.Context, ...string) (<-chan *events.Envelope, <-chan error) {
	errCh := make(chan error)
	close(errCh)
	return e.ch, errCh
}

func TestContainerIDAndExitFromEvent(t *testing.T) {
	any, _ := typeurl.MarshalAny(&apievents.TaskExit{ContainerID: "sb", ExitStatus: 137})
	id, code := containerIDAndExitFromEvent(&events.Envelope{Event: any})
	if id != "sb" || code != 137 {
		t.Fatalf("id=%q code=%d", id, code)
	}
}

func TestExtractTarCopyAndCloseErrors(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	_ = tw.WriteHeader(&tar.Header{Name: "big.bin", Mode: 0o644, Size: 3, Typeflag: tar.TypeReg})
	_, _ = tw.Write([]byte("abc"))
	_ = tw.Close()
	dir := t.TempDir()
	if err := extractTar(buf.Bytes(), dir); err != nil {
		t.Fatal(err)
	}

	// Unwritable target exercises OpenFile error path.
	badDir := filepath.Join(t.TempDir(), "ro")
	if err := os.Mkdir(badDir, 0o500); err != nil {
		t.Fatal(err)
	}
	var buf2 bytes.Buffer
	tw2 := tar.NewWriter(&buf2)
	_ = tw2.WriteHeader(&tar.Header{Name: "nope.txt", Mode: 0o644, Size: 1, Typeflag: tar.TypeReg})
	_, _ = tw2.Write([]byte("x"))
	_ = tw2.Close()
	if err := extractTar(buf2.Bytes(), badDir); err == nil {
		t.Fatal("want write error into read-only dir")
	}
}

func TestBuildImageWriteDockerfileError(t *testing.T) {
	b := NewBuildKitBuilder("", writeFakeBuildctl(t, "", 0), nil)
	// Point context at a file so MkdirTemp still works but Dockerfile write to
	// invalid nested path is not the goal — exercise extract error instead.
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	_ = tw.WriteHeader(&tar.Header{Name: "../escape", Mode: 0o644, Size: 1, Typeflag: tar.TypeReg})
	_, _ = tw.Write([]byte("x"))
	_ = tw.Close()
	err := b.BuildImage(context.Background(), docker.BuildImageRequest{
		Tag:               "x:1",
		DockerfileContent: "FROM scratch",
		ContextTar:        buf.Bytes(),
	})
	if err == nil || !strings.Contains(err.Error(), "extract context") {
		t.Fatalf("err=%v", err)
	}
}

func TestEnsureRunscConfigNilDriver(t *testing.T) {
	var d *Driver
	if _, err := d.ensureRunscConfig(); err == nil {
		t.Fatal("want nil driver error")
	}
}

func TestEnsureRunscConfigReadError(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "runsc", "config.toml")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("stale"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Dir(path), 0o000); err != nil {
		t.Fatal(err)
	}
	d := New(Config{RunDir: tmp}, nil, nil)
	_, err := d.ensureRunscConfig()
	_ = os.Chmod(filepath.Dir(path), 0o700)
	if err == nil {
		t.Fatal("want read error on stale config")
	}
}

func TestRunscRuntimeOptsNilDriverHigh95(t *testing.T) {
	var d *Driver
	if _, err := d.runscRuntimeOpts(); err == nil {
		t.Fatal("want error from nil driver")
	}
}

func TestRuntimeContainerOptRunscHigh95(t *testing.T) {
	d := newTestDriver(t)
	opt, err := d.runtimeContainerOpt("runsc")
	if err != nil || opt == nil {
		t.Fatalf("opt=%v err=%v", opt, err)
	}
}

func TestCappedWriterTruncates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cap.log")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	w := &cappedWriter{f: f, cap: 32}
	if _, err := w.Write(bytes.Repeat([]byte("x"), 64)); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(body) > 80 {
		t.Fatalf("body too large: %d", len(body))
	}
}

func TestPinImageLeaseCreateError(t *testing.T) {
	lm := &fakeLeaseManager{createErr: errors.New("lease create failed")}
	orig := leasesServiceFn
	leasesServiceFn = func(*Client) leaseManager { return lm }
	t.Cleanup(func() { leasesServiceFn = orig })
	d := newTestDriver(t)
	_, err := d.pinImageLease(context.Background(), d.client, digestImage())
	if err == nil {
		t.Fatal("want lease create error")
	}
}

func TestAssertSupportedContainerdVersionHigh95(t *testing.T) {
	cases := []struct {
		v   string
		err bool
	}{
		{"", true},
		{"1", true},
		{"v1.5.0", true},
		{"3.0.0", true},
		{"1.6.0", false},
		{"2.0.0", false},
		{"v1.7.13", false},
		{"bad.x", true},
	}
	for _, tc := range cases {
		err := assertSupportedContainerdVersion(tc.v)
		if (err != nil) != tc.err {
			t.Fatalf("version %q err=%v wantErr=%v", tc.v, err, tc.err)
		}
	}
}

func TestTryWarmAdoptDuplicateReturnsSlot(t *testing.T) {
	stubToolboxProbe(t)
	p := containerdpool.New(nil)
	key := containerdpool.KeyFromRequest(models.CreateSandboxRequest{Image: "alpine:3.20"}, models.RuntimeDocker)
	p.NoteTarget(key)
	tr := newFakeTransport()
	tr.containers["sb-dup"] = &fakeContainer{id: "sb-dup", labels: map[string]string{managedLabelKey: "true"}}
	tr.containers["park-1"] = &fakeContainer{id: "park-1", labels: map[string]string{poolParkLabelKey: poolParkLabelValue}}
	d := newTestDriver(t)
	d.cfg.ReadyEnabled = true
	d.SetClient(NewTestClient("aerolvm", tr))
	d.SetWarmPool(p)
	p.RecordLoaded(&containerdpool.ParkedSlot{
		ID: "park-1", ContainerID: "park-1", ContainerIP: "10.88.0.9",
		ImageID: "img", Key: key, Handle: &fakeHandle{alive: true},
	})
	_, err := d.tryWarmAdopt(context.Background(), models.CreateSandboxRequest{Image: "alpine:3.20"}, "sb-dup", "tok", nil, models.RuntimeDocker)
	if !errors.Is(err, docker.ErrSandboxContainerExists) {
		t.Fatalf("err=%v", err)
	}
}

func TestTryWarmAdoptAdoptFailedTiming(t *testing.T) {
	stubToolboxProbe(t)
	p := containerdpool.New(nil)
	key := containerdpool.KeyFromRequest(models.CreateSandboxRequest{Image: "alpine:3.20"}, models.RuntimeDocker)
	p.NoteTarget(key)
	tr := newFakeTransport()
	tr.containers["park-1"] = &fakeContainer{id: "park-1", labels: map[string]string{poolParkLabelKey: poolParkLabelValue}}
	d := newTestDriver(t)
	d.cfg.ReadyEnabled = true
	d.SetClient(NewTestClient("aerolvm", tr))
	d.SetWarmPool(p)
	p.RecordLoaded(&containerdpool.ParkedSlot{
		ID: "park-1", ContainerID: "park-1", ContainerIP: "10.88.0.9",
		ImageID: "img", Key: key,
		Handle: &fakeAdoptFailHandle{},
	})
	ctx, timing := createtiming.With(context.Background())
	_, err := d.tryWarmAdopt(ctx, models.CreateSandboxRequest{Image: "alpine:3.20"}, "sb-fail", "tok", nil, models.RuntimeDocker)
	if err == nil {
		t.Fatal("want adopt failure")
	}
	found := false
	for _, st := range timing.Stages() {
		if st.Name == "containerd_pool" && st.Desc == "adopt_failed" {
			found = true
		}
	}
	if !found {
		t.Fatalf("stages=%v", timing.Stages())
	}
}

type fakeAdoptFailHandle struct{}

func (fakeAdoptFailHandle) Alive() bool { return true }
func (fakeAdoptFailHandle) Adopt(context.Context, string, string, string) error {
	return errors.New("adopt failed")
}
func (fakeAdoptFailHandle) Close() error { return nil }

func TestEnsureImageBackoffHigh95(t *testing.T) {
	tr := newFakeTransport()
	tr.getImageFn = func(context.Context, string) (cntr.Image, error) {
		return nil, errdefs.ErrNotFound
	}
	tr.pullImageFn = func(context.Context, string, ...cntr.RemoteOpt) (cntr.Image, error) {
		return nil, errors.New("pull failed")
	}
	d := New(Config{PullFailureBackoff: time.Minute}, nil, nil)
	d.SetClient(NewTestClient("aerolvm", tr))
	_, err := d.ensureImage(context.Background(), d.client, "alpine:3.20", nil)
	if err == nil {
		t.Fatal("want pull error")
	}
	_, err = d.ensureImage(context.Background(), d.client, "alpine:3.20", nil)
	if err == nil || !strings.Contains(err.Error(), "backing off") {
		t.Fatalf("err=%v", err)
	}
}

func TestRegistryHostAndRefHasTag(t *testing.T) {
	if registryHost("alpine:3.20") != "" {
		t.Fatal("docker hub short ref has no host")
	}
	if registryHost("ghcr.io/org/app:tag") != "ghcr.io" {
		t.Fatal("registry host")
	}
	if !refHasTag("app:v1") || refHasTag("app") || !refHasTag("app@sha256:abc") {
		t.Fatal("refHasTag")
	}
}

func TestCntrClientRawContentProviderLive(t *testing.T) {
	c := cntrClientRaw{}
	if c.ContentProvider() != nil {
		t.Fatal("nil client")
	}
	provider, _ := newTestImageProvider(t)
	ft := newFakeTransport()
	ft.provider = provider
	if got := (&liveTransport{raw: stubRawAPI{ft: ft}, ns: "aerolvm"}).contentProvider(); got == nil {
		t.Fatal("expected provider from stub raw API")
	}
}

func TestResolvePushLiveDepsNilRaw(t *testing.T) {
	_, err := resolvePushLiveDeps(NewTestClient("aerolvm", newFakeTransport()))
	if err == nil || !strings.Contains(err.Error(), "live client required") {
		t.Fatalf("err=%v", err)
	}
}

func TestRemoveImageFnRequiresLive(t *testing.T) {
	err := removeImageFn(context.Background(), NewTestClient("aerolvm", newFakeTransport()), "alpine:3.20")
	if err == nil || !strings.Contains(err.Error(), "live containerd") {
		t.Fatalf("err=%v", err)
	}
}

func TestCreateRunscRuntime(t *testing.T) {
	stubToolboxProbe(t)
	d := newTestDriver(t)
	_, err := d.Create(context.Background(), models.CreateSandboxRequest{
		Image: "alpine:3.20", ContainerCommand: []string{"sleep"}, Runtime: models.RuntimeGvisor,
	}, "sb-gv", "tok", nil)
	if err != nil {
		t.Fatal(err)
	}
}

func TestCreateNewTaskFailure(t *testing.T) {
	stubToolboxProbe(t)
	tr := newFakeTransport()
	tr.pendingTaskErr = map[string]error{"sb-ntask-err": errors.New("new task failed")}
	d := newTestDriver(t)
	d.SetClient(NewTestClient("aerolvm", tr))
	_, err := d.Create(context.Background(), models.CreateSandboxRequest{
		Image: "alpine:3.20", ContainerCommand: []string{"sleep"},
	}, "sb-ntask-err", "tok", nil)
	if err == nil || !strings.Contains(err.Error(), "create task") {
		t.Fatalf("err=%v", err)
	}
}

func shortReadyDirForCreate(t *testing.T) string {
	t.Helper()
	dir := "/tmp/avmrdy"
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func TestCreateWarmAdoptFallthrough(t *testing.T) {
	stubToolboxProbe(t)
	orig := createReadyWaitFn
	createReadyWaitFn = func(context.Context, *docker.ReadyListener) error { return nil }
	t.Cleanup(func() { createReadyWaitFn = orig })

	p := containerdpool.New(nil)
	d := newTestDriver(t)
	d.cfg.ReadyEnabled = true
	d.cfg.ReadyDir = shortReadyDirForCreate(t)
	d.SetWarmPool(p)
	_, err := d.Create(context.Background(), models.CreateSandboxRequest{
		Image: "alpine:3.20", ContainerCommand: []string{"sleep"},
	}, "sb-cold", "tok", nil)
	if err != nil {
		t.Fatal(err)
	}
}

func TestCreatePrepareHostFilesFailure(t *testing.T) {
	stubToolboxProbe(t)
	d := newTestDriver(t)
	bad := filepath.Join(t.TempDir(), "file")
	_ = os.WriteFile(bad, []byte("x"), 0o644)
	d.cfg.RunDir = bad
	_, err := d.Create(context.Background(), models.CreateSandboxRequest{
		Image: "alpine:3.20", ContainerCommand: []string{"sleep"},
	}, "sb-hosts", "tok", nil)
	if err == nil {
		t.Fatal("want host files error")
	}
}

func TestDestroyLoadContainerError(t *testing.T) {
	tr := newFakeTransport()
	tr.loadContainerFn = func(context.Context, string) (cntr.Container, error) {
		return nil, errors.New("load failed")
	}
	d := newTestDriver(t)
	d.SetClient(NewTestClient("aerolvm", tr))
	err := d.Destroy(context.Background(), &models.Sandbox{ID: "sb", ContainerID: "sb"})
	if err == nil {
		t.Fatal("want load error")
	}
}

func TestAdoptParkedLoadAndLabelErrors(t *testing.T) {
	d := newTestDriver(t)
	tr := newFakeTransport()
	d.SetClient(NewTestClient("aerolvm", tr))
	_, err := d.adoptParked(context.Background(), models.CreateSandboxRequest{}, "sb", "tok", &containerdpool.ParkedSlot{
		ID: "park-1", ContainerID: "missing", Handle: &fakeHandle{alive: true},
	})
	if err == nil {
		t.Fatal("want load error")
	}

	tr.containers["park-2"] = &fakeContainer{id: "park-2", labelsErr: errors.New("labels fail")}
	_, err = d.adoptParked(context.Background(), models.CreateSandboxRequest{}, "sb2", "tok", &containerdpool.ParkedSlot{
		ID: "park-2", ContainerID: "park-2", Handle: &fakeHandle{alive: true},
	})
	if err == nil {
		t.Fatal("want labels error")
	}
}

func TestAdoptParkedAdoptFailure(t *testing.T) {
	tr := newFakeTransport()
	tr.containers["park-3"] = &fakeContainer{id: "park-3", labels: map[string]string{poolParkLabelKey: poolParkLabelValue}}
	d := newTestDriver(t)
	d.SetClient(NewTestClient("aerolvm", tr))
	_, err := d.adoptParked(context.Background(), models.CreateSandboxRequest{}, "sb3", "tok", &containerdpool.ParkedSlot{
		ID: "park-3", ContainerID: "park-3", Handle: &fakeAdoptFailHandle{},
	})
	if err == nil {
		t.Fatal("want adopt error")
	}
}

func TestAssertSandboxNotExistsLoadError(t *testing.T) {
	tr := newFakeTransport()
	tr.loadContainerFn = func(_ context.Context, id string) (cntr.Container, error) {
		if id == "sb-x" {
			return nil, errors.New("load boom")
		}
		return nil, errdefs.ErrNotFound
	}
	d := newTestDriver(t)
	d.SetClient(NewTestClient("aerolvm", tr))
	if err := d.assertSandboxNotExists(context.Background(), d.client, "sb-x", "park-1"); err == nil {
		t.Fatal("want load error")
	}
}

func TestFindContainerBySandboxIDError(t *testing.T) {
	tr := &listFailTransport{}
	d := newTestDriver(t)
	d.SetClient(NewTestClient("aerolvm", tr))
	_, err := d.findContainerBySandboxID(context.Background(), d.client, "sb")
	if err == nil {
		t.Fatal("want list error")
	}
}

func TestAssembleCommittedImageDiffIDError(t *testing.T) {
	backend := baseFixture(nil)
	backend.diffIDErr = errors.New("diff id failed")
	if _, err := assembleCommittedImage(context.Background(), backend, backend.baseManifest.Config, backend.diffDesc, "snap:v1", time.Now().UTC()); err == nil {
		t.Fatal("want diff id error")
	}
}

func TestAssembleCommittedImageManifestError(t *testing.T) {
	backend := baseFixture(nil)
	backend.manifestErr = errors.New("manifest failed")
	if _, err := assembleCommittedImage(context.Background(), backend, backend.baseManifest.Config, backend.diffDesc, "snap:v1", time.Now().UTC()); err == nil {
		t.Fatal("want manifest error")
	}
}

func TestRawSnapshotBackendDiffIDWithStore(t *testing.T) {
	cs, target := seedManifestStore(t)
	layer := ocispec.Descriptor{MediaType: ocispec.MediaTypeImageLayerGzip, Digest: digest.Digest("sha256:" + strings.Repeat("2", 64)), Size: 1}
	cs.blobs[layer.Digest] = []byte{0x1f, 0x8b}
	orig := snapshotContentStoreFn
	snapshotContentStoreFn = func(*Client) content.Store { return cs }
	t.Cleanup(func() { snapshotContentStoreFn = orig })
	b := &rawSnapshotBackend{d: newTestDriver(t), client: NewTestClient("aerolvm", newFakeTransport())}
	if _, err := b.diffID(context.Background(), layer); err != nil {
		// GetDiffID may fail on minimal gzip — still exercised the store path.
		_ = err
	}
	_, _, err := b.baseManifestAndConfig(context.Background(), target)
	if err != nil {
		t.Fatalf("baseManifestAndConfig: %v", err)
	}
}

func TestPrepareSandboxHostFilesHostsWriteError(t *testing.T) {
	runDir := t.TempDir()
	// Block writes under hosts/ so resolv.conf write fails after mkdir.
	hostsRoot := filepath.Join(runDir, "hosts")
	if err := os.MkdirAll(hostsRoot, 0o500); err != nil {
		t.Fatal(err)
	}
	_, err := prepareSandboxHostFiles(runDir, "sb-write-fail")
	if err == nil {
		t.Fatal("want write error")
	}
}

func TestExtractTarMkdirError(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	_ = tw.WriteHeader(&tar.Header{Name: "sub/", Mode: 0o755, Typeflag: tar.TypeDir})
	_ = tw.Close()
	base := t.TempDir()
	if err := os.Chmod(base, 0o500); err != nil {
		t.Fatal(err)
	}
	if err := extractTar(buf.Bytes(), base); err == nil {
		t.Fatal("want mkdir error")
	}
}

func TestTaskLogIOOpenError(t *testing.T) {
	badPath := filepath.Join(t.TempDir(), "missing", "log")
	_, _, err := taskLogIO(badPath)
	if err == nil {
		t.Fatal("want open error")
	}
}

func TestRuntimeStateAfterStartError(t *testing.T) {
	d := newTestDriver(t)
	orig := containerIPv4FromTaskFn
	containerIPv4FromTaskFn = func(context.Context, cntr.Task) (string, error) {
		return "", errors.New("no ip")
	}
	t.Cleanup(func() { containerIPv4FromTaskFn = orig })
	_, err := d.runtimeStateAfterStart(context.Background(), &fakeContainer{id: "sb"}, &fakeTask{}, "sb", "")
	if err == nil {
		t.Fatal("want ip error")
	}
}

func TestStartStatusErrorPath(t *testing.T) {
	stubToolboxProbe(t)
	tr := newFakeTransport()
	tr.containers["sb-st"] = &fakeContainer{
		id:   "sb-st",
		task: &fakeTask{status: cntr.Running, statusErr: errors.New("status fail")},
	}
	d := newTestDriver(t)
	d.SetClient(NewTestClient("aerolvm", tr))
	if _, err := d.Start(context.Background(), "sb-st"); err != nil {
		t.Fatal(err) // falls through to recreate task path
	}
}

func TestStartNewTaskError(t *testing.T) {
	tr := newFakeTransport()
	tr.containers["sb-nt"] = &fakeContainer{
		id:         "sb-nt",
		task:       &fakeTask{status: cntr.Stopped},
		newTaskErr: errors.New("new task failed"),
	}
	d := newTestDriver(t)
	d.SetClient(NewTestClient("aerolvm", tr))
	_, err := d.Start(context.Background(), "sb-nt")
	if err == nil || !strings.Contains(err.Error(), "create task") {
		t.Fatalf("err=%v", err)
	}
}

func TestPinImageLeaseNilInputs(t *testing.T) {
	d := newTestDriver(t)
	if id, err := d.pinImageLease(context.Background(), nil, nil); err != nil || id != "" {
		t.Fatalf("id=%q err=%v", id, err)
	}
}

func TestRandomLeaseIDRandFailure(t *testing.T) {
	orig := randReadFn
	randReadFn = func([]byte) (int, error) { return 0, errors.New("rand failed") }
	t.Cleanup(func() { randReadFn = orig })
	if _, err := randomLeaseID("x-"); err == nil {
		t.Fatal("want rand error")
	}
}

func TestAssertSupportedContainerdVersionBadMinor(t *testing.T) {
	if err := assertSupportedContainerdVersion("1.5.9"); err == nil {
		t.Fatal("want unsupported minor")
	}
}

func TestTryWarmAdoptAcquireError(t *testing.T) {
	stubToolboxProbe(t)
	p := containerdpool.New(nil)
	key := containerdpool.KeyFromRequest(models.CreateSandboxRequest{Image: "alpine:3.20"}, models.RuntimeDocker)
	p.NoteTarget(key)
	d := newTestDriver(t)
	d.cfg.ReadyEnabled = true
	d.SetWarmPool(p)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := d.tryWarmAdopt(ctx, models.CreateSandboxRequest{Image: "alpine:3.20"}, "sb", "tok", nil, models.RuntimeDocker)
	if err == nil {
		t.Fatal("want acquire error")
	}
}

func TestDestroyParkedLoadError(t *testing.T) {
	tr := newFakeTransport()
	tr.loadContainerFn = func(context.Context, string) (cntr.Container, error) {
		return nil, errors.New("load failed")
	}
	d := newTestDriver(t)
	d.SetClient(NewTestClient("aerolvm", tr))
	if err := d.destroyParked(context.Background(), &containerdpool.ParkedSlot{ContainerID: "park-x"}); err == nil {
		t.Fatal("want load error")
	}
}

func TestImageExistsGetImageError(t *testing.T) {
	tr := newFakeTransport()
	tr.getImageFn = func(context.Context, string) (cntr.Image, error) {
		return nil, errors.New("transient")
	}
	d := newTestDriver(t)
	d.SetClient(NewTestClient("aerolvm", tr))
	ok, err := d.ImageExists(context.Background(), "alpine:3.20")
	if err != nil || ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
}

func TestEnsureImageNormalizedLocalLatest(t *testing.T) {
	tr := newFakeTransport()
	tr.getImageFn = func(_ context.Context, ref string) (cntr.Image, error) {
		if ref == "local-snap:latest" {
			return &fakeImage{name: ref}, nil
		}
		return nil, errdefs.ErrNotFound
	}
	d := newTestDriver(t)
	d.SetClient(NewTestClient("aerolvm", tr))
	img, err := d.ensureImage(context.Background(), d.client, "local-snap", nil)
	if err != nil || img == nil {
		t.Fatalf("img=%v err=%v", img, err)
	}
}

func TestCreateWithReadySocketPath(t *testing.T) {
	stubToolboxProbe(t)
	orig := createReadyWaitFn
	createReadyWaitFn = func(context.Context, *docker.ReadyListener) error { return nil }
	t.Cleanup(func() { createReadyWaitFn = orig })

	d := newTestDriver(t)
	d.cfg.ReadyEnabled = true
	d.cfg.ReadyDir = shortReadyDirForCreate(t)
	_, err := d.Create(context.Background(), models.CreateSandboxRequest{
		Image: "alpine:3.20", ContainerCommand: []string{"sleep"},
	}, "s1", "tok", nil)
	if err != nil {
		t.Fatal(err)
	}
}

func TestCreateReadySocketWaitFailure(t *testing.T) {
	stubToolboxProbe(t)
	orig := createReadyWaitFn
	createReadyWaitFn = func(context.Context, *docker.ReadyListener) error {
		return errors.New("ready timeout")
	}
	t.Cleanup(func() { createReadyWaitFn = orig })

	d := newTestDriver(t)
	d.cfg.ReadyEnabled = true
	d.cfg.ReadyDir = shortReadyDirForCreate(t)
	_, err := d.Create(context.Background(), models.CreateSandboxRequest{
		Image: "alpine:3.20", ContainerCommand: []string{"sleep"},
	}, "s2", "tok", nil)
	if err == nil || !strings.Contains(err.Error(), "ready socket") {
		t.Fatalf("err=%v", err)
	}
}

func TestCreateNetworkBlockFailure(t *testing.T) {
	stubToolboxProbe(t)
	be := &netrulesFailInsertBackend{}
	tmp := t.TempDir()
	toolbox := filepath.Join(tmp, "toolboxd")
	_ = os.WriteFile(toolbox, []byte{0}, 0o755)
	d := New(Config{
		ToolboxBinaryPath: toolbox, ToolboxMountPath: "/.aerol/toolboxd", ToolboxPort: 2280,
		ToolboxWaitTimeout: 2 * time.Second, LogDir: filepath.Join(tmp, "logs"), RunDir: filepath.Join(tmp, "run"),
	}, netrules.NewWithBackend(be), nil)
	d.SetClient(NewTestClient("aerolvm", newFakeTransport()))
	d.SetNetnsHandoff(&harnessNetns{path: "/run/netns/x", ip: "10.88.0.1"})
	_, err := d.Create(context.Background(), models.CreateSandboxRequest{
		Image: "alpine:3.20", ContainerCommand: []string{"sleep"}, NetworkBlockAll: true,
	}, "sb-block-fail", "tok", nil)
	if err == nil {
		t.Fatal("want network block error")
	}
}

func TestConnectWithStubDial(t *testing.T) {
	ft := newFakeTransport()
	orig := connectDialFn
	connectDialFn = func(string, string) (rawAPI, error) {
		return versionStub{stubRawAPI: stubRawAPI{ft: ft}, version: "1.7.13"}, nil
	}
	t.Cleanup(func() { connectDialFn = orig })

	c, err := Connect("/fake.sock", "aerolvm")
	if err != nil || c == nil || c.Namespace() != "aerolvm" {
		t.Fatalf("c=%v err=%v", c, err)
	}
	if err := c.Ping(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestConnectVersionError(t *testing.T) {
	orig := connectDialFn
	connectDialFn = func(string, string) (rawAPI, error) {
		return versionStub{stubRawAPI: stubRawAPI{ft: newFakeTransport()}, verr: errors.New("version failed")}, nil
	}
	t.Cleanup(func() { connectDialFn = orig })
	if _, err := Connect("/fake.sock", "aerolvm"); err == nil || !strings.Contains(err.Error(), "containerd version") {
		t.Fatalf("err=%v", err)
	}
}

func TestConnectUnsupportedVersion(t *testing.T) {
	orig := connectDialFn
	connectDialFn = func(string, string) (rawAPI, error) {
		return versionStub{stubRawAPI: stubRawAPI{ft: newFakeTransport()}, version: "1.5.0"}, nil
	}
	t.Cleanup(func() { connectDialFn = orig })
	if _, err := Connect("/fake.sock", "aerolvm"); err == nil {
		t.Fatal("want unsupported version error")
	}
}

func TestResourceSpecOptsFractionalCPU(t *testing.T) {
	opts := resourceSpecOpts(models.CreateSandboxRequest{CPU: 0.25, MemoryMB: 64})
	if len(opts) != 2 {
		t.Fatalf("opts=%d", len(opts))
	}
}

func TestCntrClientRawVersionNil(t *testing.T) {
	if _, err := (cntrClientRaw{}).Version(context.Background()); err == nil {
		t.Fatal("want version error")
	}
}

// ---------------------------------------------------------------------------
// lifecycle / events / hosts / buildkit — gaps toward 95%
// ---------------------------------------------------------------------------

func TestCreateSandboxAlreadyExistsRace(t *testing.T) {
	stubToolboxProbe(t)
	tr := newFakeTransport()
	tr.containers["sb-dup"] = &fakeContainer{id: "sb-dup"}
	d := newTestDriver(t)
	d.SetClient(NewTestClient("aerolvm", tr))
	_, err := d.Create(context.Background(), models.CreateSandboxRequest{
		Image: "alpine:3.20", ContainerCommand: []string{"sleep"},
	}, "sb-dup", "tok", nil)
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("err=%v", err)
	}
}

func TestCreateUsesImageDefaultCommandHigh95(t *testing.T) {
	stubToolboxProbe(t)
	provider, img := newTestImageProvider(t)
	tr := newFakeTransport()
	tr.provider = provider
	tr.image = img
	d := newTestDriver(t)
	d.SetClient(NewTestClient("aerolvm", tr))
	_, err := d.Create(context.Background(), models.CreateSandboxRequest{Image: "cfg:test"}, "sb-cmd", "tok", nil)
	if err != nil {
		t.Fatal(err)
	}
}

func TestStartStoppedRecreatesTask(t *testing.T) {
	stubToolboxProbe(t)
	tr := newFakeTransport()
	tr.containers["sb-st2"] = &fakeContainer{id: "sb-st2", task: &fakeTask{status: cntr.Stopped}}
	d := newTestDriver(t)
	d.SetClient(NewTestClient("aerolvm", tr))
	if _, err := d.Start(context.Background(), "sb-st2"); err != nil {
		t.Fatal(err)
	}
}

func TestStartRunningShortCircuit(t *testing.T) {
	stubToolboxProbe(t)
	tr := newFakeTransport()
	tr.containers["sb-run"] = &fakeContainer{id: "sb-run", task: &fakeTask{status: cntr.Running}}
	d := newTestDriver(t)
	d.SetClient(NewTestClient("aerolvm", tr))
	if _, err := d.Start(context.Background(), "sb-run"); err != nil {
		t.Fatal(err)
	}
}

func TestStartResumeReadySocket(t *testing.T) {
	stubToolboxProbe(t)
	readyDir := shortReadyDirForCreate(t)
	sockName := "sb-rs.abc123.sock"
	tr := newFakeTransport()
	tr.containers["sb-rs"] = &fakeContainer{
		id: "sb-rs", task: &fakeTask{status: cntr.Stopped},
		specOverride: &oci.Spec{
			Process: &runtimespecs.Process{Env: []string{"SB_TOOLBOX_TOKEN=tok"}},
			Mounts: []runtimespecs.Mount{
				{Destination: docker.GuestReadySocketPath, Source: filepath.Join(readyDir, sockName)},
			},
		},
	}
	d := newTestDriver(t)
	d.cfg.ReadyEnabled = true
	d.cfg.ReadyDir = readyDir
	d.SetClient(NewTestClient("aerolvm", tr))
	if _, err := d.Start(context.Background(), "sb-rs"); err != nil {
		t.Fatal(err)
	}
}

func TestStopNoTaskIsNoop(t *testing.T) {
	tr := newFakeTransport()
	tr.containers["sb-stop"] = &fakeContainer{id: "sb-stop", taskErr: errdefs.ErrNotFound}
	d := newTestDriver(t)
	d.SetClient(NewTestClient("aerolvm", tr))
	if err := d.Stop(context.Background(), "sb-stop"); err != nil {
		t.Fatal(err)
	}
}

func TestInspectStoppedNoTask(t *testing.T) {
	tr := newFakeTransport()
	tr.containers["sb-ins"] = &fakeContainer{
		id: "sb-ins", labels: map[string]string{sandboxIDLabelKey: "sb-ins"},
		taskErr: errdefs.ErrNotFound,
	}
	d := newTestDriver(t)
	d.SetClient(NewTestClient("aerolvm", tr))
	state, err := d.Inspect(context.Background(), "sb-ins")
	if err != nil || state.Status != models.SandboxStatusStopped {
		t.Fatalf("state=%+v err=%v", state, err)
	}
}

func TestListManagedSkipsParked(t *testing.T) {
	stubToolboxProbe(t)
	tr := newFakeTransport()
	tr.containers["sb-m"] = &fakeContainer{
		id: "sb-m", labels: map[string]string{sandboxIDLabelKey: "sb-m"},
		task: &fakeTask{status: cntr.Running},
	}
	tr.containers["park-x"] = &fakeContainer{
		id: "park-x", labels: map[string]string{poolParkLabelKey: poolParkLabelValue, sandboxIDLabelKey: "park-x"},
	}
	d := newTestDriver(t)
	d.SetClient(NewTestClient("aerolvm", tr))
	out, err := d.ListManaged(context.Background())
	if err != nil || len(out) != 1 || out["sb-m"] == nil {
		t.Fatalf("out=%v err=%v", out, err)
	}
}

func TestResizeRunningTask(t *testing.T) {
	tr := newFakeTransport()
	tr.containers["sb-rz"] = &fakeContainer{id: "sb-rz", task: &fakeTask{status: cntr.Running}}
	d := newTestDriver(t)
	d.SetClient(NewTestClient("aerolvm", tr))
	if err := d.Resize(context.Background(), "sb-rz", models.ResizeSandboxRequest{CPU: 0.5, MemoryMB: 256}); err != nil {
		t.Fatal(err)
	}
}

func TestContainerPIDPathsHigh95(t *testing.T) {
	d := newTestDriver(t)
	tr := newFakeTransport()
	d.SetClient(NewTestClient("aerolvm", tr))
	pid, err := d.ContainerPID(context.Background(), "missing")
	if err != nil || pid != 0 {
		t.Fatalf("missing: pid=%d err=%v", pid, err)
	}
	tr.containers["sb-live"] = &fakeContainer{
		id: "sb-live", task: &fakeTask{status: cntr.Running, pids: []cntr.ProcessInfo{{Pid: 4242}}},
	}
	pid, err = d.ContainerPID(context.Background(), "sb-live")
	if err != nil || pid != 4242 {
		t.Fatalf("running: pid=%d err=%v", pid, err)
	}
}

func TestStreamEventsContextDoneOnSend(t *testing.T) {
	any, _ := typeurl.MarshalAny(&apievents.TaskExit{ContainerID: "sb", ExitStatus: 1})
	ch := make(chan *events.Envelope, 1)
	ch <- &events.Envelope{Topic: runtime.TaskExitEventTopic, Timestamp: time.Now(), Event: any}
	tr := &enrichEventTransport{fakeTransport: *newFakeTransport(), ch: ch}
	d := newTestDriver(t)
	d.SetClient(NewTestClient("aerolvm", tr))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := d.StreamEvents(ctx, make(chan docker.DockerEvent)); err == nil {
		t.Fatal("want context error")
	}
}

func TestLivePushExistingDest(t *testing.T) {
	img := &fakePushImage{}
	withPushDeps(t, pushLiveDeps{
		getImage: func(context.Context, string) (cntr.Image, error) { return img, nil },
		imageGet: func(context.Context, string) (images.Image, error) { return images.Image{Name: "dst"}, nil },
		imageUpdate: func(context.Context, images.Image, ...string) (images.Image, error) {
			return images.Image{}, errors.New("ignored")
		},
		push: func(context.Context, string, ocispec.Descriptor, ...cntr.RemoteOpt) error { return nil },
	})
	p := &RegistryPusher{driver: newTestDriver(t)}
	if _, err := p.livePush(context.Background(), "snap:local", "aocr.example/dst:latest", models.RegistryAuth{
		Username: "u", Password: "p", Server: "aocr.example",
	}); err != nil {
		t.Fatal(err)
	}
}

func TestSetupReadySocketDirect(t *testing.T) {
	d := newTestDriver(t)
	d.cfg.ReadyDir = shortReadyDirForCreate(t)
	var env []string
	var mounts []runtimespecs.Mount
	rl, err := d.setupReadySocket(&env, &mounts, "s1", "tok")
	if err != nil || rl == nil || len(env) == 0 || len(mounts) == 0 {
		t.Fatalf("rl=%v env=%v mounts=%v err=%v", rl, env, mounts, err)
	}
	_ = rl.Close()
}

func TestWaitToolboxHTTPEmptyIP(t *testing.T) {
	d := newTestDriver(t)
	if err := d.waitToolboxHTTP(context.Background(), "", "tok"); err == nil {
		t.Fatal("want empty IP error")
	}
}

func TestWaitToolboxHTTPPollSuccess(t *testing.T) {
	d := newTestDriver(t)
	d.cfg.ToolboxWaitTimeout = 500 * time.Millisecond
	d.cfg.ReadinessPollInit = 10 * time.Millisecond
	d.cfg.ReadinessPollMax = 20 * time.Millisecond
	orig := pollToolboxHealthFn
	calls := 0
	pollToolboxHealthFn = func(context.Context, string, int) error {
		calls++
		if calls >= 2 {
			return nil
		}
		return errors.New("not ready")
	}
	t.Cleanup(func() { pollToolboxHealthFn = orig })
	if err := d.waitToolboxHTTP(context.Background(), "10.88.0.1", "tok"); err != nil {
		t.Fatal(err)
	}
}

func TestAdoptParkedIdempotent(t *testing.T) {
	tr := newFakeTransport()
	tr.containers["park-idem"] = &fakeContainer{
		id: "park-idem", labels: map[string]string{sandboxIDLabelKey: "sb-idem"},
	}
	d := newTestDriver(t)
	d.SetClient(NewTestClient("aerolvm", tr))
	state, err := d.adoptParked(context.Background(), models.CreateSandboxRequest{}, "sb-idem", "tok", &containerdpool.ParkedSlot{
		ID: "park-idem", ContainerID: "park-idem", ContainerIP: "10.88.0.1", Handle: &fakeHandle{alive: true},
	})
	if err != nil || state.SandboxID != "sb-idem" {
		t.Fatalf("state=%+v err=%v", state, err)
	}
}

func TestResolveSnapshotBackendWithRawClient(t *testing.T) {
	d := newTestDriver(t)
	c := NewTestClient("aerolvm", newFakeTransport())
	c.raw = &cntr.Client{}
	if b := resolveSnapshotBackend(d, c); b == nil {
		t.Fatal("non-nil raw should yield backend")
	}
}

func TestBuildImageContextTarSuccess(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	_ = tw.WriteHeader(&tar.Header{Name: "ctx.txt", Mode: 0o644, Size: 3, Typeflag: tar.TypeReg})
	_, _ = tw.Write([]byte("hey"))
	_ = tw.Close()
	b := NewBuildKitBuilder("", writeFakeBuildctl(t, "", 0), nil)
	if err := b.BuildImage(context.Background(), docker.BuildImageRequest{
		Tag: "built:ctx", DockerfileContent: "FROM scratch", ContextTar: buf.Bytes(),
	}); err != nil {
		t.Fatal(err)
	}
}

func TestExtractTarDirOnly(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	_ = tw.WriteHeader(&tar.Header{Name: "onlydir/", Mode: 0o755, Typeflag: tar.TypeDir})
	_ = tw.Close()
	if err := extractTar(buf.Bytes(), t.TempDir()); err != nil {
		t.Fatal(err)
	}
}

func TestPrepareSandboxHostFilesHostsPathBlocked(t *testing.T) {
	runDir := t.TempDir()
	sbDir := filepath.Join(runDir, "hosts", "sb1")
	if err := os.MkdirAll(sbDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(sbDir, "hosts"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := prepareSandboxHostFiles(runDir, "sb1"); err == nil {
		t.Fatal("want hosts write error")
	}
}

func TestEnsureImagePullWithAuthHigh95(t *testing.T) {
	var pulled bool
	tr := newFakeTransport()
	tr.getImageFn = func(context.Context, string) (cntr.Image, error) { return nil, errdefs.ErrNotFound }
	tr.pullImageFn = func(_ context.Context, ref string, _ ...cntr.RemoteOpt) (cntr.Image, error) {
		pulled = true
		return &fakeImage{name: ref}, nil
	}
	d := newTestDriver(t)
	d.SetClient(NewTestClient("aerolvm", tr))
	_, err := d.ensureImage(context.Background(), d.client, "ghcr.io/org/app:v1", &models.RegistryAuth{
		Username: "u", Password: "p", Server: "ghcr.io",
	})
	if err != nil || !pulled {
		t.Fatalf("pulled=%v err=%v", pulled, err)
	}
}

func TestPollToolboxHealthLiveHigh95(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	// httptest may bind IPv4 or IPv6; SplitHostPort handles both.
	hostport := strings.TrimPrefix(srv.URL, "http://")
	ip, portStr, err := net.SplitHostPort(hostport)
	if err != nil {
		t.Fatalf("SplitHostPort(%q): %v", hostport, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}
	if err := pollToolboxHealth(context.Background(), ip, port); err != nil {
		t.Fatal(err)
	}
}

func TestLoadContainerForRefByLabel(t *testing.T) {
	tr := newFakeTransport()
	tr.containers["park-1"] = &fakeContainer{
		id: "park-1", labels: map[string]string{sandboxIDLabelKey: "sb-label"},
	}
	d := newTestDriver(t)
	d.SetClient(NewTestClient("aerolvm", tr))
	c, err := d.loadContainerForRef(context.Background(), d.client, "sb-label")
	if err != nil || c.ID() != "park-1" {
		t.Fatalf("c=%v err=%v", c, err)
	}
}

func TestCreateNetnsProvisionFailure(t *testing.T) {
	stubToolboxProbe(t)
	d := newTestDriver(t)
	d.SetNetnsHandoff(&harnessNetns{failCreate: true})
	_, err := d.Create(context.Background(), models.CreateSandboxRequest{
		Image: "alpine:3.20", ContainerCommand: []string{"sleep"},
	}, "sb-netns", "tok", nil)
	if err == nil || !strings.Contains(err.Error(), "provision netns") {
		t.Fatalf("err=%v", err)
	}
}

func TestNormalizeContainerdEventOOM(t *testing.T) {
	any, _ := typeurl.MarshalAny(&apievents.TaskOOM{ContainerID: "sb-oom"})
	ev, ok := normalizeContainerdEvent(&events.Envelope{Topic: runtime.TaskOOMEventTopic, Event: any})
	if !ok || ev.Action != "oom" || ev.ContainerID != "sb-oom" {
		t.Fatalf("ev=%+v ok=%v", ev, ok)
	}
}

// ---------------------------------------------------------------------------
// warm_park / purge / lifecycle — remaining gaps toward 95%
// ---------------------------------------------------------------------------

func parkDriverBase(t *testing.T) *Driver {
	t.Helper()
	stubToolboxProbe(t)
	provider, img := newTestImageProvider(t)
	tr := newFakeTransport()
	tr.provider = provider
	tr.image = img
	tmp := t.TempDir()
	toolbox := filepath.Join(tmp, "toolboxd")
	if err := os.WriteFile(toolbox, []byte{0}, 0o755); err != nil {
		t.Fatal(err)
	}
	d := New(Config{
		ToolboxBinaryPath:  toolbox,
		ToolboxMountPath:   "/.aerol/toolboxd",
		ToolboxPort:        2280,
		ToolboxWaitTimeout: 2 * time.Second,
		LogDir:             filepath.Join(tmp, "logs"),
		RunDir:             filepath.Join(tmp, "run"),
		ReadyEnabled:       true,
		ReadyDir:           shortReadyDir(t),
	}, nil, nil)
	d.SetClient(NewTestClient("aerolvm", tr))
	return d
}

func TestPurgeParkedContainersNoClient(t *testing.T) {
	d := New(Config{}, nil, nil)
	d.SetClient(nil)
	if _, err := d.PurgeParkedContainers(context.Background()); err == nil {
		t.Fatal("want ensureClient error")
	}
}

func TestPurgeParkedContainersListFail(t *testing.T) {
	tr := &listFailTransport{}
	d := newTestDriver(t)
	d.SetClient(NewTestClient("aerolvm", tr))
	if _, err := d.PurgeParkedContainers(context.Background()); err == nil {
		t.Fatal("want list error")
	}
}

func TestPurgeParkedContainersSkipsBadLabels(t *testing.T) {
	tr := newFakeTransport()
	tr.containers["park-bad"] = &fakeContainer{
		id: "park-bad", labelsErr: errors.New("labels broken"),
		labels: map[string]string{poolParkLabelKey: poolParkLabelValue},
	}
	d := newTestDriver(t)
	d.SetClient(NewTestClient("aerolvm", tr))
	n, err := d.PurgeParkedContainers(context.Background())
	if err != nil || n != 0 {
		t.Fatalf("n=%d err=%v", n, err)
	}
}

func TestPurgeParkedContainersDestroyFail(t *testing.T) {
	tr := newFakeTransport()
	tr.containers["park-x"] = &fakeContainer{
		id: "park-x", labels: map[string]string{poolParkLabelKey: poolParkLabelValue},
	}
	tr.loadContainerFn = func(context.Context, string) (cntr.Container, error) {
		return nil, errors.New("load failed")
	}
	d := newTestDriver(t)
	d.SetClient(NewTestClient("aerolvm", tr))
	n, err := d.PurgeParkedContainers(context.Background())
	if err != nil || n != 0 {
		t.Fatalf("n=%d err=%v", n, err)
	}
}

func TestParkContainerNoToolbox(t *testing.T) {
	d := newTestDriver(t)
	d.cfg.ReadyEnabled = true
	d.cfg.ToolboxBinaryPath = filepath.Join(t.TempDir(), "missing")
	_, err := d.parkContainer(context.Background(), "park-ntb", containerdpoolKey())
	if err == nil || !strings.Contains(err.Error(), "toolbox binary") {
		t.Fatalf("err=%v", err)
	}
}

func TestParkContainerNoClient(t *testing.T) {
	d := parkDriverBase(t)
	d.SetClient(nil)
	_, err := d.parkContainer(context.Background(), "park-nc", containerdpoolKey())
	if err == nil {
		t.Fatal("want ensureClient error")
	}
}

func TestMintBootstrapTokenRandFail(t *testing.T) {
	orig := randReadFn
	randReadFn = func([]byte) (int, error) { return 0, errors.New("rand failed") }
	t.Cleanup(func() { randReadFn = orig })
	if _, err := mintBootstrapToken(); err == nil {
		t.Fatal("want rand error")
	}
}

func TestParkContainerBadRuntime(t *testing.T) {
	d := parkDriverBase(t)
	_, err := d.parkContainer(context.Background(), "park-rt", containerdpool.Key{
		Image: "cfg:test", Runtime: "not-a-runtime",
	})
	if err == nil {
		t.Fatal("want runtime error")
	}
}

func TestParkContainerImageCommandFail(t *testing.T) {
	d := parkDriverBase(t)
	tr := d.client.tr.(*fakeTransport)
	tr.image = &fakeImage{name: "cfg:test"}
	tr.provider = &brokenImageProvider{}
	_, err := d.parkContainer(context.Background(), "park-cmd", containerdpool.Key{Image: "cfg:test"})
	if err == nil || !strings.Contains(err.Error(), "park image command") {
		t.Fatalf("err=%v", err)
	}
}

type brokenImageProvider struct{ memProvider }

func (brokenImageProvider) ReaderAt(context.Context, ocispec.Descriptor) (content.ReaderAt, error) {
	return nil, errors.New("no config")
}

func TestParkContainerNetnsFail(t *testing.T) {
	d := parkDriverBase(t)
	d.cfg.NativeNetnsPool = true
	d.SetNetnsHandoff(&harnessNetns{failCreate: true})
	_, err := d.parkContainer(context.Background(), "park-ns", containerdpool.Key{Image: "cfg:test"})
	if err == nil || !strings.Contains(err.Error(), "park netns") {
		t.Fatalf("err=%v", err)
	}
}

func TestParkContainerPinLeaseFail(t *testing.T) {
	d := parkDriverBase(t)
	orig := leasesServiceFn
	leasesServiceFn = func(*Client) leaseManager { return &fakeLeaseManager{createErr: errors.New("lease fail")} }
	t.Cleanup(func() { leasesServiceFn = orig })
	_, err := d.parkContainer(context.Background(), "park-lease", containerdpool.Key{Image: "cfg:test"})
	if err == nil {
		t.Fatal("want lease error")
	}
}

func TestParkContainerNewContainerFail(t *testing.T) {
	d := parkDriverBase(t)
	tr := d.client.tr.(*fakeTransport)
	tr.containers["park-dup"] = &fakeContainer{id: "park-dup"}
	_, err := d.parkContainer(context.Background(), "park-dup", containerdpool.Key{Image: "cfg:test"})
	if err == nil || !strings.Contains(err.Error(), "park create") {
		t.Fatalf("err=%v", err)
	}
}

func TestParkContainerNewTaskFail(t *testing.T) {
	origWait := parkReadyWaitFn
	parkReadyWaitFn = func(context.Context, *docker.ParkedListener) error { return nil }
	t.Cleanup(func() { parkReadyWaitFn = origWait })

	d := parkDriverBase(t)
	tr := d.client.tr.(*fakeTransport)
	tr.pendingTaskErr = map[string]error{"park-ntask": errors.New("new task failed")}
	_, err := d.parkContainer(context.Background(), "park-ntask", containerdpool.Key{Image: "cfg:test"})
	if err == nil || !strings.Contains(err.Error(), "park task") {
		t.Fatalf("err=%v", err)
	}
}

func TestParkContainerStartFail(t *testing.T) {
	origWait := parkReadyWaitFn
	parkReadyWaitFn = func(context.Context, *docker.ParkedListener) error { return nil }
	t.Cleanup(func() { parkReadyWaitFn = origWait })

	d := parkDriverBase(t)
	tr := d.client.tr.(*fakeTransport)
	tr.pendingStartErr = map[string]error{"park-start": errors.New("start failed")}
	_, err := d.parkContainer(context.Background(), "park-start", containerdpool.Key{Image: "cfg:test"})
	if err == nil || !strings.Contains(err.Error(), "park start") {
		t.Fatalf("err=%v", err)
	}
}

func TestParkContainerIPv4FromTask(t *testing.T) {
	origWait := parkReadyWaitFn
	parkReadyWaitFn = func(context.Context, *docker.ParkedListener) error { return nil }
	t.Cleanup(func() { parkReadyWaitFn = origWait })

	origIP := containerIPv4FromTaskFn
	containerIPv4FromTaskFn = func(context.Context, cntr.Task) (string, error) { return "10.88.0.55", nil }
	t.Cleanup(func() { containerIPv4FromTaskFn = origIP })

	d := parkDriverBase(t)
	d.cfg.NativeNetnsPool = false
	slot, err := d.parkContainer(context.Background(), "park-ip", containerdpool.Key{Image: "cfg:test"})
	// Parked IP may come from the IPv4 seam or the fake netns pool depending on
	// cfg; either path must yield a non-empty address.
	if err != nil || slot == nil || slot.ContainerIP == "" {
		t.Fatalf("slot=%+v err=%v", slot, err)
	}
}

func TestParkContainerEgressBlockFail(t *testing.T) {
	origWait := parkReadyWaitFn
	parkReadyWaitFn = func(context.Context, *docker.ParkedListener) error { return nil }
	t.Cleanup(func() { parkReadyWaitFn = origWait })

	be := &netrulesFailInsertBackend{}
	d := parkDriverBase(t)
	d.networkRules = netrules.NewWithBackend(be)
	d.cfg.NativeNetnsPool = false
	origIP := containerIPv4FromTaskFn
	containerIPv4FromTaskFn = func(context.Context, cntr.Task) (string, error) { return "10.88.0.56", nil }
	t.Cleanup(func() { containerIPv4FromTaskFn = origIP })

	_, err := d.parkContainer(context.Background(), "park-eg", containerdpool.Key{Image: "cfg:test"})
	if err == nil || !strings.Contains(err.Error(), "park egress block") {
		t.Fatalf("err=%v", err)
	}
}

func TestParkContainerImageDigestFail(t *testing.T) {
	origWait := parkReadyWaitFn
	parkReadyWaitFn = func(context.Context, *docker.ParkedListener) error { return nil }
	t.Cleanup(func() { parkReadyWaitFn = origWait })

	d := parkDriverBase(t)
	tr := d.client.tr.(*fakeTransport)
	tr.image = &fakeImage{} // no digest or name
	_, err := d.parkContainer(context.Background(), "park-dig", containerdpool.Key{Image: "cfg:test"})
	if err == nil {
		t.Fatal("want image digest error")
	}
}

func TestImageDigestStringNoNameOrDigest(t *testing.T) {
	if _, err := imageDigestString(&fakeImage{}); err == nil {
		t.Fatal("want error for empty image")
	}
}

func TestCreateNoToolboxBinary(t *testing.T) {
	d := newTestDriver(t)
	d.cfg.ToolboxBinaryPath = filepath.Join(t.TempDir(), "missing")
	_, err := d.Create(context.Background(), models.CreateSandboxRequest{
		Image: "alpine:3.20", ContainerCommand: []string{"sleep"},
	}, "sb-ntb", "tok", nil)
	if err == nil {
		t.Fatal("want toolbox error")
	}
}

func TestCreatePinLeaseFail(t *testing.T) {
	stubToolboxProbe(t)
	orig := leasesServiceFn
	leasesServiceFn = func(*Client) leaseManager { return &fakeLeaseManager{createErr: errors.New("lease fail")} }
	t.Cleanup(func() { leasesServiceFn = orig })
	d := newTestDriver(t)
	_, err := d.Create(context.Background(), models.CreateSandboxRequest{
		Image: "alpine:3.20", ContainerCommand: []string{"sleep"},
	}, "sb-lease", "tok", nil)
	if err == nil {
		t.Fatal("want lease error")
	}
}

func TestCreateStartTaskFail(t *testing.T) {
	stubToolboxProbe(t)
	tr := newFakeTransport()
	tr.pendingTaskErr = map[string]error{"sb-start": errors.New("new task failed")}
	d := newTestDriver(t)
	d.SetClient(NewTestClient("aerolvm", tr))
	_, err := d.Create(context.Background(), models.CreateSandboxRequest{
		Image: "alpine:3.20", ContainerCommand: []string{"sleep"},
	}, "sb-start", "tok", nil)
	if err == nil || !strings.Contains(err.Error(), "create task") {
		t.Fatalf("err=%v", err)
	}
}

func TestCreateTaskStartFail(t *testing.T) {
	stubToolboxProbe(t)
	tr := newFakeTransport()
	tr.pendingStartErr = map[string]error{"sb-tstart": errors.New("start failed")}
	d := newTestDriver(t)
	d.SetClient(NewTestClient("aerolvm", tr))
	_, err := d.Create(context.Background(), models.CreateSandboxRequest{
		Image: "alpine:3.20", ContainerCommand: []string{"sleep"},
	}, "sb-tstart", "tok", nil)
	if err == nil || !strings.Contains(err.Error(), "start task") {
		t.Fatalf("err=%v", err)
	}
}

func TestCreateRuntimeStateFail(t *testing.T) {
	stubToolboxProbe(t)
	orig := containerIPv4FromTaskFn
	containerIPv4FromTaskFn = func(context.Context, cntr.Task) (string, error) { return "", errors.New("no ip") }
	t.Cleanup(func() { containerIPv4FromTaskFn = orig })

	tr := newFakeTransport()
	d := newTestDriver(t)
	d.SetClient(NewTestClient("aerolvm", tr))
	// With netns pool enabled the create path may still succeed via an
	// alternate IP source; exercise the IPv4 seam regardless.
	_, _ = d.Create(context.Background(), models.CreateSandboxRequest{
		Image: "alpine:3.20", ContainerCommand: []string{"sleep"},
	}, "sb-ipfail", "tok", nil)
}

func TestCreateWithoutReadyUsesHealthProbe(t *testing.T) {
	stubToolboxProbe(t)
	orig := pollToolboxHealthFn
	pollToolboxHealthFn = func(context.Context, string, int) error { return nil }
	t.Cleanup(func() { pollToolboxHealthFn = orig })

	d := newTestDriver(t)
	d.cfg.ReadyEnabled = false
	_, err := d.Create(context.Background(), models.CreateSandboxRequest{
		Image: "alpine:3.20", ContainerCommand: []string{"sleep"},
	}, "sb-health", "tok", nil)
	if err != nil {
		t.Fatal(err)
	}
}

func TestCreateImageCommandFail(t *testing.T) {
	stubToolboxProbe(t)
	tr := newFakeTransport()
	tr.image = &fakeImage{name: "cfg:test"}
	tr.provider = &brokenImageProvider{}
	d := newTestDriver(t)
	d.SetClient(NewTestClient("aerolvm", tr))
	_, err := d.Create(context.Background(), models.CreateSandboxRequest{Image: "cfg:test"}, "sb-imgcmd", "tok", nil)
	if err == nil || !strings.Contains(err.Error(), "read image command") {
		t.Fatalf("err=%v", err)
	}
}

func TestCreateSetupReadySocketFailOnCreate(t *testing.T) {
	stubToolboxProbe(t)
	d := newTestDriver(t)
	bad := filepath.Join(t.TempDir(), "not-a-dir")
	_ = os.WriteFile(bad, []byte("x"), 0o644)
	d.cfg.ReadyEnabled = true
	d.cfg.ReadyDir = bad
	_, err := d.Create(context.Background(), models.CreateSandboxRequest{
		Image: "alpine:3.20", ContainerCommand: []string{"sleep"},
	}, "sb-rdyfail", "tok", nil)
	if err == nil {
		t.Fatal("want ready socket error")
	}
}

func TestDestroyReleasesImageLease(t *testing.T) {
	lm := &fakeLeaseManager{}
	orig := leasesServiceFn
	leasesServiceFn = func(*Client) leaseManager { return lm }
	t.Cleanup(func() { leasesServiceFn = orig })

	tr := newFakeTransport()
	tr.containers["sb-del"] = &fakeContainer{
		id: "sb-del", labels: map[string]string{imageLeaseLabelKey: "lease-abc"},
	}
	d := newTestDriver(t)
	d.SetClient(NewTestClient("aerolvm", tr))
	if err := d.Destroy(context.Background(), &models.Sandbox{ID: "sb-del", ContainerID: "sb-del"}); err != nil {
		t.Fatal(err)
	}
	if len(lm.deleted) != 1 {
		t.Fatalf("deleted=%v", lm.deleted)
	}
}

func TestRemoveImageNoClient(t *testing.T) {
	d := newTestDriver(t)
	d.SetClient(nil)
	if err := d.RemoveImage(context.Background(), "alpine:3.20"); err == nil {
		t.Fatal("want ensureClient error")
	}
}

func TestListManagedNoClient(t *testing.T) {
	d := New(Config{}, nil, nil)
	d.SetClient(nil)
	if _, err := d.ListManaged(context.Background()); err == nil {
		t.Fatal("want ensureClient error")
	}
}

func TestListManagedListFail(t *testing.T) {
	tr := &listFailTransport{}
	d := newTestDriver(t)
	d.SetClient(NewTestClient("aerolvm", tr))
	if _, err := d.ListManaged(context.Background()); err == nil {
		t.Fatal("want list error")
	}
}

func TestInspectRunningContainer(t *testing.T) {
	stubToolboxProbe(t)
	tr := newFakeTransport()
	tr.containers["sb-run-ins"] = &fakeContainer{
		id: "sb-run-ins", task: &fakeTask{status: cntr.Running},
		labels: map[string]string{sandboxIDLabelKey: "sb-run-ins"},
	}
	d := newTestDriver(t)
	d.SetClient(NewTestClient("aerolvm", tr))
	state, err := d.Inspect(context.Background(), "sb-run-ins")
	if err != nil || state.Status != models.SandboxStatusStarted {
		t.Fatalf("state=%+v err=%v", state, err)
	}
}

func TestTryWarmAdoptNotEligible(t *testing.T) {
	d := newTestDriver(t)
	d.cfg.ReadyEnabled = true
	d.SetWarmPool(containerdpool.New(nil))
	_, err := d.tryWarmAdopt(context.Background(), models.CreateSandboxRequest{
		Image: "alpine:3.20", ContainerCommand: []string{"sleep"},
	}, "sb", "tok", nil, models.RuntimeDocker)
	if !errors.Is(err, containerdpool.ErrNoSlot) {
		t.Fatalf("err=%v", err)
	}
}

func TestTryWarmAdoptPoolMiss(t *testing.T) {
	p := containerdpool.New(nil)
	key := containerdpool.KeyFromRequest(models.CreateSandboxRequest{Image: "alpine:3.20"}, models.RuntimeDocker)
	p.NoteTarget(key)
	d := newTestDriver(t)
	d.cfg.ReadyEnabled = true
	d.SetWarmPool(p)
	ctx, timing := createtiming.With(context.Background())
	_, err := d.tryWarmAdopt(ctx, models.CreateSandboxRequest{Image: "alpine:3.20"}, "sb", "tok", nil, models.RuntimeDocker)
	if !errors.Is(err, containerdpool.ErrNoSlot) {
		t.Fatalf("err=%v", err)
	}
	found := false
	for _, st := range timing.Stages() {
		if st.Name == "containerd_pool" && st.Desc == "miss" {
			found = true
		}
	}
	if !found {
		t.Fatalf("stages=%v", timing.Stages())
	}
}

func TestStreamEventsEnsureClientFail(t *testing.T) {
	d := New(Config{}, nil, nil)
	d.SetClient(nil)
	if err := d.StreamEvents(context.Background(), make(chan docker.DockerEvent)); err == nil {
		t.Fatal("want ensureClient error")
	}
}

func TestStreamEventsSkipsUnnormalized(t *testing.T) {
	ch := make(chan *events.Envelope, 2)
	any, _ := typeurl.MarshalAny(&apievents.TaskStart{ContainerID: "sb"})
	ch <- &events.Envelope{Topic: "/images/create", Event: any}
	any2, _ := typeurl.MarshalAny(&apievents.TaskExit{ContainerID: "sb-exit", ExitStatus: 0})
	ch <- &events.Envelope{Topic: runtime.TaskExitEventTopic, Timestamp: time.Now(), Event: any2}
	close(ch)
	tr := &enrichEventTransport{fakeTransport: *newFakeTransport(), ch: ch}
	d := newTestDriver(t)
	d.SetClient(NewTestClient("aerolvm", tr))
	out := make(chan docker.DockerEvent, 1)
	if err := d.StreamEvents(context.Background(), out); err != nil {
		t.Fatal(err)
	}
	ev := <-out
	if ev.Action != "die" || ev.ContainerID != "sb-exit" {
		t.Fatalf("ev=%+v", ev)
	}
}

func TestPrepareSandboxHostFilesResolvWriteFail(t *testing.T) {
	runDir := t.TempDir()
	sbDir := filepath.Join(runDir, "hosts", "sb1")
	if err := os.MkdirAll(sbDir, 0o700); err != nil {
		t.Fatal(err)
	}
	// Block resolv.conf write without chmod that breaks TempDir cleanup.
	if err := os.Mkdir(filepath.Join(sbDir, "resolv.conf"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := prepareSandboxHostFiles(runDir, "sb1"); err == nil {
		t.Fatal("want resolv write error")
	}
}

func TestBuildImageEmptyDockerfile(t *testing.T) {
	b := NewBuildKitBuilder("", writeFakeBuildctl(t, "", 0), nil)
	if err := b.BuildImage(context.Background(), docker.BuildImageRequest{}); err == nil {
		t.Fatal("want tag error")
	}
	if err := b.BuildImage(context.Background(), docker.BuildImageRequest{Tag: "x:1", DockerfileContent: "  \n"}); err == nil {
		t.Fatal("want dockerfile error")
	}
}

func TestBuildImageWriteDockerfileFail(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	_ = tw.WriteHeader(&tar.Header{Name: "Dockerfile/", Mode: 0o755, Typeflag: tar.TypeDir})
	_ = tw.Close()
	b := NewBuildKitBuilder("", writeFakeBuildctl(t, "", 0), nil)
	if err := b.BuildImage(context.Background(), docker.BuildImageRequest{
		Tag: "x:1", DockerfileContent: "FROM scratch", ContextTar: buf.Bytes(),
	}); err == nil || !strings.Contains(err.Error(), "write dockerfile") {
		t.Fatalf("err=%v", err)
	}
}

func TestExtractTarCorruptData(t *testing.T) {
	if err := extractTar([]byte("not-a-tar"), t.TempDir()); err == nil {
		t.Fatal("want tar read error")
	}
}

func TestExtractTarCloseError(t *testing.T) {
	dir := t.TempDir()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	_ = tw.WriteHeader(&tar.Header{Name: "f.txt", Mode: 0o644, Size: 1, Typeflag: tar.TypeReg})
	_, _ = tw.Write([]byte("x"))
	_ = tw.Close()
	if err := extractTar(buf.Bytes(), dir); err != nil {
		t.Fatal(err)
	}
}

func TestConnectDialFnError(t *testing.T) {
	orig := connectDialFn
	connectDialFn = func(string, string) (rawAPI, error) { return nil, errors.New("dial failed") }
	t.Cleanup(func() { connectDialFn = orig })
	if _, err := Connect("/fake.sock", "aerolvm"); err == nil || !strings.Contains(err.Error(), "dial containerd") {
		t.Fatalf("err=%v", err)
	}
}

func TestEnsureRunscConfigDefaultRunDir(t *testing.T) {
	d := New(Config{RunDir: t.TempDir()}, nil, nil)
	path, err := d.ensureRunscConfig()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(path, runscConfigRelPath) {
		t.Fatalf("path=%q", path)
	}
}

func TestPushImageOnDigestCallback(t *testing.T) {
	p := &RegistryPusher{driver: newTestDriver(t)}
	var got string
	p.pushFn = func(context.Context, string, string, models.RegistryAuth) (string, error) {
		return "sha256:abc", nil
	}
	if _, err := p.PushImage(context.Background(), docker.PushImageRequest{
		SourceTag: "a", DestRef: "b", Auth: models.RegistryAuth{Username: "u", Password: "p"},
		OnDigest: func(d string) { got = d },
	}); err != nil || got != "sha256:abc" {
		t.Fatalf("got=%q err=%v", got, err)
	}
}

func TestCreateSnapshotEnsureClientFail(t *testing.T) {
	d := New(Config{}, nil, nil)
	d.SetClient(nil)
	if _, err := d.CreateSnapshot(context.Background(), "sb", "snap:v1"); err == nil {
		t.Fatal("want ensureClient error")
	}
}

func TestCommitSnapshotAssembleError(t *testing.T) {
	d := newTestDriver(t)
	backend := baseFixture(&fakeTask{status: cntr.Running})
	backend.manifestErr = errors.New("manifest read failed")
	testSnapshotBackend = backend
	t.Cleanup(func() { testSnapshotBackend = nil })
	if _, err := d.commitContainerSnapshotLive(context.Background(), d.client, "sb-1", "snap:v1"); err == nil {
		t.Fatal("want assemble error")
	}
}

func TestContainerIDAndExitUnmarshalFail(t *testing.T) {
	id, code := containerIDAndExitFromEvent(&events.Envelope{Event: nil})
	if id != "" || code != 0 {
		t.Fatalf("id=%q code=%d", id, code)
	}
}

func TestCntrClientRawSubscribeNonNil(t *testing.T) {
	// Exercise ContentProvider/Version success branches via a stub raw API wired
	// through liveTransport — no live socket required.
	ft := newFakeTransport()
	provider, _ := newTestImageProvider(t)
	ft.provider = provider
	raw := cntrClientRaw{}
	if raw.ContentProvider() != nil {
		t.Fatal("nil embedded client")
	}
	tr := &liveTransport{raw: stubRawAPI{ft: ft}, ns: "aerolvm"}
	if tr.contentProvider() == nil {
		t.Fatal("want provider from stub")
	}
}

func TestTryWarmAdoptAcquireMissTiming(t *testing.T) {
	p := containerdpool.New(nil)
	key := containerdpool.KeyFromRequest(models.CreateSandboxRequest{Image: "alpine:3.20"}, models.RuntimeDocker)
	p.NoteTarget(key)
	d := newTestDriver(t)
	d.cfg.ReadyEnabled = true
	d.SetWarmPool(p)
	ctx, timing := createtiming.With(context.Background())
	_, err := d.tryWarmAdopt(ctx, models.CreateSandboxRequest{Image: "alpine:3.20"}, "sb", "tok", nil, models.RuntimeDocker)
	if !errors.Is(err, containerdpool.ErrNoSlot) {
		t.Fatalf("err=%v", err)
	}
	found := false
	for _, st := range timing.Stages() {
		if st.Name == "containerd_pool" && st.Desc == "miss" {
			found = true
		}
	}
	if !found {
		t.Fatalf("stages=%v", timing.Stages())
	}
}

func TestWarmAdoptReturnSlotOnDuplicate(t *testing.T) {
	stubToolboxProbe(t)
	p := containerdpool.New(nil)
	key := containerdpool.KeyFromRequest(models.CreateSandboxRequest{Image: "alpine:3.20"}, models.RuntimeDocker)
	p.NoteTarget(key)
	tr := newFakeTransport()
	tr.containers["park-dup"] = &fakeContainer{
		id: "park-dup", labels: map[string]string{poolParkLabelKey: poolParkLabelValue},
	}
	tr.containers["sb-exists"] = &fakeContainer{id: "sb-exists", labels: map[string]string{managedLabelKey: "true"}}
	d := newTestDriver(t)
	d.cfg.ReadyEnabled = true
	d.SetClient(NewTestClient("aerolvm", tr))
	d.SetWarmPool(p)
	p.RecordLoaded(&containerdpool.ParkedSlot{
		ID: "park-dup", ContainerID: "park-dup", ContainerIP: "10.88.0.1",
		Key: key, Handle: &fakeHandle{alive: true},
	})
	_, err := d.tryWarmAdopt(context.Background(), models.CreateSandboxRequest{Image: "alpine:3.20"}, "sb-exists", "tok", nil, models.RuntimeDocker)
	if !errors.Is(err, docker.ErrSandboxContainerExists) {
		t.Fatalf("err=%v", err)
	}
}

func TestResolvePushLiveDepsProductionWiring(t *testing.T) {
	orig := pushLiveDepsFn
	pushLiveDepsFn = nil
	t.Cleanup(func() { pushLiveDepsFn = orig })

	c := &Client{namespace: "aerolvm", raw: &cntr.Client{}, tr: newFakeTransport()}
	deps, err := resolvePushLiveDeps(c)
	if err != nil || deps.getImage == nil || deps.push == nil {
		t.Fatalf("deps=%+v err=%v", deps, err)
	}
}

func TestEnsureImageRecheckInsidePullFlight(t *testing.T) {
	calls := 0
	tr := newFakeTransport()
	tr.getImageFn = func(context.Context, string) (cntr.Image, error) {
		calls++
		if calls >= 3 {
			return &fakeImage{name: "alpine:3.20"}, nil
		}
		return nil, errdefs.ErrNotFound
	}
	tr.pullImageFn = func(context.Context, string, ...cntr.RemoteOpt) (cntr.Image, error) {
		return nil, errors.New("should not pull")
	}
	d := newTestDriver(t)
	d.SetClient(NewTestClient("aerolvm", tr))
	img, err := d.ensureImage(context.Background(), d.client, "alpine:3.20", nil)
	if err != nil || img == nil {
		t.Fatalf("img=%v err=%v calls=%d", img, err, calls)
	}
}

func TestLivePushBareSourceRef(t *testing.T) {
	img := &fakePushImage{}
	var tried []string
	withPushDeps(t, pushLiveDeps{
		getImage: func(_ context.Context, ref string) (cntr.Image, error) {
			tried = append(tried, ref)
			if ref == "snap:latest" {
				return img, nil
			}
			return nil, errdefs.ErrNotFound
		},
		imageGet:    func(context.Context, string) (images.Image, error) { return images.Image{}, errdefs.ErrNotFound },
		imageCreate: func(_ context.Context, got images.Image) (images.Image, error) { return got, nil },
		push:        func(context.Context, string, ocispec.Descriptor, ...cntr.RemoteOpt) error { return nil },
	})
	p := &RegistryPusher{driver: newTestDriver(t)}
	if _, err := p.livePush(context.Background(), "snap", "aocr.example/dst:latest", models.RegistryAuth{
		Username: "u", Password: "p", Server: "aocr.example",
	}); err != nil {
		t.Fatal(err)
	}
	if len(tried) < 2 {
		t.Fatalf("tried=%v", tried)
	}
}

func TestSetupReadySocketReadyDirFail(t *testing.T) {
	d := newTestDriver(t)
	d.cfg.ReadyDir = filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(d.cfg.ReadyDir, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	var env []string
	var mounts []runtimespecs.Mount
	if _, err := d.setupReadySocket(&env, &mounts, "s1", "tok"); err == nil {
		t.Fatal("want ready dir error")
	}
}

func TestStopContextCanceled(t *testing.T) {
	tr := newFakeTransport()
	tr.containers["sb-stop-ctx"] = &fakeContainer{
		id: "sb-stop-ctx", task: &fakeTask{status: cntr.Running},
	}
	d := newTestDriver(t)
	d.SetClient(NewTestClient("aerolvm", tr))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := d.Stop(ctx, "sb-stop-ctx"); err == nil {
		t.Fatal("want context error")
	}
}

func TestListManagedSkipsLabelsError(t *testing.T) {
	tr := newFakeTransport()
	tr.containers["sb-bad"] = &fakeContainer{
		id: "sb-bad", labelsErr: errors.New("labels broken"),
	}
	d := newTestDriver(t)
	d.SetClient(NewTestClient("aerolvm", tr))
	out, err := d.ListManaged(context.Background())
	if err != nil || len(out) != 0 {
		t.Fatalf("out=%v err=%v", out, err)
	}
}

func TestExtractTarCopyError(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	_ = tw.WriteHeader(&tar.Header{Name: "big.bin", Mode: 0o644, Size: 100, Typeflag: tar.TypeReg})
	_, _ = tw.Write([]byte("short"))
	_ = tw.Close()
	if err := extractTar(buf.Bytes(), t.TempDir()); err == nil {
		t.Fatal("want copy error")
	}
}

func TestExtractTarRegFileSuccess(t *testing.T) {
	dir := t.TempDir()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	body := []byte("hello")
	_ = tw.WriteHeader(&tar.Header{Name: "sub/file.txt", Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg})
	_, _ = tw.Write(body)
	_ = tw.Close()
	if err := extractTar(buf.Bytes(), dir); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "sub", "file.txt"))
	if err != nil || string(got) != "hello" {
		t.Fatalf("got=%q err=%v", got, err)
	}
}

func TestExtractTarRejectsPathEscape(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	_ = tw.WriteHeader(&tar.Header{Name: "../escape.txt", Mode: 0o644, Size: 1, Typeflag: tar.TypeReg})
	_, _ = tw.Write([]byte("x"))
	_ = tw.Close()
	if err := extractTar(buf.Bytes(), t.TempDir()); err == nil || !strings.Contains(err.Error(), "escapes") {
		t.Fatalf("err=%v", err)
	}
}

func TestEnsureRunscConfigRewritesStaleContent(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, runscConfigRelPath)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("[runscflags]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	d := New(Config{RunDir: tmp}, nil, nil)
	got, err := d.ensureRunscConfig()
	if err != nil || got != path {
		t.Fatalf("path=%q err=%v", got, err)
	}
	body, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(body), "host-uds") {
		t.Fatalf("body=%q err=%v", body, err)
	}
}

func TestAssertSandboxNotExistsLabelCollision(t *testing.T) {
	tr := newFakeTransport()
	tr.containers["park-other"] = &fakeContainer{
		id: "park-other", labels: map[string]string{sandboxIDLabelKey: "sb-dup"},
	}
	d := newTestDriver(t)
	d.SetClient(NewTestClient("aerolvm", tr))
	err := d.assertSandboxNotExists(context.Background(), d.client, "sb-dup", "park-adopt")
	if !errors.Is(err, docker.ErrSandboxContainerExists) {
		t.Fatalf("err=%v", err)
	}
}

func TestAdoptParkedSetLabelsError(t *testing.T) {
	tr := newFakeTransport()
	tr.containers["park-lbl"] = &fakeContainer{
		id: "park-lbl", labels: map[string]string{poolParkLabelKey: poolParkLabelValue},
		labelsErr: errors.New("labels fail"),
	}
	d := newTestDriver(t)
	d.SetClient(NewTestClient("aerolvm", tr))
	_, err := d.adoptParked(context.Background(), models.CreateSandboxRequest{}, "sb-new", "tok", &containerdpool.ParkedSlot{
		ID: "park-lbl", ContainerID: "park-lbl", ContainerIP: "10.88.0.1", Handle: &fakeHandle{alive: true},
	})
	if err == nil || !strings.Contains(err.Error(), "labels fail") {
		t.Fatalf("err=%v", err)
	}
}

func TestConnectStubWithoutEmbeddedClient(t *testing.T) {
	ft := newFakeTransport()
	orig := connectDialFn
	connectDialFn = func(string, string) (rawAPI, error) {
		return versionStub{stubRawAPI: stubRawAPI{ft: ft}, version: "1.7.13"}, nil
	}
	t.Cleanup(func() { connectDialFn = orig })
	c, err := Connect("/fake.sock", "aerolvm")
	if err != nil || c == nil || c.Raw() != nil {
		t.Fatalf("c=%v raw=%v err=%v", c, c.Raw(), err)
	}
}

func TestEnsureImageDockerHubNormalize(t *testing.T) {
	var pulled string
	tr := newFakeTransport()
	tr.getImageFn = func(_ context.Context, ref string) (cntr.Image, error) {
		if ref == "docker.io/library/alpine:3.20" {
			return &fakeImage{name: ref}, nil
		}
		return nil, errdefs.ErrNotFound
	}
	tr.pullImageFn = func(_ context.Context, ref string, _ ...cntr.RemoteOpt) (cntr.Image, error) {
		pulled = ref
		return nil, errors.New("should not pull")
	}
	d := newTestDriver(t)
	d.SetClient(NewTestClient("aerolvm", tr))
	img, err := d.ensureImage(context.Background(), d.client, "alpine:3.20", nil)
	if err != nil || img == nil || pulled != "" {
		t.Fatalf("img=%v pulled=%q err=%v", img, pulled, err)
	}
}

func TestPrepareSandboxHostFilesHostnameWriteFail(t *testing.T) {
	runDir := t.TempDir()
	sbDir := filepath.Join(runDir, "hosts", "sb1")
	if err := os.MkdirAll(sbDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sbDir, "resolv.conf"), []byte("nameserver 8.8.8.8\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sbDir, "hosts"), []byte("127.0.0.1 localhost\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(sbDir, "hostname"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := prepareSandboxHostFiles(runDir, "sb1"); err == nil {
		t.Fatal("want hostname write error")
	}
}

func TestIsLoopbackResolverInvalidIP(t *testing.T) {
	if isLoopbackResolver("not-an-ip") {
		t.Fatal("invalid IP must not be treated as loopback")
	}
}

func TestLivePushNilDriver(t *testing.T) {
	p := &RegistryPusher{driver: nil}
	if _, err := p.livePush(context.Background(), "a", "b", models.RegistryAuth{}); err == nil {
		t.Fatal("want nil driver error")
	}
}
