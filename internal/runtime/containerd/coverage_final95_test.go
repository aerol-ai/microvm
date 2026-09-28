package containerd

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	cntr "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/errdefs"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/aerol-ai/microvm/internal/pool/containerdpool"
	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/docker/netrules"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts"
	runtimespecs "github.com/opencontainers/runtime-spec/specs-go"
)

// Final push from ~92% → 95%: small, deterministic branches.

func TestInspectBranchesFinal95(t *testing.T) {
	t.Run("ensureClient", func(t *testing.T) {
		d := New(Config{}, nil, nil)
		if _, err := d.Inspect(context.Background(), "sb"); err == nil {
			t.Fatal("want ensureClient error")
		}
	})
	t.Run("loadFail", func(t *testing.T) {
		d := newTestDriver(t)
		d.SetClient(NewTestClient("aerolvm", newFakeTransport()))
		if _, err := d.Inspect(context.Background(), "missing"); err == nil {
			t.Fatal("want load error")
		}
	})
	t.Run("stoppedNoTask", func(t *testing.T) {
		tr := newFakeTransport()
		tr.containers["sb-stop"] = &fakeContainer{
			id: "sb-stop", taskErr: errdefs.ErrNotFound,
			labels: map[string]string{sandboxIDLabelKey: "sb-stop"},
		}
		d := newTestDriver(t)
		d.SetClient(NewTestClient("aerolvm", tr))
		st, err := d.Inspect(context.Background(), "sb-stop")
		if err != nil || st == nil || st.Status != models.SandboxStatusStopped {
			t.Fatalf("st=%+v err=%v", st, err)
		}
	})
}

func TestListManagedBranchesFinal95(t *testing.T) {
	t.Run("ensureClient", func(t *testing.T) {
		d := New(Config{}, nil, nil)
		if _, err := d.ListManaged(context.Background()); err == nil {
			t.Fatal("want ensureClient error")
		}
	})
	t.Run("listsManaged", func(t *testing.T) {
		stubToolboxProbe(t)
		tr := newFakeTransport()
		tr.containers["sb-m"] = &fakeContainer{
			id: "sb-m", labels: map[string]string{managedLabelKey: "true", sandboxIDLabelKey: "sb-m"},
			task: &fakeTask{status: cntr.Running},
		}
		d := newTestDriver(t)
		d.SetClient(NewTestClient("aerolvm", tr))
		got, err := d.ListManaged(context.Background())
		if err != nil || got["sb-m"] == nil {
			t.Fatalf("got=%v err=%v", got, err)
		}
	})
}

func TestSetupReadySocketEnsureDirFail(t *testing.T) {
	stubToolboxProbe(t)
	d := newTestDriver(t)
	file := filepath.Join(t.TempDir(), "blocked")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	d.cfg.ReadyDir = file
	d.cfg.ReadyEnabled = true
	_, err := d.Create(context.Background(), models.CreateSandboxRequest{
		Image: "alpine:3.20", ContainerCommand: []string{"sleep"},
	}, "sb-ready-fail", "tok", nil)
	if err == nil {
		t.Fatal("want ready-dir error from Create")
	}
}

func TestExtractTarPathTraversalAndDir(t *testing.T) {
	dir := t.TempDir()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	_ = tw.WriteHeader(&tar.Header{Name: "../escape", Mode: 0o644, Size: 1, Typeflag: tar.TypeReg})
	_, _ = tw.Write([]byte("x"))
	_ = tw.Close()
	if err := extractTar(buf.Bytes(), dir); err == nil || !strings.Contains(err.Error(), "escapes") {
		t.Fatalf("traversal: %v", err)
	}

	buf.Reset()
	tw = tar.NewWriter(&buf)
	_ = tw.WriteHeader(&tar.Header{Name: "subdir", Mode: 0o755, Typeflag: tar.TypeDir})
	_ = tw.WriteHeader(&tar.Header{Name: "subdir/f.txt", Mode: 0o644, Size: 3, Typeflag: tar.TypeReg})
	_, _ = tw.Write([]byte("abc"))
	_ = tw.Close()
	if err := extractTar(buf.Bytes(), dir); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "subdir", "f.txt"))
	if err != nil || string(got) != "abc" {
		t.Fatalf("got=%q err=%v", got, err)
	}
}

func TestExtractTarWriteFail(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "f.txt"), 0o755); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	_ = tw.WriteHeader(&tar.Header{Name: "f.txt", Mode: 0o644, Size: 1, Typeflag: tar.TypeReg})
	_, _ = tw.Write([]byte("x"))
	_ = tw.Close()
	if err := extractTar(buf.Bytes(), dir); err == nil {
		t.Fatal("want OpenFile error")
	}
}

func TestWaitToolboxHTTPBranchesFinal95(t *testing.T) {
	d := newTestDriver(t)
	d.cfg.ToolboxWaitTimeout = 50 * time.Millisecond
	d.cfg.ReadinessPollInit = time.Millisecond
	d.cfg.ReadinessPollMax = 5 * time.Millisecond

	t.Run("timeout", func(t *testing.T) {
		orig := pollToolboxHealthFn
		pollToolboxHealthFn = func(context.Context, string, int) error { return errors.New("down") }
		t.Cleanup(func() { pollToolboxHealthFn = orig })
		if err := d.waitToolboxHTTP(context.Background(), "10.0.0.1", "tok"); err == nil || !strings.Contains(err.Error(), "did not become ready") {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("ctxCancel", func(t *testing.T) {
		orig := pollToolboxHealthFn
		pollToolboxHealthFn = func(context.Context, string, int) error { return errors.New("down") }
		t.Cleanup(func() { pollToolboxHealthFn = orig })
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		d.cfg.ToolboxWaitTimeout = time.Second
		if err := d.waitToolboxHTTP(ctx, "10.0.0.1", "tok"); err == nil {
			t.Fatal("want ctx error")
		}
	})
	t.Run("success", func(t *testing.T) {
		orig := pollToolboxHealthFn
		pollToolboxHealthFn = func(context.Context, string, int) error { return nil }
		t.Cleanup(func() { pollToolboxHealthFn = orig })
		if err := d.waitToolboxHTTP(context.Background(), "10.0.0.1", "tok"); err != nil {
			t.Fatal(err)
		}
	})
}

func TestStopBranchesFinal95(t *testing.T) {
	t.Run("ensureClient", func(t *testing.T) {
		d := New(Config{}, nil, nil)
		if err := d.Stop(context.Background(), "sb"); err == nil {
			t.Fatal("want ensureClient error")
		}
	})
	t.Run("loadFail", func(t *testing.T) {
		d := newTestDriver(t)
		d.SetClient(NewTestClient("aerolvm", newFakeTransport()))
		if err := d.Stop(context.Background(), "missing"); err == nil {
			t.Fatal("want load error")
		}
	})
	t.Run("noTaskOK", func(t *testing.T) {
		tr := newFakeTransport()
		tr.containers["sb"] = &fakeContainer{id: "sb", taskErr: errdefs.ErrNotFound}
		d := newTestDriver(t)
		d.SetClient(NewTestClient("aerolvm", tr))
		if err := d.Stop(context.Background(), "sb"); err != nil {
			t.Fatal(err)
		}
	})
}

func TestCreateWarmAdoptExistsFinal95(t *testing.T) {
	stubToolboxProbe(t)
	p := containerdpool.New(nil)
	req := models.CreateSandboxRequest{Image: "alpine:3.20"}
	key := containerdpool.KeyFromRequest(req, models.RuntimeDocker)
	p.NoteTarget(key)
	tr := newFakeTransport()
	tr.containers["park-1"] = &fakeContainer{
		id: "park-1", labels: map[string]string{poolParkLabelKey: poolParkLabelValue},
	}
	tr.containers["sb-exists"] = &fakeContainer{id: "sb-exists", labels: map[string]string{managedLabelKey: "true"}}
	d := newTestDriver(t)
	d.cfg.ReadyEnabled = true
	d.cfg.ReadyDir = t.TempDir()
	d.SetClient(NewTestClient("aerolvm", tr))
	d.SetWarmPool(p)
	p.RecordLoaded(&containerdpool.ParkedSlot{
		ID: "park-1", ContainerID: "park-1", ContainerIP: "10.88.0.1",
		Key: key, Handle: &fakeHandle{alive: true},
	})
	_, err := d.tryWarmAdopt(context.Background(), req, "sb-exists", "tok", nil, models.RuntimeDocker)
	if !errors.Is(err, docker.ErrSandboxContainerExists) {
		t.Fatalf("err=%v", err)
	}
}

func TestAssertSandboxNotExistsFinal95(t *testing.T) {
	tr := newFakeTransport()
	tr.containers["sb"] = &fakeContainer{id: "sb"}
	d := newTestDriver(t)
	client := NewTestClient("aerolvm", tr)
	if err := d.assertSandboxNotExists(context.Background(), client, "sb", "other"); !errors.Is(err, docker.ErrSandboxContainerExists) {
		t.Fatalf("err=%v", err)
	}
	client2 := NewTestClient("aerolvm", newFakeTransport())
	if err := d.assertSandboxNotExists(context.Background(), client2, "missing", "adopt"); err != nil {
		t.Fatal(err)
	}
}

func TestRawSnapshotBackendNilRawFinal95(t *testing.T) {
	b := &rawSnapshotBackend{d: newTestDriver(t), client: NewTestClient("aerolvm", newFakeTransport())}
	if _, err := b.createDiff(context.Background(), "k", "overlayfs", nil); err == nil {
		t.Fatal("want live client error")
	}
	if _, err := b.createImage(context.Background(), images.Image{Name: "x"}); err == nil {
		t.Fatal("want live client error")
	}
	if _, err := b.getImage(context.Background(), "x"); err == nil {
		t.Fatal("want live client error")
	}
}

func TestEnsureImagePullFinal95(t *testing.T) {
	tr := newFakeTransport()
	tr.getImageFn = func(_ context.Context, ref string) (cntr.Image, error) {
		return nil, errdefs.ErrNotFound
	}
	pulled := false
	tr.pullImageFn = func(_ context.Context, ref string, _ ...cntr.RemoteOpt) (cntr.Image, error) {
		pulled = true
		return &fakeImage{name: ref}, nil
	}
	d := newTestDriver(t)
	d.SetClient(NewTestClient("aerolvm", tr))
	img, err := d.ensureImage(context.Background(), d.client, "alpine:3.20", nil)
	if err != nil || !pulled || img == nil {
		t.Fatalf("img=%v pulled=%v err=%v", img, pulled, err)
	}
}

func TestCreateValidateRuntimeFailFinal95(t *testing.T) {
	stubToolboxProbe(t)
	d := newTestDriver(t)
	_, err := d.Create(context.Background(), models.CreateSandboxRequest{
		Image: "alpine:3.20", ContainerCommand: []string{"sleep"}, Runtime: "not-a-runtime",
	}, "sb-badrt", "tok", nil)
	if err == nil {
		t.Fatal("want runtime validation error")
	}
}

func TestTaskLogPathFailFinal95(t *testing.T) {
	d := newTestDriver(t)
	d.cfg.LogDir = ""
	if _, err := d.taskLogPath("sb"); err == nil {
		t.Fatal("want log dir error")
	}
	file := filepath.Join(t.TempDir(), "logfile")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	d.cfg.LogDir = file
	if _, err := d.taskLogPath("sb"); err == nil {
		t.Fatal("want mkdir error")
	}
}

func TestCntrClientRawNilFinal95(t *testing.T) {
	raw := cntrClientRaw{}
	if raw.ContentProvider() != nil {
		t.Fatal("nil client ContentProvider")
	}
	if _, err := raw.Version(context.Background()); err == nil {
		t.Fatal("nil client Version")
	}
	ch, errCh := raw.Subscribe(context.Background())
	<-ch
	if err := <-errCh; err == nil {
		t.Fatal("want subscribe error")
	}
}

func TestResolvePushLiveDepsNilRawFinal95(t *testing.T) {
	_, err := resolvePushLiveDeps(NewTestClient("aerolvm", newFakeTransport()))
	if err == nil || !strings.Contains(err.Error(), "live client required") {
		t.Fatalf("err=%v", err)
	}
}

func TestAdoptParkedNetworkPolicyFailFinal95(t *testing.T) {
	tr := newFakeTransport()
	tr.containers["park-net"] = &fakeContainer{
		id: "park-net", labels: map[string]string{poolParkLabelKey: poolParkLabelValue},
	}
	be := &netrulesFailInsertBackend{}
	d := New(Config{}, netrules.NewWithBackend(be), nil)
	d.SetClient(NewTestClient("aerolvm", tr))
	_, err := d.adoptParked(context.Background(), models.CreateSandboxRequest{NetworkBlockAll: true}, "sb-net", "tok", &containerdpool.ParkedSlot{
		ID: "park-net", ContainerID: "park-net", ContainerIP: "10.88.0.5", Handle: &fakeHandle{alive: true},
	})
	if err == nil {
		t.Fatal("want network policy error")
	}
}

type adoptFailHandle struct{}

func (adoptFailHandle) Alive() bool { return true }
func (adoptFailHandle) Adopt(context.Context, string, string, string) error {
	return errors.New("adopt failed")
}
func (adoptFailHandle) Close() error { return nil }

func TestAdoptParkedAdoptFailFinal95(t *testing.T) {
	tr := newFakeTransport()
	tr.containers["park-ad"] = &fakeContainer{
		id: "park-ad", labels: map[string]string{poolParkLabelKey: poolParkLabelValue},
	}
	d := newTestDriver(t)
	d.SetClient(NewTestClient("aerolvm", tr))
	_, err := d.adoptParked(context.Background(), models.CreateSandboxRequest{}, "sb-ad", "tok", &containerdpool.ParkedSlot{
		ID: "park-ad", ContainerID: "park-ad", ContainerIP: "10.88.0.6", Handle: adoptFailHandle{},
	})
	if err == nil || !strings.Contains(err.Error(), "adopt failed") {
		t.Fatalf("err=%v", err)
	}
}

func TestContainerPIDStatusErrorFinal95(t *testing.T) {
	tr := newFakeTransport()
	tr.containers["sb-st"] = &fakeContainer{
		id: "sb-st", task: &fakeTask{status: cntr.Running, statusErr: errors.New("status fail")},
	}
	d := newTestDriver(t)
	d.SetClient(NewTestClient("aerolvm", tr))
	if _, err := d.ContainerPID(context.Background(), "sb-st"); err == nil {
		t.Fatal("want status error")
	}
}

func TestEnsureImageLatestFallbackFinal95(t *testing.T) {
	tr := newFakeTransport()
	tr.getImageFn = func(_ context.Context, ref string) (cntr.Image, error) {
		if ref == "localsnap:latest" {
			return &fakeImage{name: ref}, nil
		}
		return nil, errdefs.ErrNotFound
	}
	d := newTestDriver(t)
	d.SetClient(NewTestClient("aerolvm", tr))
	img, err := d.ensureImage(context.Background(), d.client, "localsnap", nil)
	if err != nil || img == nil {
		t.Fatalf("img=%v err=%v", img, err)
	}
}

func TestBaseManifestAndConfigMissingConfigBlob(t *testing.T) {
	cs, target := seedManifestStore(t)
	var manifest ocispec.Manifest
	if err := json.Unmarshal(cs.blobs[target.Digest], &manifest); err != nil {
		t.Fatal(err)
	}
	delete(cs.blobs, manifest.Config.Digest)
	orig := snapshotContentStoreFn
	snapshotContentStoreFn = func(*Client) content.Store { return cs }
	t.Cleanup(func() { snapshotContentStoreFn = orig })
	b := &rawSnapshotBackend{d: newTestDriver(t), client: NewTestClient("aerolvm", newFakeTransport())}
	if _, _, err := b.baseManifestAndConfig(context.Background(), target); err == nil {
		t.Fatal("want config read error")
	}
}

func TestLivePushDriverEnsureClientFail(t *testing.T) {
	d := New(Config{}, nil, nil)
	d.SetClient(nil)
	p := &RegistryPusher{driver: d}
	if _, err := p.livePush(context.Background(), "a", "b", models.RegistryAuth{Username: "u", Password: "p"}); err == nil {
		t.Fatal("want ensureClient error")
	}
}

func TestCreateWithHostMountsFinal95(t *testing.T) {
	stubToolboxProbe(t)
	d := newTestDriver(t)
	hostPath := filepath.Join(t.TempDir(), "data")
	if err := os.MkdirAll(hostPath, 0o755); err != nil {
		t.Fatal(err)
	}
	_, err := d.Create(context.Background(), models.CreateSandboxRequest{
		Image: "alpine:3.20", ContainerCommand: []string{"sleep"},
	}, "sb-mounts", "tok", []mounts.ContainerBind{
		{HostPath: hostPath, ContainerPath: "/data", ReadOnly: true},
		{HostPath: hostPath, ContainerPath: "/data-rw", ReadOnly: false},
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestResizeMinimumCPUQuotaFinal95(t *testing.T) {
	tr := newFakeTransport()
	tr.containers["sb-q"] = &fakeContainer{id: "sb-q", task: &fakeTask{status: cntr.Running}}
	d := newTestDriver(t)
	d.SetClient(NewTestClient("aerolvm", tr))
	if err := d.Resize(context.Background(), "sb-q", models.ResizeSandboxRequest{CPU: 0.0001}); err != nil {
		t.Fatal(err)
	}
}

func TestResourceSpecOptsMemoryOnlyFinal95(t *testing.T) {
	opts := resourceSpecOpts(models.CreateSandboxRequest{MemoryMB: 128})
	if len(opts) != 1 {
		t.Fatalf("opts=%d", len(opts))
	}
}

func TestWithNetworkNamespaceEmptyFinal95(t *testing.T) {
	opt := withNetworkNamespace("")
	spec := &runtimespecs.Spec{}
	if err := opt(context.Background(), nil, nil, spec); err != nil {
		t.Fatal(err)
	}
	opt = withNetworkNamespace("/run/netns/test")
	spec = &runtimespecs.Spec{Linux: &runtimespecs.Linux{}}
	if err := opt(context.Background(), nil, nil, spec); err != nil {
		t.Fatal(err)
	}
}

func TestAdoptParkedSetLabelsFailFinal95(t *testing.T) {
	tr := newFakeTransport()
	tr.containers["park-sl"] = &fakeContainer{
		id: "park-sl", labels: map[string]string{poolParkLabelKey: poolParkLabelValue},
		setLabelsErr: errors.New("set labels failed"),
	}
	d := newTestDriver(t)
	d.SetClient(NewTestClient("aerolvm", tr))
	_, err := d.adoptParked(context.Background(), models.CreateSandboxRequest{}, "sb-new", "tok", &containerdpool.ParkedSlot{
		ID: "park-sl", ContainerID: "park-sl", ContainerIP: "10.88.0.1",
		Handle: &fakeHandle{alive: true},
	})
	if err == nil || !strings.Contains(err.Error(), "set labels") {
		t.Fatalf("err=%v", err)
	}
}

func TestAdoptParkedReassignNetnsFinal95(t *testing.T) {
	stubToolboxProbe(t)
	tr := newFakeTransport()
	tr.containers["park-ns"] = &fakeContainer{
		id: "park-ns", labels: map[string]string{poolParkLabelKey: poolParkLabelValue},
	}
	d := newTestDriver(t)
	d.SetClient(NewTestClient("aerolvm", tr))
	ns := &harnessNetns{path: "/run/netns/p", ip: "10.88.0.5"}
	d.SetNetnsHandoff(ns)
	state, err := d.adoptParked(context.Background(), models.CreateSandboxRequest{}, "sb-adopt", "tok", &containerdpool.ParkedSlot{
		ID: "park-ns", ContainerID: "park-ns", ContainerIP: "10.88.0.5",
		Handle: &fakeHandle{alive: true},
	})
	if err != nil || state.SandboxID != "sb-adopt" {
		t.Fatalf("state=%+v err=%v", state, err)
	}
}

func TestListManagedSkipsParkSandboxIDFinal95(t *testing.T) {
	stubToolboxProbe(t)
	tr := newFakeTransport()
	tr.containers["sb-parkid"] = &fakeContainer{
		id: "sb-parkid", labels: map[string]string{sandboxIDLabelKey: "park-deadbeef"},
		task: &fakeTask{status: cntr.Running},
	}
	d := newTestDriver(t)
	d.SetClient(NewTestClient("aerolvm", tr))
	got, err := d.ListManaged(context.Background())
	if err != nil || len(got) != 0 {
		t.Fatalf("got=%v err=%v", got, err)
	}
}

func TestSetupReadySocketPathTooLongFinal95(t *testing.T) {
	d := newTestDriver(t)
	d.cfg.ReadyDir = "/tmp/r"
	var env []string
	var mounts []runtimespecs.Mount
	longID := strings.Repeat("s", 80)
	if _, err := d.setupReadySocket(&env, &mounts, longID, "tok"); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("err=%v", err)
	}
}

func TestEnsureImageWithDigestRefFinal95(t *testing.T) {
	tr := newFakeTransport()
	tr.getImageFn = func(_ context.Context, ref string) (cntr.Image, error) {
		if strings.Contains(ref, "@sha256:") {
			return &fakeImage{name: ref}, nil
		}
		return nil, errdefs.ErrNotFound
	}
	d := newTestDriver(t)
	d.SetClient(NewTestClient("aerolvm", tr))
	img, err := d.ensureImage(context.Background(), d.client, "local@sha256:abc", nil)
	if err != nil || img == nil {
		t.Fatalf("img=%v err=%v", img, err)
	}
}

func TestAssertSupportedVersionTooOldFinal95(t *testing.T) {
	if err := assertSupportedContainerdVersion("1.5.0"); err == nil {
		t.Fatal("want unsupported 1.5")
	}
}

func TestConnectTrimWhitespaceFinal95(t *testing.T) {
	orig := connectDialFn
	connectDialFn = func(string, string) (rawAPI, error) {
		return versionStub{stubRawAPI: stubRawAPI{ft: newFakeTransport()}, version: "1.7.13"}, nil
	}
	t.Cleanup(func() { connectDialFn = orig })
	c, err := Connect("  /fake.sock  ", "  aerolvm  ")
	if err != nil || c.Namespace() != "aerolvm" {
		t.Fatalf("c=%v err=%v", c, err)
	}
}

func TestCreateWithEgressPolicyFinal95(t *testing.T) {
	stubToolboxProbe(t)
	be := &netrulesMemBackend{}
	d := New(Config{
		ToolboxBinaryPath: newTestDriver(t).cfg.ToolboxBinaryPath,
		ToolboxMountPath:  "/.aerol/toolboxd", ToolboxPort: 2280,
		ToolboxWaitTimeout: 2 * time.Second,
		LogDir:             filepath.Join(t.TempDir(), "logs"), RunDir: filepath.Join(t.TempDir(), "run"),
	}, netrules.NewWithBackend(be), nil)
	d.SetClient(NewTestClient("aerolvm", newFakeTransport()))
	d.SetNetnsHandoff(&harnessNetns{path: "/run/netns/x", ip: "10.88.0.1"})
	_, err := d.Create(context.Background(), models.CreateSandboxRequest{
		Image: "alpine:3.20", ContainerCommand: []string{"sleep"},
		NetworkAllowOut: []string{"0.0.0.0/0"},
	}, "sb-egress", "tok", nil)
	if err != nil {
		t.Fatal(err)
	}
}

func TestCommitSnapshotStatusErrorNoPauseFinal95(t *testing.T) {
	d := newTestDriver(t)
	backend := baseFixture(&fakeTask{status: cntr.Running, statusErr: errors.New("status fail")})
	testSnapshotBackend = backend
	t.Cleanup(func() { testSnapshotBackend = nil })
	if _, err := d.commitContainerSnapshotLive(context.Background(), d.client, "sb-1", "snap:v1"); err != nil {
		t.Fatal(err)
	}
}

func TestCreateWithoutReadyUsesHTTPProbeFinal95(t *testing.T) {
	stubToolboxProbe(t)
	d := newTestDriver(t)
	d.cfg.ReadyEnabled = false
	_, err := d.Create(context.Background(), models.CreateSandboxRequest{
		Image: "alpine:3.20", ContainerCommand: []string{"sleep"},
	}, "sb-http-ready", "tok", nil)
	if err != nil {
		t.Fatal(err)
	}
}

func TestApplyAdoptNetworkPolicyEgressFailFinal95(t *testing.T) {
	be := &netrulesFailInsertBackend{}
	d := New(Config{}, netrules.NewWithBackend(be), nil)
	err := d.applyAdoptNetworkPolicy("10.88.0.1", models.CreateSandboxRequest{
		NetworkAllowOut: []string{"0.0.0.0/0"},
	})
	if err == nil {
		t.Fatal("want egress error")
	}
}

func TestAssembleCommittedImageMarshalManifestFailFinal95(t *testing.T) {
	backend := baseFixture(&fakeTask{status: cntr.Running})
	backend.manifestErr = errors.New("manifest fail")
	if _, err := assembleCommittedImage(context.Background(), backend, backend.baseManifest.Config, backend.diffDesc, "snap:v1", time.Now().UTC()); err == nil {
		t.Fatal("want manifest error")
	}
}

func TestStopSIGKILLAfterGraceFinal95(t *testing.T) {
	origGrace, origPoll := stopGraceTimeout, stopPollInterval
	stopGraceTimeout = time.Millisecond
	stopPollInterval = time.Millisecond
	t.Cleanup(func() {
		stopGraceTimeout = origGrace
		stopPollInterval = origPoll
	})
	tr := newFakeTransport()
	tr.containers["sb-kill"] = &fakeContainer{
		id: "sb-kill", task: &fakeTask{status: cntr.Running},
	}
	d := newTestDriver(t)
	d.SetClient(NewTestClient("aerolvm", tr))
	if err := d.Stop(context.Background(), "sb-kill"); err != nil {
		t.Fatal(err)
	}
}
