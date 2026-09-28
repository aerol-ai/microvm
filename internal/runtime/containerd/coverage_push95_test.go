package containerd

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	cntr "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/events"
	"github.com/containerd/errdefs"
	"github.com/opencontainers/runtime-spec/specs-go"

	"github.com/aerol-ai/microvm/internal/pool/containerdpool"
	"github.com/aerol-ai/microvm/pkg/createtiming"
	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
)

// coverage_push95_test.go: hit remaining offline-reachable branches to clear 95%.

func TestListManagedInspectFailPush95(t *testing.T) {
	orig := containerIPv4FromTaskFn
	containerIPv4FromTaskFn = func(context.Context, cntr.Task) (string, error) {
		return "", errors.New("no ip")
	}
	t.Cleanup(func() { containerIPv4FromTaskFn = orig })

	tr := newFakeTransport()
	tr.containers["sb-badip"] = &fakeContainer{
		id: "sb-badip", task: &fakeTask{status: cntr.Running},
		labels: map[string]string{sandboxIDLabelKey: "sb-badip"},
	}
	d := newTestDriver(t)
	d.SetClient(NewTestClient("aerolvm", tr))
	got, err := d.ListManaged(context.Background())
	if err != nil || len(got) != 0 {
		t.Fatalf("got=%v err=%v", got, err)
	}
}

func TestStopAlreadyStoppedPush95(t *testing.T) {
	tr := newFakeTransport()
	tr.containers["sb-done"] = &fakeContainer{
		id: "sb-done", task: &fakeTask{status: cntr.Stopped},
	}
	d := newTestDriver(t)
	d.SetClient(NewTestClient("aerolvm", tr))
	if err := d.Stop(context.Background(), "sb-done"); err != nil {
		t.Fatal(err)
	}
}

func TestStartEnsureClientAndFailuresPush95(t *testing.T) {
	t.Run("ensureClient", func(t *testing.T) {
		d := New(Config{}, nil, nil)
		if _, err := d.Start(context.Background(), "sb"); err == nil {
			t.Fatal("want ensureClient error")
		}
	})
	t.Run("taskLogIO", func(t *testing.T) {
		tr := newFakeTransport()
		tr.containers["sb-logio"] = &fakeContainer{
			id: "sb-logio", taskErr: errdefs.ErrNotFound,
		}
		d := newTestDriver(t)
		d.SetClient(NewTestClient("aerolvm", tr))
		logPath := filepath.Join(d.cfg.LogDir, "sb-logio.log")
		if err := os.MkdirAll(logPath, 0o755); err != nil {
			t.Fatal(err)
		}
		if _, err := d.Start(context.Background(), "sb-logio"); err == nil {
			t.Fatal("want taskLogIO error")
		}
	})
	t.Run("startFail", func(t *testing.T) {
		tr := newFakeTransport()
		tr.containers["sb-start"] = &fakeContainer{
			id:      "sb-start",
			taskErr: errdefs.ErrNotFound,
			task:    &fakeTask{status: cntr.Stopped, startErr: errors.New("start boom")},
		}
		d := newTestDriver(t)
		d.SetClient(NewTestClient("aerolvm", tr))
		if _, err := d.Start(context.Background(), "sb-start"); err == nil || !strings.Contains(err.Error(), "start task") {
			t.Fatalf("err=%v", err)
		}
	})
}

func TestDestroyEmptyIDAndNotFoundPush95(t *testing.T) {
	d := newTestDriver(t)
	d.SetClient(NewTestClient("aerolvm", newFakeTransport()))
	if err := d.Destroy(context.Background(), &models.Sandbox{ID: "ghost-sb"}); err != nil {
		t.Fatal(err)
	}
	tr := newFakeTransport()
	tr.containers["sb-x"] = &fakeContainer{id: "sb-x", taskErr: errdefs.ErrNotFound}
	d.SetClient(NewTestClient("aerolvm", tr))
	if err := d.Destroy(context.Background(), &models.Sandbox{ID: "sb-x", ContainerID: ""}); err != nil {
		t.Fatal(err)
	}
}

func TestResizeEnsureClientAndTinyCPUPush95(t *testing.T) {
	d := New(Config{}, nil, nil)
	if err := d.Resize(context.Background(), "sb", models.ResizeSandboxRequest{CPU: 0.001}); err == nil {
		t.Fatal("want ensureClient error")
	}
	tr := newFakeTransport()
	tr.containers["sb-cpu"] = &fakeContainer{
		id: "sb-cpu", task: &fakeTask{status: cntr.Running},
	}
	d = newTestDriver(t)
	d.SetClient(NewTestClient("aerolvm", tr))
	if err := d.Resize(context.Background(), "sb-cpu", models.ResizeSandboxRequest{CPU: 0.001}); err != nil {
		t.Fatal(err)
	}
}

func TestImageExistsEnsureClientPush95(t *testing.T) {
	d := New(Config{}, nil, nil)
	if _, err := d.ImageExists(context.Background(), "alpine:3.20"); err == nil {
		t.Fatal("want ensureClient error")
	}
}

func TestCreateEnsureClientPush95(t *testing.T) {
	stubToolboxProbe(t)
	d := New(Config{
		ToolboxBinaryPath: newTestDriver(t).cfg.ToolboxBinaryPath,
		ToolboxMountPath:  "/.aerol/toolboxd",
		LogDir:            filepath.Join(t.TempDir(), "logs"),
		RunDir:            filepath.Join(t.TempDir(), "run"),
	}, nil, nil)
	if _, err := d.Create(context.Background(), models.CreateSandboxRequest{
		Image: "alpine:3.20", ContainerCommand: []string{"sleep"},
	}, "sb-noclient", "tok", nil); err == nil {
		t.Fatal("want ensureClient error")
	}
}

func TestSetupReadySocketEmptyTokenPush95(t *testing.T) {
	d := newTestDriver(t)
	d.cfg.ReadyDir = t.TempDir()
	var env []string
	var mounts []specs.Mount
	if _, err := d.setupReadySocket(&env, &mounts, "sb1", ""); err == nil {
		t.Fatal("want token error")
	}
}

func TestRecreateResumeReadySocketListenerFailPush95(t *testing.T) {
	d := newTestDriver(t)
	blocked := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(blocked, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	d.cfg.ReadyDir = blocked
	spec := &specs.Spec{
		Process: &specs.Process{Env: []string{"SB_TOOLBOX_TOKEN=tok"}},
		Mounts: []specs.Mount{{
			Destination: docker.GuestReadySocketPath,
			Source:      filepath.Join(blocked, "sb1.nonce123.sock"),
		}},
	}
	if rl := d.recreateResumeReadySocket(spec); rl != nil {
		t.Fatal("want nil when listener create fails")
	}
}

func TestDefaultCreateReadyWaitPush95(t *testing.T) {
	if err := defaultCreateReadyWait(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
}

func TestDefaultParkReadyWaitPush95(t *testing.T) {
	dir := shortReadyDir(t)
	pl, err := docker.NewParkedListener(dir, "p1", "tok", "n0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pl.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := defaultParkReadyWait(ctx, pl); err == nil {
		t.Fatal("want wait timeout/error")
	}
}

func TestWaitToolboxHTTPCancelDuringPollPush95(t *testing.T) {
	d := newTestDriver(t)
	d.cfg.ToolboxWaitTimeout = 2 * time.Second
	d.cfg.ReadinessPollInit = 200 * time.Millisecond
	d.cfg.ReadinessPollMax = 200 * time.Millisecond
	orig := pollToolboxHealthFn
	pollToolboxHealthFn = func(context.Context, string, int) error { return errors.New("down") }
	t.Cleanup(func() { pollToolboxHealthFn = orig })
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(30 * time.Millisecond)
		cancel()
	}()
	if err := d.waitToolboxHTTP(ctx, "10.0.0.1", "tok"); err == nil {
		t.Fatal("want ctx cancel")
	}
}

func TestResourceSpecOptsTinyCPUPush95(t *testing.T) {
	opts := resourceSpecOpts(models.CreateSandboxRequest{CPU: 0.001})
	if len(opts) != 1 {
		t.Fatalf("opts=%d", len(opts))
	}
}

func TestTryWarmAdoptDeadSlotTimingPush95(t *testing.T) {
	p := containerdpool.New(nil)
	req := models.CreateSandboxRequest{Image: "alpine:3.20"}
	key := containerdpool.KeyFromRequest(req, models.RuntimeDocker)
	p.NoteTarget(key)
	p.RecordLoaded(&containerdpool.ParkedSlot{
		ID: "park-dead", ContainerID: "park-dead", ContainerIP: "10.88.0.1",
		Key: key, Handle: &fakeHandle{alive: false},
	})
	d := newTestDriver(t)
	d.cfg.ReadyEnabled = true
	d.SetWarmPool(p)
	ctx, timing := createtiming.With(context.Background())
	_, err := d.tryWarmAdopt(ctx, req, "sb-dead", "tok", nil, models.RuntimeDocker)
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

func TestAdoptParkedEnsureClientPush95(t *testing.T) {
	d := New(Config{}, nil, nil)
	_, err := d.adoptParked(context.Background(), models.CreateSandboxRequest{}, "sb", "tok", &containerdpool.ParkedSlot{
		ID: "p", ContainerID: "p", Handle: &fakeHandle{alive: true},
	})
	if err == nil {
		t.Fatal("want ensureClient error")
	}
}

func TestAssertSandboxNotExistsLoadErrorPush95(t *testing.T) {
	tr := newFakeTransport()
	tr.loadContainerFn = func(context.Context, string) (cntr.Container, error) {
		return nil, errors.New("store unavailable")
	}
	d := newTestDriver(t)
	client := NewTestClient("aerolvm", tr)
	if err := d.assertSandboxNotExists(context.Background(), client, "sb", "park"); err == nil {
		t.Fatal("want load error")
	}
}

func TestDestroyParkedEnsureClientPush95(t *testing.T) {
	d := New(Config{}, nil, nil)
	if err := d.destroyParked(context.Background(), &containerdpool.ParkedSlot{ContainerID: "park-x"}); err == nil {
		t.Fatal("want ensureClient error")
	}
}

func TestContainerPIDEnsureClientPush95(t *testing.T) {
	d := New(Config{}, nil, nil)
	if _, err := d.ContainerPID(context.Background(), "sb"); err == nil {
		t.Fatal("want ensureClient error")
	}
}

func TestContainerPIDTaskNotFoundPush95(t *testing.T) {
	tr := newFakeTransport()
	tr.containers["sb-tnf"] = &fakeContainer{id: "sb-tnf", taskErr: errdefs.ErrNotFound}
	d := newTestDriver(t)
	d.SetClient(NewTestClient("aerolvm", tr))
	pid, err := d.ContainerPID(context.Background(), "sb-tnf")
	if err != nil || pid != 0 {
		t.Fatalf("pid=%d err=%v", pid, err)
	}
}

func TestPollToolboxHealthBadURLPush95(t *testing.T) {
	if err := pollToolboxHealth(context.Background(), "\n", 1); err == nil {
		t.Fatal("want NewRequest error")
	}
}

func TestContainerIDAndExitNilEventPush95(t *testing.T) {
	id, code := containerIDAndExitFromEvent(&events.Envelope{Event: nil})
	if id != "" || code != 0 {
		t.Fatalf("got %q %d", id, code)
	}
}

func TestStreamEventsCtxDonePush95(t *testing.T) {
	d := newTestDriver(t)
	d.SetClient(NewTestClient("aerolvm", newFakeTransport()))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	out := make(chan docker.DockerEvent, 1)
	if err := d.StreamEvents(ctx, out); err == nil {
		t.Fatal("want ctx error")
	}
}

func TestPoolSpawnerNilPush95(t *testing.T) {
	var p *PoolSpawner
	if _, err := p.Park(context.Background(), "park-1", containerdpool.Key{Image: "x"}); err == nil {
		t.Fatal("want nil spawner error")
	}
	if err := p.DestroyParked(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
}

func TestEnsureRunscConfigMkdirFailPush95(t *testing.T) {
	d := newTestDriver(t)
	parent := t.TempDir()
	blocked := filepath.Join(parent, "blocked")
	if err := os.WriteFile(blocked, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	d.cfg.RunDir = filepath.Join(blocked, "run")
	if _, err := d.ensureRunscConfig(); err == nil {
		t.Fatal("want mkdir error")
	}
}

func TestEnsureRunscConfigWriteFailPush95(t *testing.T) {
	d := newTestDriver(t)
	runDir := t.TempDir()
	cfgPath := filepath.Join(runDir, runscConfigRelPath)
	if err := os.MkdirAll(cfgPath, 0o755); err != nil {
		t.Fatal(err)
	}
	d.cfg.RunDir = runDir
	if _, err := d.ensureRunscConfig(); err == nil {
		t.Fatal("want write error")
	}
}

func TestGenerateResolvConfShortLinePush95(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "resolv.conf")
	if err := os.WriteFile(path, []byte("nameserver\nnameserver 1.1.1.1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	body, err := generateResolvConf(path)
	if err != nil || !strings.Contains(body, "1.1.1.1") {
		t.Fatalf("body=%q err=%v", body, err)
	}
}

func TestLeasesServiceFnNilPush95(t *testing.T) {
	if leasesServiceFn(nil) != nil {
		t.Fatal("nil client")
	}
	if leasesServiceFn(NewTestClient("aerolvm", newFakeTransport())) != nil {
		t.Fatal("nil raw")
	}
}

func TestPinImageLeaseRandFailPush95(t *testing.T) {
	origLS := leasesServiceFn
	leasesServiceFn = func(*Client) leaseManager { return &fakeLeaseManager{} }
	t.Cleanup(func() { leasesServiceFn = origLS })
	orig := randReadFn
	randReadFn = func([]byte) (int, error) { return 0, errors.New("rand fail") }
	t.Cleanup(func() { randReadFn = orig })
	d := newTestDriver(t)
	if _, err := d.pinImageLease(context.Background(), NewTestClient("aerolvm", newFakeTransport()), &fakeImage{name: "x"}); err == nil {
		t.Fatal("want rand error")
	}
}

func TestAssertSupportedVersionBadMinorPush95(t *testing.T) {
	if err := assertSupportedContainerdVersion("1.x.0"); err == nil {
		t.Fatal("want bad minor")
	}
}

func TestWithNetworkNamespaceEmptyLinuxPush95(t *testing.T) {
	opt := withNetworkNamespace("/run/netns/x")
	s := &specs.Spec{}
	if err := opt(context.Background(), nil, nil, s); err != nil {
		t.Fatal(err)
	}
	if s.Linux == nil || len(s.Linux.Namespaces) == 0 {
		t.Fatal("want network namespace")
	}
}

func TestRuntimeContainerOptRunscFailPush95(t *testing.T) {
	d := newTestDriver(t)
	blocked := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocked, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	d.cfg.RunDir = filepath.Join(blocked, "run")
	if _, err := d.runtimeContainerOpt("runsc"); err == nil {
		t.Fatal("want runsc config error")
	}
}

func TestExtractTarMkdirAllFailPush95(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "nested"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	_ = tw.WriteHeader(&tar.Header{Name: "nested/f.txt", Mode: 0o644, Size: 2, Typeflag: tar.TypeReg})
	_, _ = tw.Write([]byte("hi"))
	_ = tw.Close()
	if err := extractTar(buf.Bytes(), dir); err == nil {
		t.Fatal("want mkdir error")
	}
}

func TestEnsureImagePullSemCancelPush95(t *testing.T) {
	tr := newFakeTransport()
	tr.getImageFn = func(context.Context, string) (cntr.Image, error) { return nil, errdefs.ErrNotFound }
	tr.pullImageFn = func(context.Context, string, ...cntr.RemoteOpt) (cntr.Image, error) {
		return &fakeImage{name: "alpine:3.20"}, nil
	}
	d := newTestDriver(t)
	d.SetClient(NewTestClient("aerolvm", tr))
	d.pullSem = make(chan struct{}, 1)
	d.pullSem <- struct{}{}
	t.Cleanup(func() { <-d.pullSem })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := d.ensureImage(ctx, d.client, "alpine:3.20", nil); err == nil {
		t.Fatal("want ctx cancel while waiting for pull sem")
	}
}
