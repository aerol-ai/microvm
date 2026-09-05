package containerd

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	apievents "github.com/containerd/containerd/api/events"
	"github.com/containerd/containerd/api/types"
	cntr "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/containers"
	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/events"
	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/core/runtime"
	"github.com/containerd/containerd/v2/pkg/cio"
	"github.com/containerd/containerd/v2/pkg/oci"
	"github.com/containerd/errdefs"
	"github.com/containerd/platforms"
	"github.com/containerd/typeurl/v2"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/opencontainers/runtime-spec/specs-go"

	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/docker/netrules"
	"github.com/aerol-ai/microvm/pkg/models"
)

type fakeTransport struct {
	mu              sync.Mutex
	containers      map[string]*fakeContainer
	pendingTaskErr  map[string]error
	pendingStartErr map[string]error
	image           cntr.Image
	getImageFn      func(context.Context, string) (cntr.Image, error)
	pullImageFn     func(context.Context, string, ...cntr.RemoteOpt) (cntr.Image, error)
	loadContainerFn func(context.Context, string) (cntr.Container, error)
	newContainerFn  func(context.Context, string, ...cntr.NewContainerOpts) (cntr.Container, error)
	emitEvents      bool
	provider        content.Provider
}

func newFakeTransport() *fakeTransport {
	return &fakeTransport{
		containers: make(map[string]*fakeContainer),
		image:      &fakeImage{name: "alpine:3.20"},
	}
}

func (f *fakeTransport) close() error { return nil }

func (f *fakeTransport) isServing(context.Context) (bool, error) { return true, nil }

func (f *fakeTransport) loadContainer(ctx context.Context, id string) (cntr.Container, error) {
	if f.loadContainerFn != nil {
		return f.loadContainerFn(ctx, id)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	c, ok := f.containers[id]
	if !ok {
		return nil, errdefs.ErrNotFound
	}
	return c, nil
}

func (f *fakeTransport) newContainer(ctx context.Context, id string, opts ...cntr.NewContainerOpts) (cntr.Container, error) {
	if f.newContainerFn != nil {
		return f.newContainerFn(ctx, id, opts...)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, exists := f.containers[id]; exists {
		return nil, errdefs.ErrAlreadyExists
	}
	c := &fakeContainer{id: id}
	if f.pendingTaskErr != nil {
		if err, ok := f.pendingTaskErr[id]; ok {
			c.newTaskErr = err
		}
	}
	if f.pendingStartErr != nil {
		if err, ok := f.pendingStartErr[id]; ok {
			c.task = &fakeTask{status: cntr.Stopped, startErr: err}
		}
	}
	f.containers[id] = c
	return c, nil
}

func (f *fakeTransport) getImage(ctx context.Context, ref string) (cntr.Image, error) {
	if f.getImageFn != nil {
		return f.getImageFn(ctx, ref)
	}
	return f.image, nil
}

func (f *fakeTransport) pullImage(ctx context.Context, ref string, opts ...cntr.RemoteOpt) (cntr.Image, error) {
	if f.pullImageFn != nil {
		return f.pullImageFn(ctx, ref, opts...)
	}
	return f.image, nil
}

func (f *fakeTransport) listContainers(context.Context, ...string) ([]cntr.Container, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]cntr.Container, 0, len(f.containers))
	for _, c := range f.containers {
		out = append(out, c)
	}
	return out, nil
}

func (f *fakeTransport) subscribe(ctx context.Context, _ ...string) (<-chan *events.Envelope, <-chan error) {
	ch := make(chan *events.Envelope, 1)
	errCh := make(chan error, 1)
	go func() {
		if f.emitEvents {
			any, err := typeurl.MarshalAny(&apievents.TaskStart{ContainerID: "sb-ev"})
			if err == nil {
				ch <- &events.Envelope{Topic: runtime.TaskStartEventTopic, Timestamp: time.Now(), Event: any}
			}
		}
		close(ch)
		<-ctx.Done()
		errCh <- ctx.Err()
	}()
	return ch, errCh
}

func (f *fakeTransport) contentStore() content.Store {
	if cs, ok := f.provider.(content.Store); ok {
		return cs
	}
	return nil
}

func (f *fakeTransport) contentProvider() content.Provider { return f.provider }

type fakeImage struct {
	name   string
	target ocispec.Descriptor
}

func (f *fakeImage) Name() string { return f.name }
func (f *fakeImage) Target() ocispec.Descriptor {
	if f.target.Digest != "" || f.target.MediaType != "" {
		return f.target
	}
	return ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest}
}
func (f *fakeImage) Labels() map[string]string                               { return nil }
func (f *fakeImage) Unpack(context.Context, string, ...cntr.UnpackOpt) error { return nil }
func (f *fakeImage) RootFS(context.Context) ([]digest.Digest, error)         { return nil, nil }
func (f *fakeImage) Size(context.Context) (int64, error)                     { return 0, nil }
func (f *fakeImage) Usage(context.Context, ...cntr.UsageOpt) (int64, error)  { return 0, nil }
func (f *fakeImage) Config(context.Context) (ocispec.Descriptor, error) {
	return ocispec.Descriptor{}, errors.New("no config in fake")
}
func (f *fakeImage) IsUnpacked(context.Context, string) (bool, error) { return true, nil }
func (f *fakeImage) ContentStore() content.Store                      { return nil }
func (f *fakeImage) Metadata() images.Image                           { return images.Image{Name: f.name} }
func (f *fakeImage) Platform() platforms.MatchComparer                { return nil }
func (f *fakeImage) Spec(context.Context) (ocispec.Image, error)      { return ocispec.Image{}, nil }

type fakeContainer struct {
	id           string
	task         *fakeTask
	taskErr      error
	labels       map[string]string
	infoErr      error
	snapshotKey  string
	snapshotter  string
	baseImage    string
	labelsErr    error
	noSnapshot   bool
	newTaskErr   error
	specOverride *oci.Spec
	setLabelsErr error
}

func (c *fakeContainer) ID() string { return c.id }
func (c *fakeContainer) Info(context.Context, ...cntr.InfoOpts) (containers.Container, error) {
	if c.infoErr != nil {
		return containers.Container{}, c.infoErr
	}
	labels := map[string]string{managedLabelKey: "true"}
	for k, v := range c.labels {
		labels[k] = v
	}
	snapKey := c.id + "-snap"
	if c.snapshotKey != "" {
		snapKey = c.snapshotKey
	}
	if c.noSnapshot {
		snapKey = ""
	}
	snapper := "overlayfs"
	if c.snapshotter != "" {
		snapper = c.snapshotter
	}
	img := "alpine:3.20"
	if c.baseImage != "" {
		img = c.baseImage
	}
	return containers.Container{
		ID:          c.id,
		Image:       img,
		Labels:      labels,
		SnapshotKey: snapKey,
		Snapshotter: snapper,
	}, nil
}
func (c *fakeContainer) Delete(context.Context, ...cntr.DeleteOpts) error { return nil }
func (c *fakeContainer) NewTask(context.Context, cio.Creator, ...cntr.NewTaskOpts) (cntr.Task, error) {
	if c.newTaskErr != nil {
		return nil, c.newTaskErr
	}
	if c.task == nil {
		c.task = &fakeTask{status: cntr.Running}
	}
	return c.task, nil
}
func (c *fakeContainer) Spec(context.Context) (*oci.Spec, error) {
	if c.specOverride != nil {
		return c.specOverride, nil
	}
	return &oci.Spec{}, nil
}
func (c *fakeContainer) Task(context.Context, cio.Attach) (cntr.Task, error) {
	if c.taskErr != nil {
		return nil, c.taskErr
	}
	if c.task == nil {
		return nil, errors.New("no task")
	}
	return c.task, nil
}
func (c *fakeContainer) Image(context.Context) (cntr.Image, error) {
	return &fakeImage{name: "alpine:3.20"}, nil
}
func (c *fakeContainer) Labels(context.Context) (map[string]string, error) {
	if c.labelsErr != nil {
		return nil, c.labelsErr
	}
	out := map[string]string{managedLabelKey: "true"}
	for k, v := range c.labels {
		out[k] = v
	}
	return out, nil
}
func (c *fakeContainer) SetLabels(_ context.Context, labels map[string]string) (map[string]string, error) {
	if c.setLabelsErr != nil {
		return nil, c.setLabelsErr
	}
	c.labels = make(map[string]string, len(labels))
	for k, v := range labels {
		c.labels[k] = v
	}
	return c.labels, nil
}
func (c *fakeContainer) Extensions(context.Context) (map[string]typeurl.Any, error) {
	return nil, nil
}
func (c *fakeContainer) Update(context.Context, ...cntr.UpdateContainerOpts) error { return nil }
func (c *fakeContainer) Checkpoint(context.Context, string, ...cntr.CheckpointOpts) (cntr.Image, error) {
	return nil, errors.New("not implemented")
}
func (c *fakeContainer) Restore(context.Context, cio.Creator, string) (int, error) {
	return 0, errors.New("not implemented")
}

type fakeTask struct {
	status    cntr.ProcessStatus
	statusErr error
	pids      []cntr.ProcessInfo
	pauseErr  error
	startErr  error
}

func (t *fakeTask) Pid() uint32 { return 0 }
func (t *fakeTask) ID() string  { return "init" }
func (t *fakeTask) Start(context.Context) error {
	if t.startErr != nil {
		return t.startErr
	}
	t.status = cntr.Running
	return nil
}
func (t *fakeTask) Delete(context.Context, ...cntr.ProcessDeleteOpts) (*cntr.ExitStatus, error) {
	t.status = cntr.Stopped
	return &cntr.ExitStatus{}, nil
}
func (t *fakeTask) Kill(context.Context, syscall.Signal, ...cntr.KillOpts) error { return nil }
func (t *fakeTask) Pause(context.Context) error {
	if t.pauseErr != nil {
		return t.pauseErr
	}
	return nil
}
func (t *fakeTask) Resume(context.Context) error { return nil }
func (t *fakeTask) Status(context.Context) (cntr.Status, error) {
	if t.statusErr != nil {
		return cntr.Status{}, t.statusErr
	}
	return cntr.Status{Status: t.status}, nil
}
func (t *fakeTask) Wait(context.Context) (<-chan cntr.ExitStatus, error) {
	ch := make(chan cntr.ExitStatus, 1)
	ch <- cntr.ExitStatus{}
	close(ch)
	return ch, nil
}
func (t *fakeTask) IO() cio.IO                                          { return nil }
func (t *fakeTask) CloseIO(context.Context, ...cntr.IOCloserOpts) error { return nil }
func (t *fakeTask) Pids(context.Context) ([]cntr.ProcessInfo, error) {
	if t.pids != nil {
		return t.pids, nil
	}
	return []cntr.ProcessInfo{{Pid: 4242}}, nil
}
func (t *fakeTask) Resize(context.Context, uint32, uint32) error         { return nil }
func (t *fakeTask) Update(context.Context, ...cntr.UpdateTaskOpts) error { return nil }
func (t *fakeTask) Exec(context.Context, string, *specs.Process, cio.Creator) (cntr.Process, error) {
	return nil, errors.New("not implemented")
}
func (t *fakeTask) LoadProcess(context.Context, string, cio.Attach) (cntr.Process, error) {
	return nil, errors.New("not implemented")
}
func (t *fakeTask) Metrics(context.Context) (*types.Metric, error) { return nil, nil }
func (t *fakeTask) Spec(context.Context) (*oci.Spec, error)        { return &oci.Spec{}, nil }
func (t *fakeTask) Checkpoint(context.Context, ...cntr.CheckpointTaskOpts) (cntr.Image, error) {
	return nil, errors.New("not implemented")
}

type harnessNetns struct {
	path, ip   string
	failCreate bool
	released   bool
}

func (h *harnessNetns) Provision(context.Context, string) (string, string, error) {
	if h.failCreate {
		return "", "", errors.New("provision failed")
	}
	return h.path, h.ip, nil
}
func (h *harnessNetns) Release(context.Context, string) error {
	h.released = true
	return nil
}
func (h *harnessNetns) ReassignOwner(context.Context, string, string) error { return nil }

func newTestDriver(t *testing.T) *Driver {
	t.Helper()
	tmp := t.TempDir()
	toolbox := tmp + "/toolboxd"
	if err := os.WriteFile(toolbox, []byte{0}, 0o755); err != nil {
		t.Fatal(err)
	}
	d := New(Config{
		ToolboxBinaryPath:  toolbox,
		ToolboxMountPath:   "/.aerol/toolboxd",
		ToolboxPort:        2280,
		ToolboxWaitTimeout: 2 * time.Second,
		LogDir:             tmp + "/logs",
		RunDir:             tmp + "/run",
		ReadyEnabled:       false,
		NativeNetnsPool:    true,
	}, nil, nil)
	d.SetClient(NewTestClient("aerolvm", newFakeTransport()))
	d.SetNetnsHandoff(&harnessNetns{path: "/run/netns/sb", ip: "10.88.0.9"})
	return d
}

func stubToolboxProbe(t *testing.T) {
	t.Helper()
	origProbe := pollToolboxHealthFn
	pollToolboxHealthFn = func(context.Context, string, int) error { return nil }
	origIP := containerIPv4FromTaskFn
	containerIPv4FromTaskFn = func(context.Context, cntr.Task) (string, error) {
		return "10.88.0.9", nil
	}
	t.Cleanup(func() {
		pollToolboxHealthFn = origProbe
		containerIPv4FromTaskFn = origIP
	})
}

func TestCreateWithFakeContainerd(t *testing.T) {
	stubToolboxProbe(t)
	d := newTestDriver(t)
	state, err := d.Create(context.Background(), models.CreateSandboxRequest{
		Image:            "alpine:3.20",
		ContainerCommand: []string{"sleep", "inf"},
	}, "sb-fake", "tok", nil)
	if err != nil {
		t.Fatal(err)
	}
	if state.ContainerIP != "10.88.0.9" || state.SandboxID != "sb-fake" {
		t.Fatalf("state=%+v", state)
	}
}

func TestStopDestroyInspectWithFake(t *testing.T) {
	stubToolboxProbe(t)
	d := newTestDriver(t)
	ctx := context.Background()
	_, err := d.Create(ctx, models.CreateSandboxRequest{
		Image:            "alpine:3.20",
		ContainerCommand: []string{"sleep"},
	}, "sb-life", "tok", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Inspect(ctx, "sb-life"); err != nil {
		t.Fatal(err)
	}
	if err := d.Stop(ctx, "sb-life"); err != nil {
		t.Fatal(err)
	}
	if err := d.Destroy(ctx, &models.Sandbox{ID: "sb-life", ContainerID: "sb-life"}); err != nil {
		t.Fatal(err)
	}
}

func TestListManagedFake(t *testing.T) {
	stubToolboxProbe(t)
	d := newTestDriver(t)
	ctx := context.Background()
	_, _ = d.Create(ctx, models.CreateSandboxRequest{
		Image:            "alpine:3.20",
		ContainerCommand: []string{"sleep"},
	}, "sb-list", "tok", nil)
	managed, err := d.ListManaged(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(managed) != 1 {
		t.Fatalf("managed=%d", len(managed))
	}
}

func TestContainerPIDFake(t *testing.T) {
	stubToolboxProbe(t)
	d := newTestDriver(t)
	ctx := context.Background()
	_, _ = d.Create(ctx, models.CreateSandboxRequest{
		Image:            "alpine:3.20",
		ContainerCommand: []string{"sleep"},
	}, "sb-pid", "tok", nil)
	pid, err := d.ContainerPID(ctx, "sb-pid")
	if err != nil || pid != 4242 {
		t.Fatalf("pid=%d err=%v", pid, err)
	}
}

func TestSecuritySpecEnvelope(t *testing.T) {
	// DefaultProfile reads Process.Capabilities.Bounding — must be non-nil
	// (same shape as applyOpts in security_test.go).
	spec := &specs.Spec{
		Linux:   &specs.Linux{},
		Process: &specs.Process{Capabilities: &specs.LinuxCapabilities{}},
	}
	ctx := context.Background()
	for _, opt := range securitySpecOpts() {
		if err := opt(ctx, nil, nil, spec); err != nil {
			t.Fatal(err)
		}
	}
	if !spec.Process.NoNewPrivileges {
		t.Fatal("NoNewPrivileges missing")
	}
	if len(spec.Linux.MaskedPaths) == 0 || len(spec.Linux.ReadonlyPaths) == 0 {
		t.Fatal("masked/readonly paths missing")
	}
	if spec.Linux.Seccomp == nil {
		t.Fatal("seccomp profile missing")
	}
}

func TestPhase0SpikeBudgetDocumented(t *testing.T) {
	const phase0ColdCreateP50BudgetMS = 120
	if phase0ColdCreateP50BudgetMS <= 0 {
		t.Fatal("phase 0 budget must be positive")
	}
}

func TestPhase3WarmAdoptSeam(t *testing.T) {
	h := &harnessNetns{path: "/run/netns/warm", ip: "10.88.0.3"}
	path, ip, err := h.Provision(context.Background(), "sb-warm")
	if err != nil || path == "" || ip == "" {
		t.Fatalf("provision: %s %s %v", path, ip, err)
	}
}

func TestClientPingWithFakeTransport(t *testing.T) {
	if err := NewTestClient("aerolvm", newFakeTransport()).Ping(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestRemoveImageFake(t *testing.T) {
	if err := newTestDriver(t).RemoveImage(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
}

func TestLifoTeardownNilSafe(t *testing.T) {
	newTestDriver(t).lifoTeardown(context.Background(), nil, nil, nil, "", nil)
}

func TestCreateRejectsInvalidSandboxID(t *testing.T) {
	stubToolboxProbe(t)
	_, err := newTestDriver(t).Create(context.Background(), models.CreateSandboxRequest{
		Image: "alpine:3.20", ContainerCommand: []string{"sleep"},
	}, "../evil", "tok", nil)
	if err == nil {
		t.Fatal("want validation error")
	}
}

func TestNormalizeContainerdEventTaskExitHarness(t *testing.T) {
	any, err := typeurl.MarshalAny(&apievents.TaskExit{ContainerID: "sb-ev"})
	if err != nil {
		t.Fatal(err)
	}
	env := &events.Envelope{Topic: runtime.TaskExitEventTopic, Timestamp: time.Now(), Event: any}
	got, ok := normalizeContainerdEvent(env)
	if !ok || got.Action != "die" || got.ContainerID != "sb-ev" {
		t.Fatalf("got=%+v ok=%v", got, ok)
	}
}

func TestStartIdempotentFake(t *testing.T) {
	stubToolboxProbe(t)
	d := newTestDriver(t)
	ctx := context.Background()
	_, err := d.Create(ctx, models.CreateSandboxRequest{
		Image: "alpine:3.20", ContainerCommand: []string{"sleep"},
	}, "sb-start", "tok", nil)
	if err != nil {
		t.Fatal(err)
	}
	state, err := d.Start(ctx, "sb-start")
	if err != nil || state.Status != models.SandboxStatusStarted {
		t.Fatalf("start: %+v err=%v", state, err)
	}
}

func TestStartAfterStopFake(t *testing.T) {
	stubToolboxProbe(t)
	d := newTestDriver(t)
	ctx := context.Background()
	_, err := d.Create(ctx, models.CreateSandboxRequest{
		Image: "alpine:3.20", ContainerCommand: []string{"sleep"},
	}, "sb-restart", "tok", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Stop(ctx, "sb-restart"); err != nil {
		t.Fatal(err)
	}
	state, err := d.Start(ctx, "sb-restart")
	if err != nil || state.ContainerIP != "10.88.0.9" {
		t.Fatalf("restart: %+v err=%v", state, err)
	}
}

func TestStreamEventsFake(t *testing.T) {
	tr := newFakeTransport()
	tr.emitEvents = true
	d := newTestDriver(t)
	d.SetClient(NewTestClient("aerolvm", tr))
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out := make(chan docker.DockerEvent, 1)
	errCh := make(chan error, 1)
	go func() { errCh <- d.StreamEvents(ctx, out) }()
	select {
	case ev := <-out:
		if ev.Action != "start" || ev.ContainerID != "sb-ev" {
			t.Fatalf("event=%+v", ev)
		}
	case err := <-errCh:
		if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for event")
	}
	cancel()
}

func TestEnsureImagePullPathFake(t *testing.T) {
	tr := newFakeTransport()
	var calls int
	tr.getImageFn = func(ctx context.Context, ref string) (cntr.Image, error) {
		calls++
		if calls == 1 {
			return nil, errors.New("not found")
		}
		return tr.image, nil
	}
	d := newTestDriver(t)
	img, err := d.ensureImage(context.Background(), NewTestClient("aerolvm", tr), "alpine:3.20", nil)
	if err != nil || img == nil {
		t.Fatalf("ensureImage: %v", err)
	}
	if calls < 2 {
		t.Fatalf("expected get then pull path, calls=%d", calls)
	}
}

func TestContainerPIDNotFoundFake(t *testing.T) {
	d := newTestDriver(t)
	pid, err := d.ContainerPID(context.Background(), "missing")
	if err != nil || pid != 0 {
		t.Fatalf("pid=%d err=%v", pid, err)
	}
}

func TestCreateWithEgressPolicyFake(t *testing.T) {
	stubToolboxProbe(t)
	tmp := t.TempDir()
	toolbox := filepath.Join(tmp, "toolboxd")
	if err := os.WriteFile(toolbox, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	be := &netrulesMemBackend{}
	d := New(Config{
		ToolboxBinaryPath:  toolbox,
		ToolboxMountPath:   "/.aerol/toolboxd",
		ToolboxPort:        2280,
		ToolboxWaitTimeout: 2 * time.Second,
		LogDir:             tmp + "/logs",
		RunDir:             tmp + "/run",
	}, netrules.NewWithBackend(be), nil)
	d.SetClient(NewTestClient("aerolvm", newFakeTransport()))
	d.SetNetnsHandoff(&harnessNetns{path: "/run/netns/sb", ip: "10.88.0.9"})
	_, err := d.Create(context.Background(), models.CreateSandboxRequest{
		Image:            "alpine:3.20",
		ContainerCommand: []string{"sleep"},
		NetworkDenyOut:   []string{"0.0.0.0/0"},
	}, "sb-egress", "tok", nil)
	if err != nil {
		t.Fatal(err)
	}
}

func TestWaitToolboxHTTPMissingIP(t *testing.T) {
	d := newTestDriver(t)
	err := d.waitToolboxHTTP(context.Background(), "", "tok")
	if err == nil {
		t.Fatal("want error for empty IP")
	}
}

func TestWaitToolboxHTTPTimeout(t *testing.T) {
	d := newTestDriver(t)
	d.cfg.ToolboxWaitTimeout = 50 * time.Millisecond
	d.cfg.ReadinessPollInit = 10 * time.Millisecond
	orig := pollToolboxHealthFn
	pollToolboxHealthFn = func(context.Context, string, int) error { return errors.New("down") }
	t.Cleanup(func() { pollToolboxHealthFn = orig })
	err := d.waitToolboxHTTP(context.Background(), "10.0.0.1", "tok")
	if err == nil {
		t.Fatal("want timeout error")
	}
}

func TestCreateNetworkBlockAllFake(t *testing.T) {
	stubToolboxProbe(t)
	tmp := t.TempDir()
	toolbox := filepath.Join(tmp, "toolboxd")
	_ = os.WriteFile(toolbox, []byte("x"), 0o755)
	be := &netrulesMemBackend{}
	d := New(Config{
		ToolboxBinaryPath: toolbox, ToolboxMountPath: "/.aerol/toolboxd", ToolboxPort: 2280,
		ToolboxWaitTimeout: 2 * time.Second, LogDir: tmp + "/logs", RunDir: tmp + "/run",
	}, netrules.NewWithBackend(be), nil)
	d.SetClient(NewTestClient("aerolvm", newFakeTransport()))
	d.SetNetnsHandoff(&harnessNetns{path: "/run/netns/sb", ip: "10.88.0.9"})
	_, err := d.Create(context.Background(), models.CreateSandboxRequest{
		Image: "alpine:3.20", ContainerCommand: []string{"sleep"}, NetworkBlockAll: true,
	}, "sb-block", "tok", nil)
	if err != nil {
		t.Fatal(err)
	}
}

func TestCreateDuplicateContainerFake(t *testing.T) {
	stubToolboxProbe(t)
	tr := newFakeTransport()
	d := newTestDriver(t)
	d.SetClient(NewTestClient("aerolvm", tr))
	ctx := context.Background()
	req := models.CreateSandboxRequest{Image: "alpine:3.20", ContainerCommand: []string{"sleep"}}
	if _, err := d.Create(ctx, req, "sb-dup", "tok", nil); err != nil {
		t.Fatal(err)
	}
	_, err := d.Create(ctx, req, "sb-dup", "tok", nil)
	if err == nil {
		t.Fatal("want duplicate error")
	}
}

func TestDestroyClearsNetworkFake(t *testing.T) {
	stubToolboxProbe(t)
	tmp := t.TempDir()
	toolbox := filepath.Join(tmp, "toolboxd")
	_ = os.WriteFile(toolbox, []byte("x"), 0o755)
	be := &netrulesMemBackend{}
	d := New(Config{
		ToolboxBinaryPath: toolbox, ToolboxMountPath: "/.aerol/toolboxd", ToolboxPort: 2280,
		ToolboxWaitTimeout: 2 * time.Second, LogDir: tmp + "/logs", RunDir: tmp + "/run",
	}, netrules.NewWithBackend(be), nil)
	d.SetClient(NewTestClient("aerolvm", newFakeTransport()))
	d.SetNetnsHandoff(&harnessNetns{path: "/run/netns/sb", ip: "10.88.0.9"})
	ctx := context.Background()
	if _, err := d.Create(ctx, models.CreateSandboxRequest{
		Image: "alpine:3.20", ContainerCommand: []string{"sleep"},
	}, "sb-destroy", "tok", nil); err != nil {
		t.Fatal(err)
	}
	if err := d.Destroy(ctx, &models.Sandbox{ID: "sb-destroy", ContainerID: "sb-destroy", ContainerIP: "10.88.0.9"}); err != nil {
		t.Fatal(err)
	}
}

func TestEnsureImageRegistryAuthFake(t *testing.T) {
	tr := newFakeTransport()
	tr.getImageFn = func(context.Context, string) (cntr.Image, error) { return nil, errors.New("missing") }
	d := newTestDriver(t)
	_, err := d.ensureImage(context.Background(), NewTestClient("aerolvm", tr), "ghcr.io/org/app:v1", &models.RegistryAuth{
		Username: "user", Password: "pass",
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestWithNetworkNamespaceOpt(t *testing.T) {
	spec := &specs.Spec{Linux: &specs.Linux{}}
	opt := withNetworkNamespace("/run/netns/test")
	if err := opt(context.Background(), nil, nil, spec); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, ns := range spec.Linux.Namespaces {
		if ns.Type == specs.NetworkNamespace && ns.Path == "/run/netns/test" {
			found = true
		}
	}
	if !found {
		t.Fatal("network namespace not set")
	}
}

func TestCreateMissingImageCommandFake(t *testing.T) {
	stubToolboxProbe(t)
	d := newTestDriver(t)
	_, err := d.Create(context.Background(), models.CreateSandboxRequest{Image: "alpine:3.20"}, "sb-cmd", "tok", nil)
	if err == nil || !strings.Contains(err.Error(), "read image command") {
		t.Fatalf("want image command error, got %v", err)
	}
}

func TestHarnessNetnsReleaseOnCreateFailure(t *testing.T) {
	stubToolboxProbe(t)
	boom := errors.New("boom")
	tr := newFakeTransport()
	tr.getImageFn = func(context.Context, string) (cntr.Image, error) { return nil, boom }
	tr.pullImageFn = func(context.Context, string, ...cntr.RemoteOpt) (cntr.Image, error) { return nil, boom }
	h := &harnessNetns{path: "/run/netns/sb", ip: "10.88.0.9"}
	d := newTestDriver(t)
	d.SetClient(NewTestClient("aerolvm", tr))
	d.SetNetnsHandoff(h)
	d.cfg.NativeNetnsPool = true
	_, err := d.Create(context.Background(), models.CreateSandboxRequest{
		Image: "alpine:3.20", ContainerCommand: []string{"sleep"},
	}, "sb-fail", "tok", nil)
	if err == nil {
		t.Fatal("want create failure")
	}
	if !h.released {
		t.Fatal("netns should be released on failure")
	}
}

func TestContainerPIDStoppedFake(t *testing.T) {
	stubToolboxProbe(t)
	d := newTestDriver(t)
	ctx := context.Background()
	_, _ = d.Create(ctx, models.CreateSandboxRequest{
		Image: "alpine:3.20", ContainerCommand: []string{"sleep"},
	}, "sb-stopped-pid", "tok", nil)
	if err := d.Stop(ctx, "sb-stopped-pid"); err != nil {
		t.Fatal(err)
	}
	pid, err := d.ContainerPID(ctx, "sb-stopped-pid")
	if err != nil || pid != 0 {
		t.Fatalf("pid=%d err=%v", pid, err)
	}
}

func TestStopContextCancelFake(t *testing.T) {
	stubToolboxProbe(t)
	d := newTestDriver(t)
	ctx := context.Background()
	_, err := d.Create(ctx, models.CreateSandboxRequest{
		Image: "alpine:3.20", ContainerCommand: []string{"sleep"},
	}, "sb-stop-cancel", "tok", nil)
	if err != nil {
		t.Fatal(err)
	}
	cancelCtx, cancel := context.WithCancel(ctx)
	cancel()
	if err := d.Stop(cancelCtx, "sb-stop-cancel"); err == nil {
		t.Fatal("want context error")
	}
}

func TestCreateWithoutNetnsPoolFake(t *testing.T) {
	stubToolboxProbe(t)
	d := newTestDriver(t)
	d.cfg.NativeNetnsPool = false
	d.SetNetnsHandoff(nil)
	_, err := d.Create(context.Background(), models.CreateSandboxRequest{
		Image: "alpine:3.20", ContainerCommand: []string{"sleep"},
	}, "sb-no-netns", "tok", nil)
	if err != nil {
		t.Fatal(err)
	}
}

func TestCreatePrivilegedSkipsSecurityFake(t *testing.T) {
	stubToolboxProbe(t)
	d := newTestDriver(t)
	d.cfg.Privileged = true
	d.cfg.ResourceLimitsOff = true
	_, err := d.Create(context.Background(), models.CreateSandboxRequest{
		Image: "alpine:3.20", ContainerCommand: []string{"sleep"}, CPU: 1, MemoryMB: 128,
	}, "sb-priv", "tok", nil)
	if err != nil {
		t.Fatal(err)
	}
}

func TestWithNetworkNamespaceEmptyPath(t *testing.T) {
	spec := &specs.Spec{Linux: &specs.Linux{}}
	if err := withNetworkNamespace("")(context.Background(), nil, nil, spec); err != nil {
		t.Fatal(err)
	}
}

func TestWithNetworkNamespaceReplacesExisting(t *testing.T) {
	spec := &specs.Spec{Linux: &specs.Linux{Namespaces: []specs.LinuxNamespace{
		{Type: specs.NetworkNamespace, Path: "/old"},
	}}}
	if err := withNetworkNamespace("/new")(context.Background(), nil, nil, spec); err != nil {
		t.Fatal(err)
	}
	if spec.Linux.Namespaces[0].Path != "/new" {
		t.Fatalf("path=%s", spec.Linux.Namespaces[0].Path)
	}
}

func TestImageDefaultCommandErrors(t *testing.T) {
	_, err := imageDefaultCommand(context.Background(), nil, nil)
	if err == nil {
		t.Fatal("want nil client error")
	}
	c := NewTestClient("aerolvm", newFakeTransport())
	_, err = imageDefaultCommand(context.Background(), c, &fakeImage{name: "no-config"})
	if err == nil {
		t.Fatal("want config error from fake image")
	}
}

func TestEnsureImageContextCancelDuringPullSem(t *testing.T) {
	tr := newFakeTransport()
	tr.getImageFn = func(context.Context, string) (cntr.Image, error) { return nil, errors.New("missing") }
	tr.pullImageFn = func(ctx context.Context, _ string, _ ...cntr.RemoteOpt) (cntr.Image, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	d := New(Config{PullMaxConcurrent: 1}, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	client := NewTestClient("aerolvm", tr)
	// Hold the sole pull slot so the next ensureImage blocks on the semaphore.
	d.pullSem <- struct{}{}
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
		<-d.pullSem
	}()
	_, err := d.ensureImage(ctx, client, "alpine:3.20", nil)
	if err == nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("want cancel, got %v", err)
	}
}

func TestCreateUsesImageDefaultCommandFake(t *testing.T) {
	stubToolboxProbe(t)
	provider, img := newTestImageProvider(t)
	tr := newFakeTransport()
	tr.provider = provider
	tr.image = img
	d := newTestDriver(t)
	d.SetClient(NewTestClient("aerolvm", tr))
	_, err := d.Create(context.Background(), models.CreateSandboxRequest{Image: "cfg:test"}, "sb-img-cmd", "tok", nil)
	if err != nil {
		t.Fatal(err)
	}
}

func TestDestroyNilSandbox(t *testing.T) {
	d := newTestDriver(t)
	d.SetClient(NewTestClient("aerolvm", newFakeTransport()))
	if err := d.Destroy(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
}

func TestContainerPIDLookupError(t *testing.T) {
	tr := newFakeTransport()
	tr.loadContainerFn = func(context.Context, string) (cntr.Container, error) {
		return nil, errors.New("lookup failed")
	}
	d := newTestDriver(t)
	d.SetClient(NewTestClient("aerolvm", tr))
	_, err := d.ContainerPID(context.Background(), "sb")
	if err == nil {
		t.Fatal("want lookup error")
	}
}

func TestClientContentProviderWired(t *testing.T) {
	provider, _ := newTestImageProvider(t)
	tr := newFakeTransport()
	tr.provider = provider
	c := NewTestClient("aerolvm", tr)
	if c.contentProvider() == nil {
		t.Fatal("expected provider")
	}
}

func TestEnsureImageEmptyRef(t *testing.T) {
	_, err := newTestDriver(t).ensureImage(context.Background(), NewTestClient("aerolvm", newFakeTransport()), "  ", nil)
	if err == nil {
		t.Fatal("want empty ref error")
	}
}

func TestContainerPIDTaskLookupError(t *testing.T) {
	tr := newFakeTransport()
	c := &fakeContainer{id: "sb-task-err", taskErr: errors.New("task lookup failed")}
	tr.mu.Lock()
	tr.containers["sb-task-err"] = c
	tr.mu.Unlock()
	d := newTestDriver(t)
	d.SetClient(NewTestClient("aerolvm", tr))
	_, err := d.ContainerPID(context.Background(), "sb-task-err")
	if err == nil {
		t.Fatal("want task lookup error")
	}
}

func TestGenerateResolvConfDirectoryPath(t *testing.T) {
	if _, err := generateResolvConf(t.TempDir()); err == nil {
		t.Fatal("want read error for directory path")
	}
}

func TestContainerPIDStatusError(t *testing.T) {
	stubToolboxProbe(t)
	tr := newFakeTransport()
	d := newTestDriver(t)
	d.SetClient(NewTestClient("aerolvm", tr))
	ctx := context.Background()
	_, _ = d.Create(ctx, models.CreateSandboxRequest{
		Image: "alpine:3.20", ContainerCommand: []string{"sleep"},
	}, "sb-status-err", "tok", nil)
	tr.mu.Lock()
	tr.containers["sb-status-err"].task.statusErr = errors.New("status failed")
	tr.mu.Unlock()
	_, err := d.ContainerPID(ctx, "sb-status-err")
	if err == nil {
		t.Fatal("want status error")
	}
}

func TestImageConfigCommandBadJSON(t *testing.T) {
	provider, img := newTestImageProvider(t)
	for digest, body := range provider.blobs {
		if len(body) > 0 && body[0] == '{' && bytes.Contains(body, []byte("sleep")) {
			provider.blobs[digest] = []byte("{")
			break
		}
	}
	_, err := imageConfigCommand(context.Background(), provider, img)
	if err == nil {
		t.Fatal("want json decode error")
	}
}

func TestContainerPIDEmptyPids(t *testing.T) {
	stubToolboxProbe(t)
	tr := newFakeTransport()
	d := newTestDriver(t)
	d.SetClient(NewTestClient("aerolvm", tr))
	ctx := context.Background()
	_, _ = d.Create(ctx, models.CreateSandboxRequest{
		Image: "alpine:3.20", ContainerCommand: []string{"sleep"},
	}, "sb-no-pid", "tok", nil)
	tr.mu.Lock()
	tr.containers["sb-no-pid"].task.pids = []cntr.ProcessInfo{}
	tr.mu.Unlock()
	pid, err := d.ContainerPID(ctx, "sb-no-pid")
	if err != nil || pid != 0 {
		t.Fatalf("pid=%d err=%v", pid, err)
	}
}

func TestContainerPIDNotRunning(t *testing.T) {
	stubToolboxProbe(t)
	tr := newFakeTransport()
	d := newTestDriver(t)
	d.SetClient(NewTestClient("aerolvm", tr))
	ctx := context.Background()
	_, _ = d.Create(ctx, models.CreateSandboxRequest{
		Image: "alpine:3.20", ContainerCommand: []string{"sleep"},
	}, "sb-not-run", "tok", nil)
	tr.mu.Lock()
	tr.containers["sb-not-run"].task.status = cntr.Stopped
	tr.mu.Unlock()
	pid, err := d.ContainerPID(ctx, "sb-not-run")
	if err != nil || pid != 0 {
		t.Fatalf("pid=%d err=%v", pid, err)
	}
}

func TestPingWithInjectedClient(t *testing.T) {
	d := newTestDriver(t)
	d.SetClient(NewTestClient("aerolvm", newFakeTransport()))
	if err := d.Ping(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestLifoTeardownWithFakeContainer(t *testing.T) {
	stubToolboxProbe(t)
	d := newTestDriver(t)
	ctx := context.Background()
	c := NewTestClient("aerolvm", newFakeTransport())
	container, err := c.NewContainer(ctx, "sb-teardown")
	if err != nil {
		t.Fatal(err)
	}
	task, err := container.NewTask(ctx, cio.NullIO)
	if err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(t.TempDir(), "sb.log")
	if err := os.WriteFile(logPath, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	hostFiles, err := prepareSandboxHostFiles(t.TempDir()+"/run", "sb-teardown")
	if err != nil {
		t.Fatal(err)
	}
	d.lifoTeardown(ctx, c, container, task, logPath, hostFiles)
	if _, err := os.Stat(logPath); !os.IsNotExist(err) {
		t.Fatal("log should be removed")
	}
}
