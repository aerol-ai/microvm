package containerd

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	cntr "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/containers"
	"github.com/containerd/errdefs"

	"github.com/aerol-ai/microvm/internal/pool/containerdpool"
	dockerpkg "github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
)

// gvisorProbe is what containerIPv4FromTask returns for a running gVisor
// sandbox: runsc has taken eth0's address out of the pinned netns (the
// sentry owns the interface), so that read finds no IPv4, and the task's pid
// sits in the host netns, which the probe refuses to report.
func gvisorProbe(context.Context, cntr.Task) (string, error) {
	return "", errors.New("task pid shares the host network namespace; refusing to report the host's address as the sandbox's")
}

// captureContainerLabels makes the fake's NewContainer keep the labels the
// driver passed, so a test can read back what Create or park recorded.
func captureContainerLabels(tr *fakeTransport) {
	tr.newContainerFn = func(ctx context.Context, id string, opts ...cntr.NewContainerOpts) (cntr.Container, error) {
		var info containers.Container
		for _, o := range opts {
			func() {
				// Spec, image and snapshot options need a live client; only
				// the label option matters here.
				defer func() { _ = recover() }()
				_ = o(ctx, nil, &info)
			}()
		}
		tr.mu.Lock()
		defer tr.mu.Unlock()
		if _, exists := tr.containers[id]; exists {
			return nil, errdefs.ErrAlreadyExists
		}
		c := &fakeContainer{id: id, labels: info.Labels}
		tr.containers[id] = c
		return c, nil
	}
}

// A running gVisor sandbox's address can't be probed, ever: Inspect, the
// listing reconcile reads, and Start must still report the address its netns
// slot was given. Before, Inspect failed, ListManaged dropped the sandbox and
// reconcile deleted it (UC-320); Start of a stopped gVisor sandbox failed too.
func TestGvisorSandboxKeepsItsAddress(t *testing.T) {
	stubToolboxProbe(t)
	containerIPv4FromTaskFn = gvisorProbe // restored by stubToolboxProbe's cleanup
	origGrace, origPoll := stopGraceTimeout, stopPollInterval
	stopGraceTimeout, stopPollInterval = 50*time.Millisecond, 5*time.Millisecond
	t.Cleanup(func() { stopGraceTimeout, stopPollInterval = origGrace, origPoll })
	tr := newFakeTransport()
	captureContainerLabels(tr)
	d := newTestDriver(t) // netns pool slot: /run/netns/sb, 10.88.0.9
	d.SetClient(NewTestClient("aerolvm", tr))
	ctx := context.Background()
	const id = "sb-gvisor"

	created, err := d.Create(ctx, models.CreateSandboxRequest{
		Image:            "alpine:3.20",
		Runtime:          models.RuntimeGvisor,
		ContainerCommand: []string{"sleep", "inf"},
	}, id, "tok", nil)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if created.ContainerIP != "10.88.0.9" {
		t.Fatalf("Create address = %q, want the slot's 10.88.0.9", created.ContainerIP)
	}

	st, err := d.Inspect(ctx, id)
	if err != nil || st.Status != models.SandboxStatusStarted || st.ContainerIP != "10.88.0.9" {
		t.Fatalf("Inspect = %+v, %v; want started at 10.88.0.9", st, err)
	}
	listed, err := d.ListManaged(ctx)
	if err != nil || listed[id] == nil || listed[id].ContainerIP != "10.88.0.9" {
		t.Fatalf("ListManaged = %v, %v; want %s listed at 10.88.0.9", listed, err, id)
	}

	// Start of an already-running sandbox, then a stop and a real restart.
	for _, step := range []string{"start while running", "restart after stop"} {
		if step == "restart after stop" {
			if err := d.Stop(ctx, id); err != nil {
				t.Fatalf("Stop: %v", err)
			}
		}
		st, err := d.Start(ctx, id)
		if err != nil || st.ContainerIP != "10.88.0.9" {
			t.Fatalf("%s: Start = %+v, %v; want 10.88.0.9", step, st, err)
		}
	}
}

// Park and adopt record the address too, so a warm-pool gVisor sandbox is
// covered as well as a cold one.
func TestWarmPoolRecordsSandboxAddress(t *testing.T) {
	stubToolboxProbe(t)
	containerIPv4FromTaskFn = gvisorProbe
	origWait := parkReadyWaitFn
	parkReadyWaitFn = func(context.Context, *dockerpkg.ParkedListener) error { return nil }
	t.Cleanup(func() { parkReadyWaitFn = origWait })

	provider, img := newTestImageProvider(t)
	tr := newFakeTransport()
	tr.provider = provider
	tr.image = img
	captureContainerLabels(tr)
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
		NativeNetnsPool:    true,
	}, nil, nil)
	d.SetClient(NewTestClient("aerolvm", tr))
	d.SetNetnsHandoff(&harnessNetns{path: "/run/netns/park-g", ip: "10.88.0.78"})
	ctx := context.Background()

	slot, err := d.parkContainer(ctx, "park-gv2", containerdpool.Key{Image: "cfg:test", Runtime: models.RuntimeGvisor})
	if err != nil {
		t.Fatalf("park: %v", err)
	}
	if got := tr.containers["park-gv2"].labels[containerIPLabelKey]; got != "10.88.0.78" {
		t.Fatalf("parked container address label = %q, want 10.88.0.78", got)
	}

	// A slot parked without a prepaid address (no netns pool) got its
	// address from the probe; adopt records it. (A fresh transport: the
	// fake's ListContainers ignores label filters.)
	tr = newFakeTransport()
	tr.containers["park-noip"] = &fakeContainer{
		id: "park-noip", task: &fakeTask{status: cntr.Running},
		labels: map[string]string{poolParkLabelKey: poolParkLabelValue},
	}
	d.SetClient(NewTestClient("aerolvm", tr))
	slot = &containerdpool.ParkedSlot{ID: "park-noip", ContainerID: "park-noip", ContainerIP: "10.88.0.79", Handle: &fakeHandle{alive: true}}
	if _, err := d.adoptParked(ctx, models.CreateSandboxRequest{}, "sb-adopted", "tok", slot); err != nil {
		t.Fatalf("adopt: %v", err)
	}
	st, err := d.Inspect(ctx, "park-noip")
	if err != nil || st.SandboxID != "sb-adopted" || st.ContainerIP != "10.88.0.79" {
		t.Fatalf("adopted Inspect = %+v, %v; want sb-adopted at 10.88.0.79", st, err)
	}
}
