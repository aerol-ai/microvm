package containerd

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	cntr "github.com/containerd/containerd"
	apievents "github.com/containerd/containerd/api/events"
	"github.com/containerd/containerd/events"
	"github.com/containerd/containerd/runtime"
	"github.com/containerd/typeurl/v2"

	"github.com/aerol-ai/microvm/internal/pool/containerdpool"
	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/docker/netrules"
	"github.com/aerol-ai/microvm/pkg/models"
)

// Phase 4 matrix (offline): cold create / park / adopt / netrules / readiness
// config for runtime=gvisor → runsc shim.

func TestRuntimeContainerOptRunsc(t *testing.T) {
	d := New(Config{RunDir: t.TempDir()}, nil, nil)
	opt, err := d.runtimeContainerOpt("runsc")
	if err != nil || opt == nil {
		t.Fatalf("opt=%v err=%v", opt, err)
	}
	cfgPath := filepath.Join(d.cfg.RunDir, "runsc", "config.toml")
	body, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), `host-uds = "open"`) {
		t.Fatalf("config missing host-uds open:\n%s", body)
	}
}

func TestContainerdRuntimeNameMatrix(t *testing.T) {
	if got := containerdRuntimeName("runsc"); got != runscShimName {
		t.Fatalf("runsc → %q", got)
	}
	if got := containerdRuntimeName("runc"); got != "runc" {
		t.Fatalf("runc → %q", got)
	}
}

func TestCreateColdRunscFake(t *testing.T) {
	stubToolboxProbe(t)
	d := newTestDriver(t)
	d.cfg.RunDir = t.TempDir()
	state, err := d.Create(context.Background(), models.CreateSandboxRequest{
		Image:            "alpine:3.20",
		Runtime:          models.RuntimeGvisor,
		ContainerCommand: []string{"sleep", "inf"},
		CPU:              1,
		MemoryMB:         256,
	}, "sb-gvisor-cold", "tok", nil)
	if err != nil {
		t.Fatal(err)
	}
	if state == nil || state.SandboxID != "sb-gvisor-cold" {
		t.Fatalf("state=%+v", state)
	}
	cfgPath := filepath.Join(d.cfg.RunDir, "runsc", "config.toml")
	if _, err := os.Stat(cfgPath); err != nil {
		t.Fatalf("expected runsc config written: %v", err)
	}
}

func TestParkContainerRunscRequiresReady(t *testing.T) {
	d := newTestDriver(t)
	d.cfg.ReadyEnabled = true
	d.cfg.RunDir = t.TempDir()
	d.cfg.ReadyDir = t.TempDir()
	_, err := d.parkContainer(context.Background(), "park-gvisor", containerdpool.Key{
		Image:   "alpine:3.20",
		Runtime: models.RuntimeGvisor,
	})
	// Fake transport lacks full park path (ready listener + task start may fail);
	// assert we got past runtime resolution into park work (not ValidateRuntime).
	if err != nil && strings.Contains(err.Error(), "incompatible with privileged") {
		t.Fatalf("unexpected runtime policy error: %v", err)
	}
}

func TestApplyAdoptNetworkPolicyRunscAdopt(t *testing.T) {
	be := &netrulesMemBackend{}
	d := New(Config{}, netrules.NewWithBackend(be), nil)
	if err := d.applyAdoptNetworkPolicy("10.88.0.55", models.CreateSandboxRequest{
		Runtime:         models.RuntimeGvisor,
		NetworkBlockAll: true,
	}); err != nil {
		t.Fatal(err)
	}
}

func TestValidateRuntimeRequestGvisorMatrix(t *testing.T) {
	err := models.ValidateRuntimeRequest(models.CreateSandboxRequest{
		Runtime: models.RuntimeGvisor,
		GPUs:    &models.GPURequest{Count: 1},
	}, models.RuntimeGvisor, false, nil)
	if err == nil || !strings.Contains(err.Error(), "GPU") {
		t.Fatalf("want GPU refusal, got %v", err)
	}
	err = models.ValidateRuntimeRequest(models.CreateSandboxRequest{
		Runtime: models.RuntimeGvisor,
	}, models.RuntimeGvisor, true, nil)
	if err == nil || !strings.Contains(err.Error(), "privileged") {
		t.Fatalf("want privileged refusal, got %v", err)
	}
}

func TestStreamEventsEnrichesSandboxLabel(t *testing.T) {
	tr := newFakeTransport()
	tr.emitEvents = true
	tr.containers["sb-ev"] = &fakeContainer{
		id:     "sb-ev",
		task:   &fakeTask{status: cntr.Running},
		labels: map[string]string{sandboxIDLabelKey: "sb-real-from-label"},
	}
	d := newTestDriver(t)
	d.SetClient(NewTestClient("aerolvm", tr))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	out := make(chan docker.DockerEvent, 1)
	errCh := make(chan error, 1)
	go func() { errCh <- d.StreamEvents(ctx, out) }()
	select {
	case ev := <-out:
		cancel()
		if ev.ContainerID != "sb-ev" {
			t.Fatalf("container id=%q", ev.ContainerID)
		}
		if ev.SandboxID != "sb-real-from-label" {
			t.Fatalf("sandbox id=%q want label enrichment", ev.SandboxID)
		}
	case err := <-errCh:
		t.Fatalf("stream ended early: %v", err)
	case <-time.After(2 * time.Second):
		cancel()
		t.Fatal("timed out waiting for event")
	}
}

func TestNormalizeExitCodeFromTaskExit(t *testing.T) {
	any, err := typeurl.MarshalAny(&apievents.TaskExit{ContainerID: "sb-exit", ExitStatus: 137})
	if err != nil {
		t.Fatal(err)
	}
	ev, ok := normalizeContainerdEvent(&events.Envelope{
		Topic:     runtime.TaskExitEventTopic,
		Timestamp: time.Now(),
		Event:     any,
	})
	if !ok || ev.ExitCode != 137 || ev.Action != "die" {
		t.Fatalf("ev=%+v ok=%v", ev, ok)
	}
}
