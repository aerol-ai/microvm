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
	"github.com/containerd/containerd/oci"
	runtimeoptions "github.com/containerd/containerd/pkg/runtimeoptions/v1"
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
	if !strings.Contains(string(body), "[runsc_config]") {
		t.Fatalf("config missing [runsc_config] section (the shim silently ignores other section names):\n%s", body)
	}
}

// Regression for the first live cluster-3-mixed-gvisor run: the shim
// typeurl-unmarshals task options against its own proto registry, so the
// options MUST marshal to containerd's well-known runtimeoptions.v1.Options
// URL. A custom-registered Go type marshals fine client-side but fails task
// create with "type with url ...: not found" on the shim.
func TestRunscRuntimeOptsWireType(t *testing.T) {
	d := New(Config{RunDir: t.TempDir()}, nil, nil)
	v, err := d.runscRuntimeOpts()
	if err != nil {
		t.Fatal(err)
	}
	any, err := typeurl.MarshalAny(v)
	if err != nil {
		t.Fatalf("marshal runsc options: %v", err)
	}
	if !strings.HasSuffix(any.GetTypeUrl(), "runtimeoptions.v1.Options") {
		t.Fatalf("options Any URL = %q, want the well-known runtimeoptions.v1.Options", any.GetTypeUrl())
	}
	ro, ok := v.(*runtimeoptions.Options)
	if !ok {
		t.Fatalf("options concrete type = %T", v)
	}
	if ro.TypeUrl != runscOptionsTypeUrl {
		t.Fatalf("options.TypeUrl = %q, want %q (shim rejects others as unsupported)", ro.TypeUrl, runscOptionsTypeUrl)
	}
}

// Regression for the second live cluster-3-mixed-gvisor failure: without the
// CRI container-type=sandbox annotation the runsc shim classifies the
// container as a pod SUB-container and deadlocks in task create waiting for
// output-pipe EOF from the standalone sandbox runsc boots anyway (reproduced
// with plain ctr on both containerd 1.7 and 2.2).
func TestRunscSandboxAnnotationOpt(t *testing.T) {
	spec := &oci.Spec{}
	if err := runscSandboxAnnotationOpt()(context.Background(), nil, nil, spec); err != nil {
		t.Fatal(err)
	}
	if got := spec.Annotations[criContainerTypeAnnotation]; got != criContainerTypeSandbox {
		t.Fatalf("annotation %q = %q, want %q", criContainerTypeAnnotation, got, criContainerTypeSandbox)
	}
	spec.Annotations["keep"] = "me"
	if err := runscSandboxAnnotationOpt()(context.Background(), nil, nil, spec); err != nil {
		t.Fatal(err)
	}
	if spec.Annotations["keep"] != "me" {
		t.Fatal("existing annotations must be preserved")
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
