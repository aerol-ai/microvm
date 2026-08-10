package service

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/secrets"
)

type stubEventsSource struct{}

func (stubEventsSource) StreamEvents(context.Context, chan<- docker.DockerEvent) error {
	return errors.New("stub events")
}

func (stubEventsSource) ContainerPID(context.Context, string) (int, error) {
	return 0, errors.New("stub pid")
}

func TestSetEventsSourceAndDockerAuxClient(t *testing.T) {
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	src := stubEventsSource{}
	svc.SetEventsSource(src)
	if svc.events == nil {
		t.Fatal("SetEventsSource did not wire events")
	}
	aux := &docker.Client{}
	svc.SetDockerAuxClient(aux)
	if svc.dockerAux != aux {
		t.Fatal("SetDockerAuxClient did not wire dockerAux")
	}
}

func TestValidateEgressPolicy(t *testing.T) {
	if err := validateEgressPolicy(nil, nil); err != nil {
		t.Fatalf("empty: %v", err)
	}
	if err := validateEgressPolicy([]string{"10.0.0.0/8"}, nil); err != nil {
		t.Fatalf("allow: %v", err)
	}
	if err := validateEgressPolicy(nil, []string{"192.168.0.0/16"}); err != nil {
		t.Fatalf("deny: %v", err)
	}
	if err := validateEgressPolicy([]string{"10.0.0.0/8"}, []string{"192.168.0.0/16"}); err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("mutual = %v", err)
	}
	if err := validateEgressPolicy([]string{"not-a-cidr"}, nil); err == nil || !strings.Contains(err.Error(), "invalid egress CIDR") {
		t.Fatalf("bad cidr = %v", err)
	}
	if err := validateEgressPolicy(nil, []string{"0.0.0.0/0"}); err == nil || !strings.Contains(err.Error(), "network_block_all") {
		t.Fatalf("deny all = %v", err)
	}
}

func TestAttachWasmRegistryAuth(t *testing.T) {
	harness, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	cipher, err := secrets.NewCipher("", filepath.Join(t.TempDir(), "key"))
	if err != nil {
		t.Fatal(err)
	}
	svc := &Service{cipher: cipher, logger: harness.logger}

	svc.attachWasmRegistryAuth(nil)
	svc.attachWasmRegistryAuth(&models.Sandbox{})

	sealed, err := svc.sealRegistry(&models.RegistryAuth{Server: "ghcr.io", Username: "u", Password: "p"})
	if err != nil || len(sealed) == 0 {
		t.Fatalf("sealRegistry: %v", err)
	}
	sb := &models.Sandbox{ID: "sb-wasm-auth", RegistryAuthSealed: sealed}
	svc.attachWasmRegistryAuth(sb)
	if sb.RegistryAuth == nil || sb.RegistryAuth.Password != "p" {
		t.Fatalf("RegistryAuth = %+v", sb.RegistryAuth)
	}

	// Corrupt seal → warn path, leave RegistryAuth nil (degrade to public pull).
	bad := &models.Sandbox{ID: "sb-bad", RegistryAuthSealed: []byte("not-sealed")}
	svc.attachWasmRegistryAuth(bad)
	if bad.RegistryAuth != nil {
		t.Fatalf("corrupt seal should leave RegistryAuth nil, got %+v", bad.RegistryAuth)
	}
}

func TestStartLiveUsageSamplerWithDockerAux(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.SetUsageReporter(&captureReporter{})
	svc.cfg.FleetLiveSampleInterval = time.Millisecond // below floor → clamped
	svc.SetDockerAuxClient(&docker.Client{})
	// Empty store → sampler ticks without calling ContainerStats (nil httpClient).
	svc.StartLiveUsageSampler(ctx)
	time.Sleep(30 * time.Millisecond)
}

func TestStartVolumeReclaimEnabled(t *testing.T) {
	s := enabledVolumeService(t)
	harness, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	s.logger = harness.logger
	s.SetVolumeReclaimer(&fakeReclaimer{})
	s.cfg.PlatformVolumes.ReclaimInterval = time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.StartVolumeReclaim(ctx)
	time.Sleep(20 * time.Millisecond)

	// Non-positive interval is a no-op even with a reclaimer.
	s.cfg.PlatformVolumes.ReclaimInterval = 0
	s.StartVolumeReclaim(context.Background())
}
