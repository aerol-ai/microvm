package service

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
)

// fenceStub answers Ready from a per-runtime table and records the asks.
type fenceStub struct {
	errs  map[string]error
	asked []string
}

func (f *fenceStub) Ready(rt string) error {
	f.asked = append(f.asked, rt)
	return f.errs[rt]
}

func TestIPv6FenceRuntime(t *testing.T) {
	for _, tc := range []struct{ runtime, engine, want string }{
		{models.RuntimeFirecracker, models.ContainerEngineContainerd, models.RuntimeFirecracker},
		{models.RuntimeWasm, models.ContainerEngineDocker, ""},
		{models.RuntimeIsolate, models.ContainerEngineContainerd, ""},
		{models.RuntimeDocker, models.ContainerEngineDocker, models.ContainerEngineDocker},
		{models.RuntimeGvisor, models.ContainerEngineDocker, models.ContainerEngineDocker},
		{models.RuntimeDocker, models.ContainerEngineContainerd, models.ContainerEngineContainerd},
		{models.RuntimeGvisor, models.ContainerEngineContainerd, models.ContainerEngineContainerd},
		{models.RuntimeDocker, "", models.ContainerEngineDocker},
	} {
		if got := ipv6FenceRuntime(tc.runtime, tc.engine); got != tc.want {
			t.Fatalf("ipv6FenceRuntime(%q, %q) = %q, want %q", tc.runtime, tc.engine, got, tc.want)
		}
	}
}

func TestRequireIPv6Fence(t *testing.T) {
	down := errors.New("nf_tables: operation not supported")
	svc := &Service{}
	if err := svc.requireIPv6Fence(models.RuntimeDocker); err != nil {
		t.Fatalf("no fence wired (tests, non-Linux): %v", err)
	}
	stub := &fenceStub{errs: map[string]error{models.ContainerEngineContainerd: down}}
	svc.SetIPv6Fence(stub)
	svc.cfg.ContainerEngine = models.ContainerEngineContainerd

	err := svc.requireIPv6Fence(models.RuntimeGvisor)
	if !errors.Is(err, ErrIPv6FenceNotReady) || !strings.Contains(err.Error(), "runtime containerd") || !strings.Contains(err.Error(), "operation not supported") {
		t.Fatalf("gvisor on containerd with the fence down = %v", err)
	}
	if err := svc.requireIPv6Fence(models.RuntimeFirecracker); err != nil {
		t.Fatalf("firecracker's fence is up: %v", err)
	}
	if err := svc.requireIPv6Fence(models.RuntimeWasm); err != nil {
		t.Fatalf("wasm has no interface on the node: %v", err)
	}
	if got := strings.Join(stub.asked, ","); got != "containerd,firecracker" {
		t.Fatalf("asked = %s", got)
	}

	// Docker engine: runc and gVisor both ask the docker bridge's fence.
	svc.cfg.ContainerEngine = models.ContainerEngineDocker
	stub.errs = map[string]error{models.ContainerEngineDocker: down}
	if err := svc.requireIPv6Fence(models.RuntimeDocker); !errors.Is(err, ErrIPv6FenceNotReady) {
		t.Fatalf("docker with the fence down = %v", err)
	}
}

// TestCreateRefusedWhileIPv6FenceDown: the gate runs before the runtime is
// asked for anything, and a fence that comes back lets the next create
// through.
func TestCreateRefusedWhileIPv6FenceDown(t *testing.T) {
	rt := &recordingRuntime{}
	svc, _, _ := newServiceRuntimeHarnessAtPath(t, filepath.Join(t.TempDir(), "state.db"), rt)
	stub := &fenceStub{errs: map[string]error{models.ContainerEngineDocker: errors.New("netlink: permission denied")}}
	svc.SetIPv6Fence(stub)

	_, err := svc.CreateSandbox(context.Background(), models.CreateSandboxRequest{Image: "alpine"})
	if !errors.Is(err, ErrIPv6FenceNotReady) {
		t.Fatalf("err = %v, want ErrIPv6FenceNotReady", err)
	}
	if rt.createCalls != 0 {
		t.Fatalf("the runtime was asked to create %d sandboxes while the fence was down", rt.createCalls)
	}

	stub.errs = nil
	if _, err := svc.CreateSandbox(context.Background(), models.CreateSandboxRequest{Image: "alpine"}); err != nil {
		t.Fatalf("create after the fence came back: %v", err)
	}
	if rt.createCalls != 1 {
		t.Fatalf("createCalls = %d", rt.createCalls)
	}
}
