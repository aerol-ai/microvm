package service

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/runtime"
	"github.com/aerol-ai/microvm/pkg/egresspolicy"
	"github.com/aerol-ai/microvm/pkg/models"
)

// newFloorService is a worker with a floor-recording runtime on each of
// docker, containerd and Firecracker, logging into a buffer.
func newFloorService() (*Service, *floorRuntime, *floorRuntime, *floorRuntime, *bytes.Buffer) {
	dockerRT, ctdRT, fcRT := newFloorRuntime(), newFloorRuntime(), newFloorRuntime()
	logs := &bytes.Buffer{}
	svc := &Service{cfg: config.Config{NodeRole: config.NodeRoleWorker}, logger: slog.New(slog.NewTextHandler(logs, nil)),
		docker: dockerRT, containerd: ctdRT, firecracker: fcRT}
	return svc, dockerRT, ctdRT, fcRT, logs
}

func floorGate(svc *Service, engine, rt string) error {
	svc.cfg.ContainerEngine = engine
	return svc.requireEgressFloor(rt)
}

func floorReady(t *testing.T, name string) string {
	t.Helper()
	v := egressFloorReady.Get(name)
	if v == nil {
		return ""
	}
	return v.String()
}

// TestEgressFloorGate: after the boot apply, a runtime whose floor failed
// refuses its creates (and only its own), WASM and isolate never wait for
// it, and a runtime with network rules off (local mode) is allowed outside
// enterprise mode only, like the node guard.
func TestEgressFloorGate(t *testing.T) {
	type gateCase struct {
		name       string
		engine     string
		runtime    string
		enterprise bool
		refused    string // "" = allowed, else a substring of the error
	}
	for _, sc := range []struct {
		name      string
		docker    error
		ctd       error
		fc        error
		wantReady map[string]string
		cases     []gateCase
	}{
		{
			name: "containerd failed, Firecracker without a firewall",
			ctd:  errors.New("iptables gone"), fc: runtime.ErrEgressFloorUnavailable,
			wantReady: map[string]string{models.ContainerEngineDocker: "1", models.ContainerEngineContainerd: "0", models.RuntimeFirecracker: "0"},
			cases: []gateCase{
				{name: "docker's floor is in", engine: models.ContainerEngineDocker, runtime: models.RuntimeDocker},
				{name: "gVisor rides docker's bridge", engine: models.ContainerEngineDocker, runtime: models.RuntimeGvisor},
				{name: "containerd's floor failed", engine: models.ContainerEngineContainerd, runtime: models.RuntimeDocker, refused: "iptables gone"},
				{name: "gVisor on containerd's bridge", engine: models.ContainerEngineContainerd, runtime: models.RuntimeGvisor, refused: "runtime containerd"},
				{name: "WASM has its dial guard", engine: models.ContainerEngineContainerd, runtime: models.RuntimeWasm},
				{name: "isolate has its dial guard", engine: models.ContainerEngineContainerd, runtime: models.RuntimeIsolate},
				{name: "WASM in enterprise mode", engine: models.ContainerEngineContainerd, runtime: models.RuntimeWasm, enterprise: true},
				{name: "Firecracker, network rules off", engine: models.ContainerEngineDocker, runtime: models.RuntimeFirecracker},
				{name: "Firecracker, network rules off, enterprise", engine: models.ContainerEngineDocker, runtime: models.RuntimeFirecracker, enterprise: true, refused: "host firewall is off"},
			},
		},
		{
			name:   "local mode: network rules off everywhere (Docker Desktop on macOS)",
			docker: runtime.ErrEgressFloorUnavailable, ctd: runtime.ErrEgressFloorUnavailable, fc: runtime.ErrEgressFloorUnavailable,
			wantReady: map[string]string{models.ContainerEngineDocker: "0", models.ContainerEngineContainerd: "0", models.RuntimeFirecracker: "0"},
			cases: []gateCase{
				{name: "docker", engine: models.ContainerEngineDocker, runtime: models.RuntimeDocker},
				{name: "containerd", engine: models.ContainerEngineContainerd, runtime: models.RuntimeDocker},
				{name: "Firecracker", engine: models.ContainerEngineDocker, runtime: models.RuntimeFirecracker},
				{name: "enterprise mode still needs it", engine: models.ContainerEngineDocker, runtime: models.RuntimeDocker, enterprise: true, refused: "runtime docker"},
			},
		},
	} {
		t.Run(sc.name, func(t *testing.T) {
			svc, dockerRT, ctdRT, fcRT, logs := newFloorService()
			dockerRT.set(sc.docker, nil, false)
			ctdRT.set(sc.ctd, nil, false)
			fcRT.set(sc.fc, nil, false)
			// Before the daemon applied a floor, nothing is gated.
			if err := floorGate(svc, models.ContainerEngineContainerd, models.RuntimeDocker); err != nil {
				t.Fatalf("before the boot apply: %v", err)
			}
			svc.ApplyEgressFloor(context.Background())
			for name, want := range sc.wantReady {
				if got := floorReady(t, name); got != want {
					t.Errorf("aerolvm_egress_floor_ready{%s} = %q, want %q", name, got, want)
				}
			}
			for _, tc := range sc.cases {
				svc.cfg.EnterpriseMode = tc.enterprise
				err := floorGate(svc, tc.engine, tc.runtime)
				switch {
				case tc.refused == "" && err != nil:
					t.Errorf("%s: refused: %v", tc.name, err)
				case tc.refused != "" && (!errors.Is(err, ErrEgressFloorNotReady) || !strings.Contains(err.Error(), tc.refused)):
					t.Errorf("%s: err = %v, want ErrEgressFloorNotReady naming %q", tc.name, err, tc.refused)
				}
			}
			// Each result is logged once, however often the supervisor
			// retries.
			svc.cfg.EnterpriseMode = false
			for range 3 {
				svc.syncEgressFloor(context.Background(), nil)
			}
			for _, line := range strings.Split(logs.String(), "\n") {
				if line == "" {
					continue
				}
				// One line per runtime: strip the timestamp and compare.
				_, rest, _ := strings.Cut(line, " level=")
				if n := strings.Count(logs.String(), rest); n != 1 {
					t.Errorf("logged %d times: %s", n, rest)
				}
			}
			if sc.ctd != nil && !errors.Is(sc.ctd, runtime.ErrEgressFloorUnavailable) && !strings.Contains(logs.String(), "level=ERROR msg=\"egress floor not installed") {
				t.Errorf("a failed floor must be an error in the log:\n%s", logs.String())
			}
		})
	}
}

// TestEgressFloorSupervisor: a failed runtime is retried on the next tick
// and its creates come back; a floor in place gets only the cheap
// re-assert, when due; a re-assert that fails gates creates until the next
// tick reinstalls the floor.
func TestEgressFloorSupervisor(t *testing.T) {
	ctx := context.Background()
	svc, dockerRT, ctdRT, _, logs := newFloorService()
	ctdRT.set(errors.New("xtables lock"), nil, false)
	svc.ApplyEgressFloor(ctx)
	if err := floorGate(svc, models.ContainerEngineContainerd, models.RuntimeDocker); !errors.Is(err, ErrEgressFloorNotReady) {
		t.Fatalf("a failed boot apply gates: %v", err)
	}

	// The retry succeeds; docker, already in place, is left alone.
	ctdRT.set(nil, nil, false)
	dSets, _ := dockerRT.counts()
	svc.syncEgressFloor(ctx, nil)
	if err := floorGate(svc, models.ContainerEngineContainerd, models.RuntimeDocker); err != nil {
		t.Fatalf("after a successful retry: %v", err)
	}
	if n, re := dockerRT.counts(); n != dSets || re != 0 {
		t.Fatalf("a floor in place is not rewritten between re-asserts: sets=%d reasserts=%d", n, re)
	}
	if got := floorReady(t, models.ContainerEngineContainerd); got != "1" {
		t.Fatalf("ready gauge = %q", got)
	}
	if last := ctdRT.floor[len(ctdRT.floor)-1]; !slices.Equal(last, egresspolicy.MetadataPrefixes) {
		t.Fatalf("the retry installs the floor the node must have: %v", last)
	}

	// The re-assert is due: it runs, and one that had to repair says so.
	svc.egressFloor.checkedAt = time.Now().Add(-2 * nodeGuardReassertInterval)
	dockerRT.set(nil, nil, true)
	svc.syncEgressFloor(ctx, nil)
	if n, re := dockerRT.counts(); n != dSets || re != 1 {
		t.Fatalf("the re-assert, not a rewrite: sets=%d reasserts=%d", n, re)
	}
	if !strings.Contains(logs.String(), "egress floor was missing and has been put back") {
		t.Fatalf("a repair is logged:\n%s", logs.String())
	}
	if err := floorGate(svc, models.ContainerEngineDocker, models.RuntimeDocker); err != nil {
		t.Fatalf("a repaired floor is ready: %v", err)
	}
	// Not due again yet: nothing runs.
	svc.syncEgressFloor(ctx, nil)
	if _, re := dockerRT.counts(); re != 1 {
		t.Fatalf("the re-assert runs every %s, not every tick: %d", nodeGuardReassertInterval, re)
	}

	// A re-assert that fails gates creates; the next tick reinstalls.
	svc.egressFloor.checkedAt = time.Now().Add(-2 * nodeGuardReassertInterval)
	dockerRT.set(nil, errors.New("netlink: socket closed"), false)
	svc.syncEgressFloor(ctx, nil)
	if err := floorGate(svc, models.ContainerEngineDocker, models.RuntimeDocker); !errors.Is(err, ErrEgressFloorNotReady) {
		t.Fatalf("a failed re-assert gates: %v", err)
	}
	if got := floorReady(t, models.ContainerEngineDocker); got != "0" {
		t.Fatalf("ready gauge after a failed re-assert = %q", got)
	}
	dockerRT.set(nil, nil, false)
	svc.syncEgressFloor(ctx, nil)
	if n, _ := dockerRT.counts(); n != dSets+1 || floorGate(svc, models.ContainerEngineDocker, models.RuntimeDocker) != nil {
		t.Fatal("a failed runtime is reinstalled on the next tick")
	}
}

// TestEgressFloorOperatorChange: the old floor does not count. An operator
// file change that fails to install leaves the runtime not ready (the chain
// may be half rewritten, and the operator's new range is open) until a
// retry installs the new floor; an identical or reordered floor rewrites
// nothing.
func TestEgressFloorOperatorChange(t *testing.T) {
	ctx := context.Background()
	svc, dockerRT, _, _, _ := newFloorService()
	svc.ApplyEgressFloor(ctx)
	if err := floorGate(svc, models.ContainerEngineDocker, models.RuntimeDocker); err != nil {
		t.Fatal(err)
	}
	wider := operatorWatcher(t, "version: 1\ndeny_cidrs: [10.20.0.0/16, 192.168.0.0/16]\n").Current()
	want := wider.DenyFloor()

	dockerRT.set(errors.New("xtables lock"), nil, false)
	svc.OnEgressOperatorChange(wider)
	if err := floorGate(svc, models.ContainerEngineDocker, models.RuntimeDocker); !errors.Is(err, ErrEgressFloorNotReady) {
		t.Fatalf("a failed change must not leave the old floor ready: %v", err)
	}
	if got := floorReady(t, models.ContainerEngineDocker); got != "0" {
		t.Fatalf("ready gauge = %q", got)
	}
	dockerRT.set(nil, nil, false)
	svc.syncEgressFloor(ctx, nil)
	if err := floorGate(svc, models.ContainerEngineDocker, models.RuntimeDocker); err != nil {
		t.Fatalf("after the retry: %v", err)
	}
	if last := dockerRT.floor[len(dockerRT.floor)-1]; !slices.Equal(last, want) {
		t.Fatalf("the retry installs the new floor %v, got %v", want, last)
	}

	// The same floor again, or the same entries in another order: no
	// rewrite (SetFloor would flush and refill the chain).
	sets, _ := dockerRT.counts()
	svc.OnEgressOperatorChange(wider)
	svc.OnEgressOperatorChange(operatorWatcher(t, "version: 1\ndeny_cidrs: [192.168.0.0/16, 10.20.0.0/16]\n").Current())
	if n, _ := dockerRT.counts(); n != sets {
		t.Fatalf("an unchanged floor was rewritten %d times", n-sets)
	}
	// A narrower floor is a change like any other.
	svc.OnEgressOperatorChange(operatorWatcher(t, "version: 1\n").Current())
	if n, _ := dockerRT.counts(); n != sets+1 || !slices.Equal(dockerRT.floor[n-1], egresspolicy.MetadataPrefixes) {
		t.Fatalf("the narrower floor was not installed: %v", dockerRT.floor)
	}
}

// TestEgressFloorNeverBlocksWithoutARuntime: a runtime that is not wired,
// or has no host firewall to hold a floor, never gates creates, and nothing
// runs before the daemon applies a floor.
func TestEgressFloorNeverBlocksWithoutARuntime(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name string
		svc  *Service
	}{
		{name: "no runtime wired", svc: &Service{logger: quietLogger()}},
		{name: "a runtime with no floor interface", svc: &Service{logger: quietLogger(), docker: &recordingRuntime{}, containerd: &recordingRuntime{}, firecracker: &recordingRuntime{}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.svc.ApplyEgressFloor(ctx)
			tc.svc.cfg.EnterpriseMode = true
			for _, engine := range []string{models.ContainerEngineDocker, models.ContainerEngineContainerd} {
				for _, rt := range []string{models.RuntimeDocker, models.RuntimeGvisor, models.RuntimeFirecracker, models.RuntimeWasm} {
					if err := floorGate(tc.svc, engine, rt); err != nil {
						t.Fatalf("%s/%s: %v", engine, rt, err)
					}
				}
			}
		})
	}

	// A supervisor tick before the boot apply has no floor to install.
	svc, dockerRT, _, _, _ := newFloorService()
	dockerRT.set(errors.New("never called"), nil, false)
	svc.syncEgressFloor(ctx, nil)
	if n, re := dockerRT.counts(); n != 0 || re != 0 || svc.egressFloor.status.Load() != nil {
		t.Fatalf("a tick before the boot apply ran: sets=%d reasserts=%d", n, re)
	}
	(*Service)(nil).ApplyEgressFloor(ctx)
}

// TestSuperviseEgressFloor: the loop retries until it is cancelled.
func TestSuperviseEgressFloor(t *testing.T) {
	svc, dockerRT, _, _, _ := newFloorService()
	svc.logger = quietLogger()
	dockerRT.set(errors.New("not yet"), nil, false)
	svc.ApplyEgressFloor(context.Background())
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { svc.SuperviseEgressFloor(ctx, time.Millisecond); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if n, _ := dockerRT.counts(); n >= 3 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the supervisor did not retry")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	<-done
	// A zero interval falls back to the default and still stops on cancel.
	done = make(chan struct{})
	go func() { svc.SuperviseEgressFloor(ctx, 0); close(done) }()
	<-done
}

// TestCreateRefusedWithoutEgressFloor: a container create on a node whose
// floor failed never reaches the runtime, and goes through once a retry
// installs it.
func TestCreateRefusedWithoutEgressFloor(t *testing.T) {
	withResolvers(t, nil)
	rt := newFloorRuntime()
	svc, _, _ := newServiceRuntimeHarnessAtPath(t, filepath.Join(t.TempDir(), "state.db"), rt)
	rt.set(errors.New("iptables gone"), nil, false)
	svc.ApplyEgressFloor(context.Background())
	_, err := svc.CreateSandbox(context.Background(), models.CreateSandboxRequest{Image: "alpine"})
	if !errors.Is(err, ErrEgressFloorNotReady) {
		t.Fatalf("create err = %v, want egress floor not ready", err)
	}
	if rt.createCalls != 0 {
		t.Fatal("the runtime must not be called")
	}
	// WASM never waits for the host firewall's floor; its own dial guard
	// holds it. It gets as far as the WASM gate.
	if _, err := svc.CreateSandbox(context.Background(), models.CreateSandboxRequest{Runtime: models.RuntimeWasm, ModuleRef: "m"}); errors.Is(err, ErrEgressFloorNotReady) {
		t.Fatalf("a WASM create waited for the floor: %v", err)
	}
	rt.set(nil, nil, false)
	svc.syncEgressFloor(context.Background(), nil)
	if _, err := svc.CreateSandbox(context.Background(), models.CreateSandboxRequest{Image: "alpine"}); err != nil {
		t.Fatalf("create after the floor is in: %v", err)
	}
}

// TestPrefixesKey: a floor's name ignores order and duplicates.
func TestPrefixesKey(t *testing.T) {
	a := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("169.254.169.254/32")}
	b := []netip.Prefix{a[1], a[0], a[1]}
	if prefixesKey(a) != prefixesKey(b) || prefixesKey(a) != "10.0.0.0/8,169.254.169.254/32" {
		t.Fatalf("%q vs %q", prefixesKey(a), prefixesKey(b))
	}
}
