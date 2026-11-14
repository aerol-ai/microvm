package service

import (
	"context"
	"errors"
	"testing"

	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
)

// An isolate row is checked against the isolate driver's listing, whatever
// Docker's state. It used to fall through to Docker's: with Docker off
// (SB_DOCKER_ENABLED=false, the Kubernetes worker) or its listing failing,
// the row was skipped, so a gone isolate kept its row, capacity and routes
// for good.
func TestIsolateGoneWithDockerDisabled(t *testing.T) {
	const id = "sb-isolate"
	cases := []struct {
		name          string
		dockerOff     bool
		dockerListErr error
		listed        bool // the isolate driver lists it (it runs)
		noDriver      bool // no isolate driver on this node
		wantRow       bool
		wantDestroyed bool
	}{
		{name: "gone, Docker off", dockerOff: true, wantDestroyed: true},
		{name: "gone, Docker listing fails", dockerListErr: errors.New("dockerd down"), wantDestroyed: true},
		{name: "gone, Docker listed", wantDestroyed: true},
		{name: "running, Docker off", dockerOff: true, listed: true, wantRow: true},
		{name: "no isolate driver here, Docker off", dockerOff: true, noDriver: true, wantRow: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			h := newReapHarness(t)
			h.svc.cfg.DockerDisabled = tc.dockerOff
			h.svc.cfg.ContainerEngine = models.ContainerEngineContainerd
			h.docker.listErr = tc.dockerListErr
			iso := &recordingRuntime{managed: map[string]*models.SandboxRuntimeState{}}
			if tc.listed {
				iso.managed[id] = &models.SandboxRuntimeState{SandboxID: id, Status: models.SandboxStatusStarted}
			}
			if !tc.noDriver {
				h.svc.SetIsolateRuntime(iso)
			}
			h.seed(t, &models.Sandbox{ID: id, Runtime: models.RuntimeIsolate, Status: models.SandboxStatusStarted}, 0)

			if err := h.svc.Reconcile(ctx); err != nil {
				t.Fatalf("Reconcile = %v", err)
			}
			_, err := h.st.Get(ctx, id)
			if tc.wantRow && err != nil {
				t.Fatalf("row = %v, want it kept", err)
			}
			if !tc.wantRow && !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("gone isolate's row survived reconcile: err = %v", err)
			}
			destroyed := len(iso.destroyIDs) == 1 && iso.destroyIDs[0] == id
			if destroyed != tc.wantDestroyed {
				t.Fatalf("isolate driver Destroy calls = %v, want destroyed=%v (its host slot is released there)", iso.destroyIDs, tc.wantDestroyed)
			}
		})
	}
}

func TestRuntimeListingsForSandbox(t *testing.T) {
	l := runtimeListings{
		docker:      map[string]*models.SandboxRuntimeState{"d": {}},
		containerd:  map[string]*models.SandboxRuntimeState{"c": {}},
		firecracker: map[string]*models.SandboxRuntimeState{"f": {}},
		wasm:        map[string]*models.SandboxRuntimeState{"w": {}},
		isolate:     map[string]*models.SandboxRuntimeState{"i": {}},
	}
	cases := []struct {
		sb       models.Sandbox
		want     string
		inDocker bool
	}{
		{models.Sandbox{Runtime: models.RuntimeDocker}, "d", true},
		{models.Sandbox{Runtime: models.RuntimeGvisor}, "d", true},
		{models.Sandbox{Runtime: models.RuntimeDocker, Engine: models.ContainerEngineContainerd}, "c", false},
		{models.Sandbox{Runtime: models.RuntimeGvisor, Engine: models.ContainerEngineContainerd}, "c", false},
		{models.Sandbox{Runtime: models.RuntimeFirecracker}, "f", false},
		{models.Sandbox{Runtime: models.RuntimeWasm}, "w", false},
		{models.Sandbox{Runtime: models.RuntimeIsolate}, "i", false},
		{models.Sandbox{Runtime: models.RuntimeIsolate, Engine: models.ContainerEngineContainerd}, "i", false},
	}
	for _, tc := range cases {
		got, inDocker := l.forSandbox(&tc.sb)
		if _, ok := got[tc.want]; !ok || inDocker != tc.inDocker {
			t.Errorf("forSandbox(runtime=%q engine=%q) = %v inDocker=%v, want listing %q inDocker=%v",
				tc.sb.Runtime, tc.sb.Engine, got, inDocker, tc.want, tc.inDocker)
		}
	}
}
