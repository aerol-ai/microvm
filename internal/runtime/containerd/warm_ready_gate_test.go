package containerd

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	cntr "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/pkg/oci"
	runtimespecs "github.com/opencontainers/runtime-spec/specs-go"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/pool/containerdpool"
	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
)

// A create on a single-node host with only SB_CONTAINERD_POOL_ENABLED on must
// reach the warm pool. Before plan PR #1000 item L2 the daemon built the
// driver with ReadyEnabled=false on such a host, so tryWarmAdopt returned
// ErrNoSlot before it ever looked at the pool, even with a ready slot parked.
func TestTryWarmAdoptReachesPoolOnSingleNodeContainerdHost(t *testing.T) {
	stubToolboxProbe(t)
	singleNode := FromDaemonConfig(config.Config{
		ContainerEngine:          models.ContainerEngineContainerd,
		ContainerdPoolEnabled:    true,
		DockerReadySocketEnabled: true,
	})

	p := containerdpool.New(nil)
	req := models.CreateSandboxRequest{Image: "alpine:3.20"}
	key := containerdpool.KeyFromRequest(req, models.RuntimeDocker)
	p.NoteTarget(key)
	tr := newFakeTransport()
	tr.containers["park-1"] = &fakeContainer{
		id: "park-1", labels: map[string]string{poolParkLabelKey: poolParkLabelValue},
	}
	// A container already named after the sandbox stops adoption right after
	// the slot is taken, so the test needs no guest toolbox to prove the pool
	// was consulted.
	tr.containers["sb-l2"] = &fakeContainer{id: "sb-l2", labels: map[string]string{managedLabelKey: "true"}}

	d := newTestDriver(t)
	d.cfg.ReadyEnabled = singleNode.ReadyEnabled
	d.cfg.ReadyDir = t.TempDir()
	d.SetClient(NewTestClient("aerolvm", tr))
	d.SetWarmPool(p)
	p.RecordLoaded(&containerdpool.ParkedSlot{
		ID: "park-1", ContainerID: "park-1", ContainerIP: "10.88.0.1",
		Key: key, Handle: &fakeHandle{alive: true},
	})

	_, err := d.tryWarmAdopt(context.Background(), req, "sb-l2", "tok", nil, models.RuntimeDocker)
	if errors.Is(err, containerdpool.ErrNoSlot) {
		t.Fatalf("warm pool skipped on a single-node containerd pool host (ReadyEnabled=%v): %v", singleNode.ReadyEnabled, err)
	}
	if !errors.Is(err, docker.ErrSandboxContainerExists) {
		t.Fatalf("err = %v, want the adopt path's name-conflict error", err)
	}
}

// Turning the containerd pool off again turns the ready socket off on a
// single-node host. A sandbox created while it was on still bind-mounts its
// create-time socket, and runc refuses to start a task whose bind source is
// missing, so the restart must recreate that socket from the stored spec, not
// from today's setting. Otherwise rolling back L2 breaks stop/start of every
// sandbox created in between.
func TestStartRecreatesReadySocketAfterPoolTurnedOff(t *testing.T) {
	stubToolboxProbe(t)
	// A short dir: a unix socket path is capped near 104 bytes on macOS.
	readyDir, err := os.MkdirTemp("/tmp", "avml2")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(readyDir) })

	tr := newFakeTransport()
	tr.containers["sb-off"] = &fakeContainer{
		id: "sb-off", task: &fakeTask{status: cntr.Stopped},
		mountCheck: true,
		specOverride: &oci.Spec{
			Process: &runtimespecs.Process{Env: []string{"SB_TOOLBOX_TOKEN=tok"}},
			Mounts: []runtimespecs.Mount{{
				Type: "bind", Destination: docker.GuestReadySocketPath,
				Source: filepath.Join(readyDir, "sb-off.abc123.sock"),
			}},
		},
	}
	d := newTestDriver(t)
	d.cfg.ReadyEnabled = FromDaemonConfig(config.Config{
		ContainerEngine:          models.ContainerEngineContainerd,
		DockerReadySocketEnabled: true,
	}).ReadyEnabled
	if d.cfg.ReadyEnabled {
		t.Fatal("test setup: a single-node host with the pool off must have the ready socket off")
	}
	d.cfg.ReadyDir = readyDir
	d.SetClient(NewTestClient("aerolvm", tr))
	if _, err := d.Start(context.Background(), "sb-off"); err != nil {
		t.Fatalf("restart of a sandbox created with the ready socket on: %v", err)
	}
}
