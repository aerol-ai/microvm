package daemon

import (
	"errors"
	"maps"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/models"
)

// A worker pod whose agent container owns its PID namespace would kill every
// WASM, V8 and Firecracker sandbox at each agent restart: it does not boot
// with them on (C14). Everywhere else the check stays out of the way.
func TestCheckHostProcessesOutliveAgent(t *testing.T) {
	const pod = "/kubepods.slice/pod1/sandboxes"
	worker := func(edit func(*config.Config)) config.Config {
		c := config.Config{NodeRole: config.NodeRoleWorker, HostProcessCgroupParent: pod, EnableWasm: true}
		if edit != nil {
			edit(&c)
		}
		return c
	}
	for _, tc := range []struct {
		name    string
		cfg     config.Config
		owns    bool
		ownsErr error
		wantErr string
	}{
		{name: "shared namespace boots", cfg: worker(nil)},
		{name: "own namespace refused", cfg: worker(nil), owns: true, wantErr: "shareProcessNamespace"},
		{name: "unreadable procfs refused", cfg: worker(nil), ownsErr: errors.New("no procfs"), wantErr: "cannot tell"},
		{name: "V8 alone is checked", cfg: worker(func(c *config.Config) { c.EnableWasm, c.EnableIsolate = false, true }), owns: true, wantErr: "shareProcessNamespace"},
		{name: "gVisor only: not checked", cfg: worker(func(c *config.Config) { c.EnableWasm = false }), owns: true},
		{name: "no cgroup parent (VM or plain container): not checked", cfg: worker(func(c *config.Config) { c.HostProcessCgroupParent = "" }), owns: true},
		{name: "not a worker: not checked", cfg: worker(func(c *config.Config) { c.NodeRole = config.NodeRoleServer }), owns: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			old := ownsPIDNamespace
			ownsPIDNamespace = func() (bool, error) { return tc.owns, tc.ownsErr }
			t.Cleanup(func() { ownsPIDNamespace = old })
			err := checkHostProcessesOutliveAgent(tc.cfg)
			if tc.wantErr == "" && err != nil {
				t.Fatalf("err = %v, want nil", err)
			}
			if tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("err = %v, want it to mention %q", err, tc.wantErr)
			}
		})
	}
}

// External-storage mount helpers die with an agent that owns its PID
// namespace too (F13): a worker pod that does not share one is warned, never
// refused, and nothing is said on a VM or in a shared pod.
// In a Kubernetes worker pod, external storage is served only when the
// chart turned it on (the runtime pid file is set) and the pod shares one
// process namespace; otherwise every mount is refused, never written to
// local disk (F13). Off Kubernetes nothing changes. Fail closed: a pod
// whose namespace cannot be read is refused too.
func TestMountsOffReason(t *testing.T) {
	const pod = "/kubepods.slice/pod1/sandboxes"
	const pidFile = "/run/aerolvm/runtime.pid"
	for _, tc := range []struct {
		name    string
		parent  string
		pidFile string
		owns    bool
		err     error
		want    string // "" = served
	}{
		{name: "VM", owns: true},
		{name: "VM with a pid file", pidFile: pidFile, owns: true},
		{name: "chart value off", parent: pod, want: "worker.externalStorage.enabled"},
		{name: "on, namespace shared", parent: pod, pidFile: pidFile},
		{name: "on, pod owns its namespace", parent: pod, pidFile: pidFile, owns: true, want: "does not share one process namespace"},
		{name: "on, namespace unreadable", parent: pod, pidFile: pidFile, err: errors.New("no procfs"), want: "cannot tell"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			old := ownsPIDNamespace
			ownsPIDNamespace = func() (bool, error) { return tc.owns, tc.err }
			t.Cleanup(func() { ownsPIDNamespace = old })
			got := mountsOffReason(config.Config{HostProcessCgroupParent: tc.parent, MountsRuntimePIDFile: tc.pidFile})
			if (got == "") != (tc.want == "") || !strings.Contains(got, tc.want) {
				t.Fatalf("mountsOffReason = %q, want %q", got, tc.want)
			}
		})
	}
}

// A jailed VM's TAP is made for the jailer's user and group (F33); without
// the jailer it has no owner, as before.
func TestFirecrackerTapHost(t *testing.T) {
	h := firecrackerTapHost(config.Config{FirecrackerIPBinary: "/sbin/ip", UseJailer: true, JailerUID: 990, JailerGID: 991})
	if h.IPCmd != "/sbin/ip" || h.Owner == nil || h.Owner.UID != 990 || h.Owner.GID != 991 {
		t.Fatalf("jailed: %+v %+v", h, h.Owner)
	}
	if h := firecrackerTapHost(config.Config{}); h.Owner != nil {
		t.Fatalf("no jailer: owner %+v", h.Owner)
	}
}

// A worker that moves gVisor sandboxes with their memory says so in its
// capacity labels, which the decommission leader reads on both ends of a
// move (C21); the operator's own labels stay, and nothing else changes.
func TestHostLabels(t *testing.T) {
	pool := map[string]string{"aerolvm.io/pool": "general"}
	for _, tc := range []struct {
		name   string
		cfg    config.Config
		labels map[string]string
	}{
		{"switch off", config.Config{NodeLabels: pool, ContainerEngine: models.ContainerEngineContainerd}, pool},
		{"switch on, Docker engine", config.Config{NodeLabels: pool, GvisorCheckpointMoves: true, ContainerEngine: models.ContainerEngineDocker}, pool},
		{"switch on, containerd", config.Config{NodeLabels: pool, GvisorCheckpointMoves: true, ContainerEngine: models.ContainerEngineContainerd},
			map[string]string{"aerolvm.io/pool": "general", cluster.CheckpointMovesLabel: "true"}},
		{"switch on, no labels of its own", config.Config{GvisorCheckpointMoves: true, ContainerEngine: models.ContainerEngineContainerd},
			map[string]string{cluster.CheckpointMovesLabel: "true"}},
	} {
		got := hostLabels(tc.cfg)
		if !maps.Equal(got, tc.labels) {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.labels)
		}
	}
	if pool[cluster.CheckpointMovesLabel] != "" {
		t.Fatal("hostLabels wrote into the config's own map")
	}
}
