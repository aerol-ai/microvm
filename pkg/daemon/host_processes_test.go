package daemon

import (
	"bytes"
	"errors"
	"log/slog"
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
func TestWarnMountHelpersEndWithAgent(t *testing.T) {
	const pod = "/kubepods.slice/pod1/sandboxes"
	for _, tc := range []struct {
		name   string
		parent string
		owns   bool
		err    error
		warns  bool
	}{
		{name: "pod that owns its namespace", parent: pod, owns: true, warns: true},
		{name: "pod that shares one", parent: pod},
		{name: "procfs unreadable: nothing to say", parent: pod, err: errors.New("no procfs")},
		{name: "VM", owns: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			old := ownsPIDNamespace
			ownsPIDNamespace = func() (bool, error) { return tc.owns, tc.err }
			t.Cleanup(func() { ownsPIDNamespace = old })
			var logs bytes.Buffer
			warnMountHelpersEndWithAgent(config.Config{HostProcessCgroupParent: tc.parent}, slog.New(slog.NewTextHandler(&logs, nil)))
			if got := strings.Contains(logs.String(), "external-storage mounts stop when this container restarts"); got != tc.warns {
				t.Fatalf("warned %v, want %v: %s", got, tc.warns, logs.String())
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
