package daemon

import (
	"errors"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/privmode"
	"github.com/aerol-ai/microvm/internal/supervisor"
)

// A restart of a Kubernetes worker's runtime container alone moves the
// sandboxes' cgroup parent. In privilege mode single, sandboxd stops for
// the kubelet to start it again with the new one (followCgroupParent);
// split hears it from its root helper.

type fakeParentNotifier struct{ fn func(error) }

func (f *fakeParentNotifier) OnCgroupParentMoved(fn func(error)) { f.fn = fn }

func TestFollowCgroupParent(t *testing.T) {
	const file = "/run/aerolvm/cgroup-parent"
	for _, tc := range []struct {
		name   string
		cfg    config.Config
		listen bool
	}{
		{name: "single, with the runtime container's file", cfg: config.Config{PrivilegeMode: privmode.Single, ContainerdCgroupParentFile: file}, listen: true},
		{name: "single, no file (a VM)", cfg: config.Config{PrivilegeMode: privmode.Single}},
		{name: "split: its root helper says it", cfg: config.Config{PrivilegeMode: privmode.Split, ContainerdCgroupParentFile: file}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n := &fakeParentNotifier{}
			var restarted []error
			followCgroupParent(tc.cfg, n, testLogger(), func(err error) { restarted = append(restarted, err) })
			if !tc.listen {
				if n.fn != nil {
					t.Fatal("listening where nothing should")
				}
				return
			}
			if n.fn == nil {
				t.Fatal("not listening for a moved parent")
			}
			moved := errors.New("the runtime container puts sandboxes under another cgroup")
			n.fn(moved)
			if len(restarted) != 1 || !errors.Is(restarted[0], moved) {
				t.Fatalf("restart asked with %v; want the move, once", restarted)
			}
		})
	}
	// No engine wired (Docker): nothing to listen on.
	followCgroupParent(config.Config{ContainerdCgroupParentFile: file}, nil, testLogger(), func(error) { t.Fatal("restart asked") })
}

// The chart gives a single-mode agent the file the runtime container's
// supervisor writes the parent to (its default, as the runtime container
// sets none), the same file the agent's start reads the parent from, on a
// folder both containers mount. A split agent gets none.
func TestChartAgentFollowsTheRuntimeCgroupParentFile(t *testing.T) {
	helm := chartHelm(t)
	for name, flags := range map[string][]string{"single": nil, "cluster": chartClusterFlags} {
		t.Run(name, func(t *testing.T) {
			out, err := renderChart(helm, flags...)
			if err != nil {
				t.Fatal(err)
			}
			agent, runtime := workerEnv(t, out, "agent"), workerEnv(t, out, "runtime")
			written := runtime["SB_CGROUP_PARENT_FILE"]
			if written == "" {
				written = supervisor.SettingsFromEnv().ParentFile
			}
			if got := agent["SB_CONTAINERD_CGROUP_PARENT_FILE"]; got != written {
				t.Fatalf("agent reads the parent again from %q; the supervisor writes it to %q", got, written)
			}
			if !strings.Contains(out, `SB_CONTAINERD_CGROUP_PARENT="$(cat `+written+`)"`) {
				t.Fatalf("the agent's start does not read its parent from %s", written)
			}
		})
	}
	out, err := renderChart(helm, "--set", "privilegeMode=split")
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := workerEnv(t, out, "agent")["SB_CONTAINERD_CGROUP_PARENT_FILE"]; ok {
		t.Fatalf("a split agent reads the parent file %q; its root helper says the parent", got)
	}
}
