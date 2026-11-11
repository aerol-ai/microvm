package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	cntr "github.com/aerol-ai/microvm/internal/runtime/containerd"
	"github.com/aerol-ai/microvm/pkg/capacity"
)

type fixedMemProbe int

func (p fixedMemProbe) FreeMB() (int, error) { return int(p), nil }

// fakeCgroupRoot points the containerd driver's cgroup root at a temp tree
// for the test: group -> {file: contents}.
func fakeCgroupRoot(t *testing.T, tree map[string]map[string]string) {
	t.Helper()
	root := t.TempDir()
	for dir, files := range tree {
		d := filepath.Join(root, filepath.FromSlash(dir))
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		for name, body := range files {
			if err := os.WriteFile(filepath.Join(d, name), []byte(body+"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	old := cntr.CgroupRoot
	cntr.CgroupRoot = root
	t.Cleanup(func() { cntr.CgroupRoot = old })
}

// Regression (Kubernetes Phase 0, finding F3): a worker pod's admission was
// sized from the machine (16 CPUs, 63 GB) rather than what its sandboxes may
// use; now it is the cgroup parent's limits, and the free-memory probe reads
// the room under them.
func TestCapacityFromCgroupParent(t *testing.T) {
	machine := capacity.HostInfo{CPUCores: 16, MemoryTotalMB: 63000}
	const parent = "/kubepods.slice/kubepods-pod1.slice/cri-containerd-a.scope/sandboxes"

	t.Run("no cgroup parent changes nothing", func(t *testing.T) {
		probe := fixedMemProbe(5000)
		host, got, err := capacityFromCgroupParent(config.Config{}, testLogger(), machine, probe)
		if err != nil || host.CPUCores != machine.CPUCores || host.MemoryTotalMB != machine.MemoryTotalMB || got != capacity.MemProbe(probe) {
			t.Fatalf("got %+v, %T, %v; want the machine and the same probe", host, got, err)
		}
	})

	t.Run("sized from the cgroup parent and its pod", func(t *testing.T) {
		fakeCgroupRoot(t, map[string]map[string]string{
			"/kubepods.slice/kubepods-pod1.slice/cri-containerd-a.scope": {"cpu.max": "1500000 100000", "memory.max": "57982058496"},
			parent: {"memory.max": "53687091200", "memory.current": "52613349376"},
		})
		host, probe, err := capacityFromCgroupParent(config.Config{ContainerdCgroupParent: parent}, testLogger(), machine, fixedMemProbe(60000))
		if err != nil {
			t.Fatal(err)
		}
		if host.CPUCores != 15 || host.MemoryTotalMB != 51200 {
			t.Fatalf("host = %+v, want 15 cores and 51200 MB", host)
		}
		free, err := probe.FreeMB()
		if err != nil || free != 1024 {
			t.Fatalf("FreeMB = %d, %v; want the 1024 MB left under sandboxes/, not the machine's 60000", free, err)
		}
	})

	t.Run("an unreadable limit is an error", func(t *testing.T) {
		fakeCgroupRoot(t, map[string]map[string]string{parent: {"cpu.max": "garbage"}})
		_, _, err := capacityFromCgroupParent(config.Config{ContainerdCgroupParent: parent}, testLogger(), machine, fixedMemProbe(1))
		if err == nil || !strings.Contains(err.Error(), "read the limits of the sandboxes' cgroup") {
			t.Fatalf("err = %v", err)
		}
	})
}

// The daemon refuses to start, as C7's own check does, rather than admit
// sandboxes against the machine's size.
func TestRunStopsOnUnreadableCgroupParentLimits(t *testing.T) {
	paths := setBaseRunEnv(t)
	setNoDockerEnv(t, paths)
	const parent = "/kubepods.slice/pod/scope/sandboxes"
	fakeCgroupRoot(t, map[string]map[string]string{parent: {"memory.max": "lots"}})
	t.Setenv("SB_CONTAINER_ENGINE", "containerd")
	t.Setenv("SB_CONTAINERD_CGROUP_PARENT", parent)

	err, _ := runCapturingLogs(t, 3*time.Second)
	if err == nil || !strings.Contains(err.Error(), "read the limits of the sandboxes' cgroup") {
		t.Fatalf("Run = %v, want the cgroup limit error", err)
	}
}
