package containerd

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/containerd/containerd/v2/core/containers"
	"github.com/containerd/containerd/v2/pkg/oci"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

// CgroupRoot is where the cgroup v2 tree is mounted. A var so tests can point
// CheckCgroupParent at a temporary tree.
var CgroupRoot = "/sys/fs/cgroup"

// ProcRoot is where /proc is mounted. A var so tests can use a temporary tree.
var ProcRoot = "/proc"

// cgroupParentControllers are the controllers a sandbox's own limits need
// (resourceSpecOpts sets CPU, memory and pids). The parent must hand all three
// down to its children, or a sandbox under it would run with no limits.
var cgroupParentControllers = []string{"cpu", "memory", "pids"}

// sandboxOOMScoreAdj is each sandbox's OOM score when a cgroup parent is set.
// Inside a worker pod, sandboxes and the machinery (containerd, sandboxd)
// share one memory limit. When the pod hits it, the kernel kills the process
// with the highest score in the pod; the machinery runs at -999 (the worker's
// supervisor sets that), so a sandbox is always chosen first. Phase 0 spike S3
// found the opposite with the defaults: one pod-level OOM killed every
// sandbox and sandboxd with them (finding F10).
const sandboxOOMScoreAdj = 500

// cgroupSpecOpts places a container's cgroup under the configured parent, as
// <parent>/<id>. With no parent it adds nothing, and containerd's default
// (/<namespace>/<id>, at the root of the machine's tree) stays in force.
//
// Why: inside a Kubernetes worker pod, that default puts every sandbox
// outside the pod's own cgroup, so the pod's limit does not cap sandboxes and
// Kubernetes cannot see their use (plans/kubernetes-v2-architecture.md §8.3,
// C7; Phase 0 spike S1 found runsc-sandbox at /aerolvm/<id>). Every path that
// builds a sandbox's spec (Create, and parkContainer for the warm pool) calls
// this, so no sandbox is ever placed anywhere else once a parent is set.
func (d *Driver) cgroupSpecOpts(id string) []oci.SpecOpts {
	if d.cfg.CgroupParent == "" {
		return nil
	}
	return []oci.SpecOpts{
		oci.WithCgroup(d.sandboxCgroupPath(id)),
		withOOMScoreAdj(sandboxOOMScoreAdj),
	}
}

// sandboxCgroupPath is the cgroup a container gets under the parent: the
// one cgroupSpecOpts asks for and markWholeOOMVictim marks.
func (d *Driver) sandboxCgroupPath(id string) string {
	return path.Join(d.cfg.CgroupParent, id)
}

// SandboxCgroup names the cgroup a sandbox's task runs in, for the usage
// exporter (runtime.CgroupLocator, C20). With a parent it is where
// cgroupSpecOpts put it; with none it is containerd's default,
// /<namespace>/<id>. containerRef is the containerd container id: for a
// sandbox taken from the warm pool, that is its slot's id, the group it was
// parked in. Naming it costs no call to containerd, so a sample of a
// thousand sandboxes adds no load there.
func (d *Driver) SandboxCgroup(containerRef string) string {
	if d.cfg.CgroupParent != "" {
		return d.sandboxCgroupPath(containerRef)
	}
	return path.Join("/", d.cfg.Namespace, containerRef)
}

// markWholeOOMVictim makes a started sandbox the kernel's choice, whole,
// when its pod runs out of memory (Kubernetes Phase 0, finding F10). It runs
// right after each task start (create, restart and warm-pool park), since a
// task's cgroup is made anew each time, and once more when the sandbox is
// ready, for processes gVisor starts after task.Start returns. It writes
// the same two values each time, so a second pass changes nothing else:
//
//   - memory.oom.group 1 on the sandbox's own group, so an out-of-memory
//     kill takes every process in it at once. A gVisor sandbox's memory is
//     one file shared by several of its processes, and killing one of them
//     freed nothing: the pod stayed at its limit (S3's fourth run);
//   - OOM score 500 on every process in the group and those below it. The
//     spec's oomScoreAdj is not enough: runsc applies it to its boot process
//     only, and gVisor's other processes inherit the shim's -999 (S3's third
//     run). Processes started later inherit from these.
//
// The groups above stay at memory.oom.group 0 (the worker sets them), so one
// event never takes the machinery or another sandbox. This replaces the
// Phase 0 harness's keeper loop. A group that is not under the parent (a
// sandbox made before the setting was on) is left as it is. Any failure is
// returned: a sandbox the kernel would not pick whole is the bug this fixes.
func (d *Driver) markWholeOOMVictim(cgroupsPath string) error {
	if d.cfg.CgroupParent == "" || cgroupsPath == "" {
		return nil
	}
	parent := path.Clean(d.cfg.CgroupParent)
	if !strings.HasPrefix(path.Clean(cgroupsPath), parent+"/") {
		return nil
	}
	dir := filepath.Join(CgroupRoot, filepath.FromSlash(cgroupsPath))
	if err := os.WriteFile(filepath.Join(dir, "memory.oom.group"), []byte("1"), 0); err != nil {
		return fmt.Errorf("sandbox cgroup %s: set memory.oom.group: %w", cgroupsPath, err)
	}
	score := []byte(strconv.Itoa(sandboxOOMScoreAdj))
	return filepath.WalkDir(dir, func(p string, e fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !e.IsDir() {
			return nil
		}
		procs, err := os.ReadFile(filepath.Join(p, "cgroup.procs"))
		if err != nil {
			return fmt.Errorf("sandbox cgroup %s: read cgroup.procs: %w", cgroupsPath, err)
		}
		for _, pid := range strings.Fields(string(procs)) {
			err := os.WriteFile(filepath.Join(ProcRoot, pid, "oom_score_adj"), score, 0)
			// A process that has already exited is not a victim to mark.
			if err != nil && !errors.Is(err, fs.ErrNotExist) && !errors.Is(err, syscall.ESRCH) {
				return fmt.Errorf("sandbox cgroup %s: set OOM score of pid %s: %w", cgroupsPath, pid, err)
			}
		}
		return nil
	})
}

// withOOMScoreAdj sets the OOM score the runtime gives the sandbox's
// processes (runc and runsc both apply process.oomScoreAdj).
func withOOMScoreAdj(adj int) oci.SpecOpts {
	return func(_ context.Context, _ oci.Client, _ *containers.Container, s *specs.Spec) error {
		if s.Process == nil {
			s.Process = &specs.Process{}
		}
		v := adj
		s.Process.OOMScoreAdj = &v
		return nil
	}
}

// CheckCgroupParent verifies at boot that parent can hold sandboxes with
// their limits: the tree is cgroup v2, the parent exists, and it hands cpu,
// memory and pids down to its children. sandboxd refuses to start when it
// cannot, rather than create sandboxes that the runtime would place without
// limits or fail one by one.
//
// cgroup v2 lets a group enable controllers for its children only when the
// group holds no processes itself, so whoever sets the parent up (the worker
// pod's supervisor, in the Kubernetes plan) first moves its own processes
// into a child group, then writes +cpu +memory +pids to the parent's
// cgroup.subtree_control.
func CheckCgroupParent(root, parent string) error {
	if _, err := os.Stat(filepath.Join(root, "cgroup.controllers")); err != nil {
		return fmt.Errorf("cgroup parent %s: %s is not a cgroup v2 tree: %w", parent, root, err)
	}
	dir := filepath.Join(root, filepath.FromSlash(parent))
	info, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("cgroup parent %s: %w", parent, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("cgroup parent %s: %s is not a directory", parent, dir)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "cgroup.subtree_control"))
	if err != nil {
		return fmt.Errorf("cgroup parent %s: %w", parent, err)
	}
	enabled := map[string]bool{}
	for c := range strings.FieldsSeq(string(raw)) {
		enabled[c] = true
	}
	var missing []string
	for _, c := range cgroupParentControllers {
		if !enabled[c] {
			missing = append(missing, c)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("cgroup parent %s does not hand %s down to its children (cgroup.subtree_control is %q); "+
			"move any processes out of it, then enable them", parent, strings.Join(missing, ", "), strings.TrimSpace(string(raw)))
	}
	return nil
}
