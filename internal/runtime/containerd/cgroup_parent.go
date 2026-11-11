package containerd

import (
	"context"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/containerd/containerd/v2/core/containers"
	"github.com/containerd/containerd/v2/pkg/oci"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

// CgroupRoot is where the cgroup v2 tree is mounted. A var so tests can point
// CheckCgroupParent at a temporary tree.
var CgroupRoot = "/sys/fs/cgroup"

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
		oci.WithCgroup(path.Join(d.cfg.CgroupParent, id)),
		withOOMScoreAdj(sandboxOOMScoreAdj),
	}
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
