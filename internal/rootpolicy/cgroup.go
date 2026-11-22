package rootpolicy

import (
	"path"
	"strings"

	"github.com/aerol-ai/microvm/internal/ownerlease"
)

// The rules for the root helper's cgroup part of PrepareSandbox
// (plans/security-gaps-m1-m4.md §3.3 "cgroups", M1 PR 6; finding F10 of
// the Kubernetes plan). A sandbox's group sits directly under the
// sandboxes' cgroup parent, beside the machinery's own groups: the worker
// pod's supervisor puts containerd, every shim and the root helper in
// <parent>/_runtime, and the host-process runtimes keep their groups there
// too. The helper makes a started sandbox's group the kernel's whole
// out-of-memory choice: memory.oom.group 1, and a high OOM score on every
// process in it. Done to a machinery group, that would make one
// out-of-memory event kill containerd and the helper with a sandbox, the
// very failure F10 fixed. So the agent names only the container, and the
// helper builds the path from its own parent and checks it here.

// SandboxOOMScoreAdj is the OOM score every process of a sandbox gets once
// its group is marked, in both privilege modes. The machinery runs at
// -999 (the worker pod's supervisor sets it), so the kernel always picks a
// sandbox first.
const SandboxOOMScoreAdj = 500

// SandboxCgroup is the group of the container id under the sandboxes'
// cgroup parent: <parent>/<id>, as the containerd driver places it
// (oci.WithCgroup) and the gate requires (checkCgroup). Refused, with
// RuleCgroup: an id ValidateID refuses (a separator, a dot path, a
// leading "_") and a name the machinery keeps (ownerlease.ReservedGroup:
// "_runtime", "aerolvm-wasm", ...). parent is the helper's own setting,
// never the agent's.
func SandboxCgroup(parent, id string) (string, error) {
	if !cleanAbs(parent) || parent == "/" {
		return "", violate(RuleCgroup, "sandbox cgroup parent %q: want a clean absolute path other than /", parent)
	}
	if err := ValidateID(id); err != nil {
		return "", violate(RuleCgroup, "sandbox cgroup of %q: %v", id, err)
	}
	if ownerlease.ReservedGroup(id) {
		return "", violate(RuleCgroup, "sandbox cgroup %q is a name the sandboxes' parent keeps for AerolVM's own processes", id)
	}
	return path.Join(parent, id), nil
}

// CheckSparesHelper refuses a group to mark that holds the root helper
// itself (helperGroup, its own cgroup v2 path as /proc/self/cgroup names
// it): marked, it would die with a sandbox. A group inside the helper's
// is no risk to it. The supervisor's layout keeps the helper two levels
// below the parent, in _runtime/aerolvm-rootd, which SandboxCgroup
// already refuses; this check holds on any other layout too, from what
// the kernel says.
func CheckSparesHelper(group, helperGroup string) error {
	if !cleanAbs(group) {
		return violate(RuleCgroup, "sandbox cgroup %q: want a clean absolute path", group)
	}
	if !cleanAbs(helperGroup) {
		return violate(RuleCgroup, "the helper's own cgroup %q: want a clean absolute path", helperGroup)
	}
	if group == "/" || group == helperGroup || strings.HasPrefix(helperGroup, group+"/") {
		return violate(RuleCgroup, "sandbox cgroup %s holds the root helper's own (%s)", group, helperGroup)
	}
	return nil
}

// CgroupV2Path reads a cgroup v2 path from a /proc/<pid>/cgroup file:
// the "0::<path>" line. ok is false when there is none (cgroup v1 only).
func CgroupV2Path(procCgroup string) (string, bool) {
	for line := range strings.SplitSeq(strings.TrimRight(procCgroup, "\n"), "\n") {
		if p, found := strings.CutPrefix(line, "0::"); found {
			return p, true
		}
	}
	return "", false
}

// InGroup reports whether a process whose cgroup v2 path is procGroup sits
// in group or below it.
func InGroup(procGroup, group string) bool {
	return procGroup == group || strings.HasPrefix(procGroup, group+"/")
}
