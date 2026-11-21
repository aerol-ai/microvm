package rootpolicy

import (
	"net/netip"
	"path"
	"strings"
)

// The rules for the root helper's calls for the hostname egress gateway
// (M1 PR 5b): its self-test's probe network, and the executable lookups
// behind per-binary egress rules. The agent sends typed values only; the
// helper probes its own bridge, and reads only a sandbox's processes.

// MaxProbeSlots bounds the self-test's probe slots: one per sandbox bridge
// on a node, far fewer than this.
const MaxProbeSlots = 16

// CheckProbeSlot: a probe slot is a small number; the helper derives the
// probe's names and source address from it.
func CheckProbeSlot(slot uint32) error {
	if slot >= MaxProbeSlots {
		return violate(RuleProbe, "probe slot %d: want 0 to %d", slot, MaxProbeSlots-1)
	}
	return nil
}

// Bounds on one executable lookup: a rule set lists a few dozen paths.
const (
	MaxMatchPaths = 64
	maxMatchPath  = 1024
)

// ProcessMatch is an executable lookup, checked.
type ProcessMatch struct {
	PID           int
	Local, Remote netip.AddrPort
	Paths         []string
}

// CheckProcessMatch checks an executable lookup's request: a process id
// other than init's, the connection's two ends as ip:port, and the paths:
// absolute, clean, bounded, each once. Whether the process is a sandbox's
// is CheckSandboxCgroup's, on what the kernel says.
func CheckProcessMatch(pid uint32, local, remote string, paths []string) (ProcessMatch, error) {
	if pid < 2 || pid > 1<<22 {
		return ProcessMatch{}, violate(RuleProcessMatch, "process id %d", pid)
	}
	m := ProcessMatch{PID: int(pid)}
	for _, a := range []struct {
		s  string
		to *netip.AddrPort
	}{{local, &m.Local}, {remote, &m.Remote}} {
		ap, err := netip.ParseAddrPort(a.s)
		if err != nil || ap.Port() == 0 || ap.Addr().Zone() != "" || ap.String() != a.s {
			return ProcessMatch{}, violate(RuleProcessMatch, "connection end %q: want a plain ip:port", a.s)
		}
		*a.to = ap
	}
	if len(paths) == 0 || len(paths) > MaxMatchPaths {
		return ProcessMatch{}, violate(RuleProcessMatch, "%d paths: want 1 to %d", len(paths), MaxMatchPaths)
	}
	for _, p := range paths {
		if len(p) > maxMatchPath || !strings.HasPrefix(p, "/") || path.Clean(p) != p || strings.ContainsAny(p, "\x00\n") {
			return ProcessMatch{}, violate(RuleProcessMatch, "path %q: want a clean absolute path", p)
		}
		if contains(m.Paths, p) {
			return ProcessMatch{}, violate(RuleProcessMatch, "path %q listed twice", p)
		}
		m.Paths = append(m.Paths, p)
	}
	return m, nil
}

// CheckSandboxCgroup checks a process's cgroup v2 membership, as its
// /proc/<pid>/cgroup reads ("0::/path"): the process must sit in a
// sandbox's cgroup, under the cgroup every sandbox sits directly under,
// in the cgroup of a valid sandbox id or below it. Any other process on the
// node (the helper's, containerd's, the agent's) is not a sandbox's.
func CheckSandboxCgroup(p Policy, procCgroup string) error {
	var cg string
	for _, line := range strings.Split(strings.TrimRight(procCgroup, "\n"), "\n") {
		if v, ok := strings.CutPrefix(line, "0::"); ok {
			cg = v
		}
	}
	if cg == "" || !cleanAbs(cg) {
		return violate(RuleProcessMatch, "cgroup %q: want a cgroup v2 path", cg)
	}
	parent := p.cgroupParent()
	rest, ok := strings.CutPrefix(cg, parent+"/")
	if !ok {
		return violate(RuleProcessMatch, "cgroup %s is not under the sandboxes' %s", cg, parent)
	}
	id, _, _ := strings.Cut(rest, "/")
	if err := ValidateID(id); err != nil {
		return violate(RuleProcessMatch, "cgroup %s: not a sandbox's (%v)", cg, err)
	}
	return nil
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
