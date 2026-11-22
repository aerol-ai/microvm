package rootpolicy

import (
	"math"
	"path"
	"regexp"
	"strings"
)

// The rules for the root helper's host-process calls
// (plans/security-gaps-m1-m4.md §3.3 "Host processes", M1 PR 9): the
// V8-isolate group hosts, WASM workers and resident hosts that sandboxd
// starts as root in privilege mode single, and the helper starts in split.
//
// The agent names a host by its kind and an id. Everything else is the
// helper's: the binary (from its own settings, never a request), the user
// the host runs as, every folder and the cgroup. So the id is the one
// thing a broken agent controls, and it becomes a folder name and a cgroup
// name: these rules keep it one plain name, of one shape per kind, so it
// can never name a path outside the helper's folders or another kind's
// group.

// HostKind is a kind of host process, as the helper's settings name it.
type HostKind string

// The kinds. Their names are rootdpb.HostKindName's.
const (
	HostWorkerd      HostKind = "workerd"
	HostWasmWorker   HostKind = "wasm_worker"
	HostWasmResident HostKind = "wasm_resident"
)

// The groups each kind's hosts start in, one level under the helper's
// host-process cgroup parent. Each host has a group of its own inside its
// kind's, so the helper finds, limits and kills one host by its group
// alone, and a kind's group never holds a process itself.
const (
	WorkerdHostsGroup = "aerolvm-isolate"
	WasmHostsGroup    = "aerolvm-wasm"
)

// groupKeyPattern is a V8 isolate group key, as the isolate driver makes
// them (internal/runtime/isolate SanitizeGroupKey): it starts with a letter
// or a digit, so it is never "." or "..", never hidden, never an option.
var groupKeyPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$`)

// CheckHostID refuses an id that is not one plain name of kind's shape:
//
//   - a V8 group key: the isolate driver's own pattern, with no "..";
//   - a WASM worker's or resident host's key: a sandbox ID's shape
//     (ValidateID: letters, digits, '-' and '_', at most 128).
func CheckHostID(kind HostKind, id string) error {
	switch kind {
	case HostWorkerd:
		if !groupKeyPattern.MatchString(id) || strings.Contains(id, "..") {
			return violate(RuleHost, "V8 group key %q: want %s with no \"..\"", id, groupKeyPattern)
		}
		return nil
	case HostWasmWorker, HostWasmResident:
		if err := ValidateID(id); err != nil {
			return violate(RuleHost, "%s id: %v", kind, err)
		}
		return nil
	}
	return violate(RuleHost, "host kind %q is not one this helper knows", kind)
}

// HostGroup is the cgroup a host starts in, relative to the helper's
// host-process cgroup parent: <kind's group>/<id>, a WASM worker's as
// w-<id> and a resident host's as r-<id> in the WASM group, so the two
// never share a name. id must have passed CheckHostID.
func HostGroup(kind HostKind, id string) string {
	switch kind {
	case HostWorkerd:
		return path.Join(WorkerdHostsGroup, id)
	case HostWasmWorker:
		return path.Join(WasmHostsGroup, "w-"+id)
	case HostWasmResident:
		return path.Join(WasmHostsGroup, "r-"+id)
	}
	return ""
}

// HostOfGroup reads a host's kind and id back from its group, the inverse
// of HostGroup: ok is false for any group the helper did not name.
func HostOfGroup(group string) (HostKind, string, bool) {
	parent, name, found := strings.Cut(group, "/")
	if !found {
		return "", "", false
	}
	var kind HostKind
	id := name
	switch parent {
	case WorkerdHostsGroup:
		kind = HostWorkerd
	case WasmHostsGroup:
		var ok bool
		if id, ok = strings.CutPrefix(name, "w-"); ok {
			kind = HostWasmWorker
		} else if id, ok = strings.CutPrefix(name, "r-"); ok {
			kind = HostWasmResident
		} else {
			return "", "", false
		}
	default:
		return "", "", false
	}
	if CheckHostID(kind, id) != nil {
		return "", "", false
	}
	return kind, id, true
}

// HostLimits are one host's cgroup limits: CPU in thousandths of a CPU,
// memory in MiB, pids. Zero on an axis is no limit.
type HostLimits struct {
	CPUMillis uint32
	MemoryMB  uint64
	Pids      uint32
}

// CheckHostLimits refuses limits beyond the node (Limits, the helper's own
// copy): a host may not be given more CPU or memory than the machine has,
// nor more pids than any one sandbox may hold. A broken agent can still
// leave a host unlimited, as an unclaimed warm host is; what a limit
// buys is the tenant's own blast radius, and the agent already decides
// who gets which host.
func CheckHostLimits(l HostLimits, node Limits) error {
	if node.CPUs > 0 && float64(l.CPUMillis) > node.CPUs*1000 {
		return violate(RuleHostLimits, "host CPU %d millis is more than the node's %g CPUs", l.CPUMillis, node.CPUs)
	}
	if node.MemoryBytes > 0 && l.MemoryMB > uint64(node.MemoryBytes>>20) {
		return violate(RuleHostLimits, "host memory %d MiB is more than the node's %d MiB", l.MemoryMB, node.MemoryBytes>>20)
	}
	if l.MemoryMB > math.MaxInt64>>20 {
		return violate(RuleHostLimits, "host memory %d MiB is more than a machine can have", l.MemoryMB)
	}
	if node.Pids > 0 && int64(l.Pids) > node.Pids {
		return violate(RuleHostLimits, "host pids %d is more than the node's per-sandbox %d", l.Pids, node.Pids)
	}
	return nil
}

// wasmCacheName is a WASM host's compile cache under the cache root: the
// operator's, one owner's, or one warm-pool slot's (internal/runtime/wasm
// compileCacheFor and SlotCompileCache).
var wasmCacheName = regexp.MustCompile(`^(operator|owner-[0-9a-f]{16}|slots/[0-9a-f]{16}/cache)$`)

// CheckWasmCache refuses a compile cache name the WASM driver does not make.
// Empty is no cache.
func CheckWasmCache(name string) error {
	if name != "" && !wasmCacheName.MatchString(name) {
		return violate(RuleHost, "WASM compile cache %q: want operator, owner-<hash> or slots/<hash>/cache", name)
	}
	return nil
}

// maxSocketPath is the longest path a Unix socket may bind (sun_path less
// its terminating zero).
const maxSocketPath = 107

// WasmHostSocket is the socket a WASM host serves, in the helper's own
// folder dir: w-<id>.sock for a worker, r-<id>.sock for a resident host.
// The agent works the same name out to dial it. Refused, with RuleHost:
// a kind that is not a WASM host, an id CheckHostID refuses, and a path
// too long to bind.
func WasmHostSocket(dir string, kind HostKind, id string) (string, error) {
	if !cleanAbs(dir) || dir == "/" {
		return "", violate(RuleHost, "WASM socket folder %q: want a clean absolute folder other than /", dir)
	}
	var prefix string
	switch kind {
	case HostWasmWorker:
		prefix = "w-"
	case HostWasmResident:
		prefix = "r-"
	default:
		return "", violate(RuleHost, "host kind %q serves no WASM socket", kind)
	}
	if err := CheckHostID(kind, id); err != nil {
		return "", err
	}
	p := path.Join(dir, prefix+id+".sock")
	if len(p) > maxSocketPath {
		return "", violate(RuleHost, "WASM socket %s is longer than a socket path may be (%d)", p, maxSocketPath)
	}
	return p, nil
}
