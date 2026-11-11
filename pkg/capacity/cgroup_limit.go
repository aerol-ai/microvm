package capacity

import (
	"errors"
	"fmt"
	"io/fs"
	"math"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// CgroupLimit is the tightest CPU and memory limit on a cgroup v2 group and
// every group above it, which is what the kernel enforces on processes in
// it. A zero field means no limit at any level.
//
// It exists for hosts where sandboxes run inside a cgroup of known size:
// a Kubernetes worker pod, whose sandboxes sit under the pod's own group
// (SB_CONTAINERD_CGROUP_PARENT). There the machine's CPUs and memory are
// not what the sandboxes can use, and sizing admission from them let a
// worker accept more than its pod could hold (Kubernetes Phase 0, finding
// F3, which fed F10's out-of-memory runs). On a VM, sandboxes do not live
// under sandboxd's group, so nothing reads this there.
type CgroupLimit struct {
	CPUs        float64
	MemoryBytes int64
	// MemoryPath is the group, relative to the cgroup root, whose
	// memory.max is MemoryBytes: the one whose memory.current says how much
	// of the limit is in use.
	MemoryPath string
}

// ReadCgroupLimit walks from group (a path relative to root, such as
// "/kubepods.slice/kubepods-pod1.slice/cri-containerd-a.scope/sandboxes")
// up to root, reading cpu.max and memory.max at each level. A level without
// those files (its controller not enabled there) sets no limit.
func ReadCgroupLimit(root, group string) (CgroupLimit, error) {
	var l CgroupLimit
	g := path.Clean("/" + group)
	for {
		dir := filepath.Join(root, filepath.FromSlash(g))
		cpus, err := readCPUMax(filepath.Join(dir, "cpu.max"))
		if err != nil {
			return CgroupLimit{}, err
		}
		if cpus > 0 && (l.CPUs == 0 || cpus < l.CPUs) {
			l.CPUs = cpus
		}
		mem, err := readMemoryMax(filepath.Join(dir, "memory.max"))
		if err != nil {
			return CgroupLimit{}, err
		}
		if mem > 0 && (l.MemoryBytes == 0 || mem < l.MemoryBytes) {
			l.MemoryBytes, l.MemoryPath = mem, g
		}
		if g == "/" {
			return l, nil
		}
		g = path.Dir(g)
	}
}

// readCPUMax parses cpu.max ("<quota> <period>" or "max <period>") into
// CPUs; 0 is no limit, as is a missing file.
func readCPUMax(file string) (float64, error) {
	b, err := os.ReadFile(file)
	if errors.Is(err, fs.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	f := strings.Fields(string(b))
	if len(f) != 2 {
		return 0, fmt.Errorf("%s: want \"<quota> <period>\", got %q", file, strings.TrimSpace(string(b)))
	}
	if f[0] == "max" {
		return 0, nil
	}
	quota, err1 := strconv.ParseFloat(f[0], 64)
	period, err2 := strconv.ParseFloat(f[1], 64)
	if err1 != nil || err2 != nil || quota <= 0 || period <= 0 {
		return 0, fmt.Errorf("%s: bad quota or period %q", file, strings.TrimSpace(string(b)))
	}
	return quota / period, nil
}

// readMemoryMax parses memory.max ("max" or bytes); 0 is no limit, as is a
// missing file.
func readMemoryMax(file string) (int64, error) {
	b, err := os.ReadFile(file)
	if errors.Is(err, fs.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	s := strings.TrimSpace(string(b))
	if s == "max" {
		return 0, nil
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("%s: bad limit %q", file, s)
	}
	return n, nil
}

// ClampedTo returns h with CPUCores and MemoryTotalMB no larger than l. A
// fractional CPU limit rounds down, but never below one core: admission
// would otherwise refuse every create on a pod given half a CPU.
func (h HostInfo) ClampedTo(l CgroupLimit) HostInfo {
	if l.CPUs > 0 {
		cores := max(int(math.Floor(l.CPUs)), 1)
		if h.CPUCores == 0 || cores < h.CPUCores {
			h.CPUCores = cores
		}
	}
	if l.MemoryBytes > 0 {
		mb := int(l.MemoryBytes / (1 << 20))
		if h.MemoryTotalMB == 0 || mb < h.MemoryTotalMB {
			h.MemoryTotalMB = mb
		}
	}
	return h
}

// cgroupMemProbe reports the smaller of the machine's free memory and the
// room left under a cgroup's memory limit, so the free-memory floor sees
// the pod running out, not only the machine.
type cgroupMemProbe struct {
	current  string // memory.current of the limiting group
	limit    int64
	fallback MemProbe
	ttl      time.Duration

	mu     sync.Mutex
	cached int
	at     time.Time
}

// NewCgroupMemProbe wraps fallback with l's memory limit. With no memory
// limit in l it returns fallback unchanged.
func NewCgroupMemProbe(root string, l CgroupLimit, fallback MemProbe) MemProbe {
	if l.MemoryBytes <= 0 {
		return fallback
	}
	return &cgroupMemProbe{
		current:  filepath.Join(root, filepath.FromSlash(l.MemoryPath), "memory.current"),
		limit:    l.MemoryBytes,
		fallback: fallback,
		ttl:      500 * time.Millisecond,
	}
}

func (p *cgroupMemProbe) FreeMB() (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.at.IsZero() && time.Since(p.at) < p.ttl {
		return p.cached, nil
	}
	b, err := os.ReadFile(p.current)
	if err != nil {
		return 0, err
	}
	used, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", p.current, err)
	}
	free := int(max(p.limit-used, 0) / (1 << 20))
	if p.fallback != nil {
		machine, err := p.fallback.FreeMB()
		if err != nil {
			return 0, err
		}
		free = min(free, machine)
	}
	p.cached, p.at = free, time.Now()
	return free, nil
}
