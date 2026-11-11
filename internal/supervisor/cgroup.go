// Package supervisor is the first process of the worker pod's runtime
// container (plans/kubernetes-v2-architecture.md §8.2-8.3, C7). It puts the
// container's cgroup in the shape sandboxes need, tells sandboxd where they
// go, and keeps containerd running inside that shape. It never exits on its
// own: the container has no liveness probe, because restarting it would end
// every sandbox in it.
//
// The shape, under this container's own group:
//
//	<self>/
//	├── supervisor/        this process (memory.min = the reserve)
//	└── sandboxes/         SB_CONTAINERD_CGROUP_PARENT (memory.max = limit - reserve)
//	    ├── _runtime/      containerd, and so every shim and runsc helper
//	    └── <sandbox id>/  one per sandbox, made by sandboxd
//
// Each choice was forced by spike S3 (finding F10): cgroup v2 hands
// controllers down only from a group with no processes of its own, so this
// process leaves <self>; a pod at its limit starved sandboxd until
// sandboxes/ got its own cap below it; and containerd's children were
// charged to the machinery's reserve until containerd moved inside the cap.
package supervisor

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

const (
	// CgroupRoot is where cgroup v2 is mounted.
	CgroupRoot = "/sys/fs/cgroup"

	supervisorGroup = "supervisor"
	sandboxesGroup  = "sandboxes"
	runtimeGroup    = "_runtime"

	// The reserve kept for the machinery: a tenth of the container's limit,
	// between 1 and 4 GiB. It only has to cover sandboxd (615 MB at 1,000
	// sandboxes in S3), so the top end is generous.
	reserveMin = int64(1) << 30
	reserveMax = int64(4) << 30
)

// Layout names this container's group on a cgroup v2 mount.
type Layout struct {
	// Root is the cgroup v2 mount (CgroupRoot outside tests).
	Root string
	// Self is this container's group as /proc/self/cgroup names it; "" when
	// the container has its own cgroup namespace and sees its group as "/".
	Self string
}

func (l Layout) dir(parts ...string) string {
	return filepath.Join(append([]string{l.Root, l.Self}, parts...)...)
}

// Parent is SB_CONTAINERD_CGROUP_PARENT: the group sandboxd puts each
// sandbox under, as a path inside the cgroup mount.
func (l Layout) Parent() string { return path.Join("/", l.Self, sandboxesGroup) }

// RuntimeDir is the group containerd runs in.
func (l Layout) RuntimeDir() string { return l.dir(sandboxesGroup, runtimeGroup) }

// SelfCgroup reads this process's cgroup v2 path from /proc/self/cgroup
// ("0::/path"). A machine on cgroup v1 has no such line, and C7 needs v2.
func SelfCgroup(procSelfCgroup []byte) (string, error) {
	sc := bufio.NewScanner(bytes.NewReader(procSelfCgroup))
	for sc.Scan() {
		if p, ok := strings.CutPrefix(sc.Text(), "0::"); ok {
			if p == "/" {
				return "", nil
			}
			return path.Clean(p), nil
		}
	}
	return "", errors.New("no cgroup v2 entry in /proc/self/cgroup: the worker needs cgroup v2")
}

// Shape is what Setup made.
type Shape struct {
	Parent string
	// CapBytes is sandboxes/'s memory.max, 0 when the container has no
	// memory limit (nothing to cap below).
	CapBytes     int64
	ReserveBytes int64
}

// Setup builds the shape. Moving this container's processes and handing the
// controllers down must succeed: without them sandboxes would get no limits,
// and C7 refuses that. The OOM-group and memory settings are best effort,
// as in the spike, and logged when they fail.
func Setup(l Layout, log *slog.Logger) (Shape, error) {
	for _, d := range []string{l.dir(supervisorGroup), l.dir(sandboxesGroup), l.RuntimeDir()} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return Shape{}, fmt.Errorf("make %s: %w", d, err)
		}
	}
	if err := moveProcs(l.dir("cgroup.procs"), l.dir(supervisorGroup, "cgroup.procs")); err != nil {
		return Shape{}, err
	}
	const controllers = "+cpu +memory +pids"
	for _, d := range []string{l.dir(), l.dir(sandboxesGroup)} {
		if err := os.WriteFile(filepath.Join(d, "cgroup.subtree_control"), []byte(controllers), 0o644); err != nil {
			return Shape{}, fmt.Errorf("hand %s down from %s: %w", controllers, d, err)
		}
	}
	// One out-of-memory event must kill one process (sandboxd then makes
	// each sandbox's own group kill as a whole), never this container or
	// all sandboxes together: the kubelet's default puts oom.group 1 on the
	// container.
	oomGroups := []string{l.dir(), l.dir(sandboxesGroup), l.RuntimeDir()}
	if l.Self != "" {
		oomGroups = append(oomGroups, filepath.Join(l.Root, path.Dir(l.Self)))
	}
	for _, d := range oomGroups {
		if err := os.WriteFile(filepath.Join(d, "memory.oom.group"), []byte("0"), 0o644); err != nil {
			log.Warn("supervisor: could not turn off group OOM kills", "group", d, "error", err)
		}
	}
	shape := Shape{Parent: l.Parent()}
	limit, err := readMemoryMax(l.dir("memory.max"))
	switch {
	case err != nil:
		log.Warn("supervisor: could not read the container's memory limit; sandboxes/ is not capped", "error", err)
	case limit == 0:
		log.Warn("supervisor: the container has no memory limit; sandboxes/ is not capped")
	default:
		reserve := min(max(limit/10, reserveMin), reserveMax)
		if limit <= reserve {
			log.Warn("supervisor: the container's memory limit is below the machinery's reserve; sandboxes/ is not capped",
				"limit_bytes", limit, "reserve_bytes", reserve)
			break
		}
		if err := os.WriteFile(l.dir(sandboxesGroup, "memory.max"), []byte(strconv.FormatInt(limit-reserve, 10)), 0o644); err != nil {
			return Shape{}, fmt.Errorf("cap sandboxes/: %w", err)
		}
		if err := os.WriteFile(l.dir(supervisorGroup, "memory.min"), []byte(strconv.FormatInt(reserve, 10)), 0o644); err != nil {
			log.Warn("supervisor: could not keep the reserve for the machinery", "error", err)
		}
		shape.CapBytes, shape.ReserveBytes = limit-reserve, reserve
	}
	return shape, nil
}

// moveProcs moves every process listed in from into to. A process that
// exited in between is no error. A few passes catch one forked meanwhile.
func moveProcs(from, to string) error {
	for pass := 0; pass < 5; pass++ {
		raw, err := os.ReadFile(from)
		if err != nil {
			return fmt.Errorf("list this container's processes: %w", err)
		}
		pids := strings.Fields(string(raw))
		if len(pids) == 0 {
			return nil
		}
		for _, pid := range pids {
			if err := moveProc(to, pid); err != nil && !isNoProcess(err) {
				return fmt.Errorf("move process %s into %s: %w", pid, to, err)
			}
		}
	}
	return fmt.Errorf("processes keep appearing in %s", from)
}

// moveProc moves one process: the kernel takes it out of its old group.
// Tests replace it, since a folder of plain files does not.
var moveProc = func(to, pid string) error { return os.WriteFile(to, []byte(pid), 0o644) }

// readMemoryMax reads a memory.max file: 0 for "max" (no limit).
func readMemoryMax(p string) (int64, error) {
	raw, err := os.ReadFile(p)
	if err != nil {
		return 0, err
	}
	v := strings.TrimSpace(string(raw))
	if v == "max" {
		return 0, nil
	}
	return strconv.ParseInt(v, 10, 64)
}

// WriteParentFile publishes the parent for the agent container, which reads
// it from the shared folder at start. Written whole, then renamed into
// place, so a reader never sees half a path.
func WriteParentFile(file, parent string) error {
	if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
		return err
	}
	tmp := file + ".tmp"
	if err := os.WriteFile(tmp, []byte(parent+"\n"), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, file)
}

// CgroupReadOnly reports whether /proc/self/mountinfo shows the cgroup mount
// read-only, as a container that is not privileged gets it (spike S7).
func CgroupReadOnly(mountinfo []byte, root string) bool {
	sc := bufio.NewScanner(bytes.NewReader(mountinfo))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) > 5 && f[4] == root {
			for _, opt := range strings.Split(f[5], ",") {
				if opt == "ro" {
					return true
				}
			}
			return false
		}
	}
	return false
}

// isNoProcess: writing a pid that has exited to cgroup.procs fails ESRCH.
func isNoProcess(err error) bool { return errors.Is(err, syscall.ESRCH) }
