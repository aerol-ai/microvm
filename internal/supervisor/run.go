package supervisor

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"
)

// Settings come from the environment (SettingsFromEnv).
type Settings struct {
	// ContainerdBinary and ContainerdConfig run containerd; a missing config
	// is written from `containerd config default`.
	ContainerdBinary string
	ContainerdConfig string
	// ParentFile is where the agent container reads its
	// SB_CONTAINERD_CGROUP_PARENT, on a folder both containers mount.
	ParentFile string
	// NetnsDir holds the network namespaces the agent mounts for sandboxes;
	// they are unmounted when the supervisor stops (UnmountNamespaces).
	NetnsDir string
	// LeaseFile is sandboxd's ownership lease (SB_OWNERSHIP_LEASE_FILE,
	// cluster mode); empty turns the LeaseGuard off.
	LeaseFile string
}

// leaseCheckInterval paces the LeaseGuard: well under sandboxd's own
// expiry check (lease/15, 1 s by default), so the freeze here is never the
// late one.
const leaseCheckInterval = 500 * time.Millisecond

// SettingsFromEnv reads SB_CONTAINERD_BINARY, SB_CONTAINERD_CONFIG,
// SB_CGROUP_PARENT_FILE, SB_NETNS_DIR and SB_OWNERSHIP_LEASE_FILE, with the
// runtime image's defaults.
func SettingsFromEnv() Settings {
	get := func(k, def string) string {
		if v := strings.TrimSpace(os.Getenv(k)); v != "" {
			return v
		}
		return def
	}
	return Settings{
		ContainerdBinary: get("SB_CONTAINERD_BINARY", "containerd"),
		ContainerdConfig: get("SB_CONTAINERD_CONFIG", "/etc/containerd/config.toml"),
		ParentFile:       get("SB_CGROUP_PARENT_FILE", "/run/aerolvm/cgroup-parent"),
		NetnsDir:         get("SB_NETNS_DIR", "/run/netns"),
		LeaseFile:        get("SB_OWNERSHIP_LEASE_FILE", ""),
	}
}

// OS is everything Run does to the machine, so Run is testable anywhere.
type OS struct {
	CgroupRoot   string
	ReadFile     func(string) ([]byte, error)
	Remount      func() error
	LowerOOM     func() error
	BecomeReaper func() error
	StartInGroup func(dir string, argv []string) (int, error)
	Terminate    func(pid int)
	Unmount      func(path string) error
	SetFrozen    func(dir string, frozen bool) error
	Reap         func(watched *atomic.Int64, exited chan<- int, log *slog.Logger)
	// DefaultConfig prints containerd's default configuration.
	DefaultConfig func(binary string) ([]byte, error)
}

// RealOS is the machine.
func RealOS() OS {
	return OS{
		CgroupRoot: CgroupRoot,
		ReadFile:   os.ReadFile,
		Remount: func() error {
			if out, err := exec.Command("mount", "-o", "remount,rw", CgroupRoot).CombinedOutput(); err != nil {
				return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
			}
			return nil
		},
		LowerOOM:     LowerOwnOOMScore,
		BecomeReaper: BecomeReaper,
		StartInGroup: StartInGroup,
		Terminate:    Terminate,
		Unmount:      Unmount,
		SetFrozen:    SetCgroupFrozen,
		Reap:         Reap,
		DefaultConfig: func(binary string) ([]byte, error) {
			return exec.Command(binary, "config", "default").Output()
		},
	}
}

// Run sets the container up and keeps containerd running until ctx ends.
func Run(ctx context.Context, s Settings, sys OS, log *slog.Logger) error {
	if mi, err := sys.ReadFile("/proc/self/mountinfo"); err == nil && CgroupReadOnly(mi, sys.CgroupRoot) {
		// A container that is not privileged gets the cgroup mount
		// read-only (spike S7); its own CAP_SYS_ADMIN may remount it. In a
		// user namespace it may not (spike S9), and C7 cannot work there.
		if err := sys.Remount(); err != nil {
			return fmt.Errorf("the cgroup mount is read-only and could not be made writable (needs CAP_SYS_ADMIN outside a user namespace): %w", err)
		}
		log.Info("supervisor: cgroup mount made writable")
	}
	raw, err := sys.ReadFile("/proc/self/cgroup")
	if err != nil {
		return err
	}
	self, err := SelfCgroup(raw)
	if err != nil {
		return err
	}
	l := Layout{Root: sys.CgroupRoot, Self: self}
	shape, err := Setup(l, log)
	if err != nil {
		return fmt.Errorf("cgroup setup: %w", err)
	}
	log.Info("supervisor: sandboxes go under the pod's own group",
		"parent", shape.Parent, "cap_mib", shape.CapBytes>>20, "reserve_mib", shape.ReserveBytes>>20)
	if err := WriteParentFile(s.ParentFile, shape.Parent); err != nil {
		return fmt.Errorf("publish the cgroup parent: %w", err)
	}
	if err := sys.LowerOOM(); err != nil {
		log.Warn("supervisor: could not lower its own OOM score", "error", err)
	}
	if err := sys.BecomeReaper(); err != nil {
		log.Warn("supervisor: could not become the reaper for orphaned shims", "error", err)
	}
	if err := ensureConfig(s, sys); err != nil {
		return err
	}
	guardDone := make(chan struct{})
	if s.LeaseFile != "" {
		g := &LeaseGuard{File: s.LeaseFile, SandboxesDir: l.dir(sandboxesGroup), SetFrozen: sys.SetFrozen, Now: time.Now, Log: log}
		go func() {
			defer close(guardDone)
			g.Run(ctx, leaseCheckInterval)
		}()
		log.Info("supervisor: enforcing sandboxd's ownership lease", "file", s.LeaseFile)
	} else {
		close(guardDone)
	}

	var watched atomic.Int64
	exited := make(chan int, 1)
	go sys.Reap(&watched, exited, log)
	k := &Keeper{
		Start: func() (int, error) {
			pid, err := sys.StartInGroup(l.RuntimeDir(), []string{s.ContainerdBinary, "--config", s.ContainerdConfig})
			if err == nil {
				watched.Store(int64(pid))
			}
			return pid, err
		},
		Exited:       exited,
		Stop:         sys.Terminate,
		Log:          log,
		MinBackoff:   2 * time.Second,
		MaxBackoff:   30 * time.Second,
		HealthyAfter: time.Minute,
	}
	k.Run(ctx)
	<-guardDone
	UnmountNamespaces(s.NetnsDir, sys.Unmount, log)
	return nil
}

// UnmountNamespaces removes the network-namespace mounts in dir as the pod
// ends. The agent mounts them with Bidirectional propagation so this
// container sees them, which also puts them in the machine's own mount
// table; left there, the kubelet cannot remove the pod's volume and the pod
// stays in Terminating (finding F8, seen on EKS and kind). This container
// stops only with the pod (an agent upgrade never stops it), so it is the
// one that can clean up without ending a live sandbox. Its own mount of dir
// must be Bidirectional too, so the unmount reaches the machine.
func UnmountNamespaces(dir string, unmount func(string) error, log *slog.Logger) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Warn("supervisor: could not list network namespaces to unmount", "dir", dir, "error", err)
		}
		return
	}
	n := 0
	for _, e := range entries {
		p := filepath.Join(dir, e.Name())
		if err := unmount(p); err != nil {
			log.Warn("supervisor: could not unmount a network namespace", "path", p, "error", err)
			continue
		}
		n++
	}
	log.Info("supervisor: network namespaces unmounted", "count", n)
}

func ensureConfig(s Settings, sys OS) error {
	if _, err := os.Stat(s.ContainerdConfig); err == nil {
		return nil
	}
	body, err := sys.DefaultConfig(s.ContainerdBinary)
	if err != nil {
		return fmt.Errorf("containerd config default: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(s.ContainerdConfig), 0o755); err != nil {
		return err
	}
	return os.WriteFile(s.ContainerdConfig, body, 0o644)
}
