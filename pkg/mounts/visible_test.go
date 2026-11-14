package mounts

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts/adapters"
)

// runtimeView stands in procfs for the runtime container: proc/<pid>/root
// points at "/" (the runtime sees what sandboxd sees, as with two-way
// propagation) or at another tree (it sees the folder under the mount), and
// proc/<pid>/ns/mnt is another file than proc/self/ns/mnt (another mount
// namespace) unless ownNamespace links them.
type runtimeView struct {
	t       *testing.T
	proc    string
	pidFile string
}

func newRuntimeView(t *testing.T, m *Manager) *runtimeView {
	t.Helper()
	old := procRoot
	v := &runtimeView{t: t, proc: t.TempDir(), pidFile: filepath.Join(t.TempDir(), "runtime.pid")}
	procRoot = v.proc
	t.Cleanup(func() { procRoot = old })
	m.runtimePIDFile = v.pidFile
	v.file(filepath.Join(v.proc, "self", "ns", "mnt"))
	return v
}

func (v *runtimeView) file(path string) {
	v.t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		v.t.Fatal(err)
	}
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		v.t.Fatal(err)
	}
}

// ownNamespace makes the runtime's pid a process in sandboxd's own mount
// namespace: what a pod without a shared process namespace gives.
func (v *runtimeView) ownNamespace() {
	v.t.Helper()
	ns := filepath.Join(v.proc, "4242", "ns", "mnt")
	_ = os.Remove(ns)
	if err := os.Symlink(filepath.Join(v.proc, "self", "ns", "mnt"), ns); err != nil {
		v.t.Fatal(err)
	}
}

// sees points the runtime's root at root.
func (v *runtimeView) sees(root string) {
	v.t.Helper()
	dir := filepath.Join(v.proc, "4242")
	_ = os.RemoveAll(dir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		v.t.Fatal(err)
	}
	if err := os.Symlink(root, filepath.Join(dir, "root")); err != nil {
		v.t.Fatal(err)
	}
	v.file(filepath.Join(dir, "ns", "mnt"))
	if err := os.WriteFile(v.pidFile, []byte("4242\n"), 0o644); err != nil {
		v.t.Fatal(err)
	}
}

// elsewhere is a tree where every path under the mounts root is a folder of
// its own: what a runtime sees without propagation.
func (v *runtimeView) elsewhere(m *Manager, paths ...string) string {
	v.t.Helper()
	other := v.t.TempDir()
	for _, p := range paths {
		if err := os.MkdirAll(filepath.Join(other, p), 0o755); err != nil {
			v.t.Fatal(err)
		}
	}
	return other
}

func TestCheckVisible(t *testing.T) {
	m := newTestManager(t, nil)
	host := filepath.Join(m.rootDir, "sb-visible", "0")
	if err := os.MkdirAll(host, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := m.checkVisible(host); err != nil {
		t.Fatalf("no runtime pid file (a VM) checks nothing: %v", err)
	}
	v := newRuntimeView(t, m)
	for _, tc := range []struct {
		name  string
		setup func()
		want  string
	}{
		{"no pid file yet", func() {}, "cannot read the runtime's pid"},
		{"not a pid", func() { _ = os.WriteFile(v.pidFile, []byte("runtime"), 0o644) }, "holds no pid"},
		{"no such process", func() { _ = os.WriteFile(v.pidFile, []byte("4242"), 0o644) }, "as the runtime (pid 4242) sees it"},
		{"the folder under the mount", func() { v.sees(v.elsewhere(m, host)) }, "sees the folder under"},
		// Without a shared process namespace the pid file names pid 1 in
		// the runtime's own namespace, which here is sandboxd's container:
		// the same file, proving nothing.
		{"a pid in sandboxd's own mount namespace", func() { v.sees("/"); v.ownNamespace() }, "in sandboxd's own mount namespace"},
		{"the runtime's namespace unreadable", func() { v.sees("/"); _ = os.Remove(filepath.Join(v.proc, "4242", "ns", "mnt")) }, "cannot read the runtime's (pid 4242) mount namespace"},
		{"this container's namespace unreadable", func() { v.sees("/"); _ = os.Remove(filepath.Join(v.proc, "self", "ns", "mnt")) }, "cannot read this container's mount namespace"},
	} {
		tc.setup()
		err := m.checkVisible(host)
		if !errors.Is(err, ErrMountNotVisible) || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want ErrMountNotVisible with %q", tc.name, err, tc.want)
		}
	}
	v.file(filepath.Join(v.proc, "self", "ns", "mnt"))
	v.sees("/")
	if err := m.checkVisible(host); err != nil {
		t.Fatalf("the runtime sees the same mount: %v", err)
	}
	if err := m.checkVisible(filepath.Join(m.rootDir, "missing")); !errors.Is(err, ErrMountNotVisible) {
		t.Fatalf("a mount point that is gone: %v", err)
	}
	// Nothing outside the mounts folder is looked at, however it is spelled.
	for _, p := range []string{t.TempDir(), m.rootDir, filepath.Join(m.rootDir, "sb-visible", "..", "..", "etc")} {
		if err := m.checkVisible(p); !errors.Is(err, ErrMountNotVisible) || !strings.Contains(err.Error(), "not below the mounts folder") {
			t.Errorf("%s: %v, want it refused as outside the mounts folder", p, err)
		}
	}
}

// A mount the runtime cannot see fails the whole set: every mount made is
// torn down and the sandbox's folder removed, so a retry can mount again.
// Before, the create went on and the sandbox wrote to local disk.
func TestMountAllFailsWhenTheRuntimeCannotSeeAMount(t *testing.T) {
	m := newTestManager(t, map[models.MountType]adapters.Adapter{models.MountTypeNFS: fakeAdapter{}})
	v := newRuntimeView(t, m)
	specs := []models.MountSpec{
		{Type: models.MountTypeNFS, Source: "a:/x", Target: "/mnt/a"},
		{Type: models.MountTypeNFS, Source: "b:/y", Target: "/mnt/b"},
	}
	v.sees(v.elsewhere(m, m.hostPath("sb-f13", 0), m.hostPath("sb-f13", 1)))
	_, err := m.MountAll(context.Background(), "sb-f13", specs)
	if !errors.Is(err, ErrMountNotVisible) || !strings.Contains(err.Error(), "mount 0 (nfs)") {
		t.Fatalf("MountAll = %v, want mount 0 refused as not visible", err)
	}
	if _, statErr := os.Stat(filepath.Join(m.rootDir, "sb-f13")); !os.IsNotExist(statErr) {
		t.Fatalf("the sandbox's mount folder was left behind: %v", statErr)
	}
	if binds := m.HostBindsFor("sb-f13"); len(binds) != 0 {
		t.Fatalf("binds kept for a refused set: %+v", binds)
	}
	// With the mounts visible, the same sandbox mounts.
	v.sees("/")
	binds, err := m.MountAll(context.Background(), "sb-f13", specs)
	if err != nil || len(binds) != 2 {
		t.Fatalf("MountAll once visible = %v, %+v", err, binds)
	}
}

func TestNewRuntimePIDFileAndCgroupRoot(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	if _, err := New(logger, Config{RootDir: t.TempDir(), CredDir: t.TempDir(), RuntimePIDFile: "run/aerolvm/runtime.pid"}); err == nil {
		t.Fatal("a relative runtime pid file was accepted")
	}
	root := filepath.Join(t.TempDir(), "kubepods", "pod", "sandboxes")
	m, err := New(logger, Config{RootDir: t.TempDir(), CredDir: t.TempDir(), RuntimePIDFile: "/run/aerolvm/runtime.pid", CgroupRoot: root})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if m.cgroup.root != root || m.runtimePIDFile != "/run/aerolvm/runtime.pid" {
		t.Fatalf("cgroup root %q, pid file %q", m.cgroup.root, m.runtimePIDFile)
	}
	d, err := New(logger, Config{RootDir: t.TempDir(), CredDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if d.cgroup.root != helperCgroupRoot {
		t.Fatalf("default cgroup root %q, want %q", d.cgroup.root, helperCgroupRoot)
	}
}

// A node whose setup cannot keep a mount where the sandbox is built (a
// Kubernetes worker pod with external storage off) refuses every mount set
// before anything starts: no helper, no folder, no adoption. Served anyway,
// the sandbox would write to local disk instead of the store.
func TestMountsUnavailableRefusesEveryMountSet(t *testing.T) {
	m := newTestManager(t, map[models.MountType]adapters.Adapter{models.MountTypeNFS: fakeAdapter{}})
	if err := m.Available(); err != nil {
		t.Fatalf("a node with no reason serves external storage: %v", err)
	}
	m.unavailable = "external storage is off on this worker"
	if err := m.Available(); !errors.Is(err, ErrMountsUnavailable) || !strings.Contains(err.Error(), "off on this worker") {
		t.Fatalf("Available = %v, want ErrMountsUnavailable with the reason", err)
	}
	specs := []models.MountSpec{{Type: models.MountTypeNFS, Source: "a:/x", Target: "/mnt/a"}}
	if _, err := m.MountAll(context.Background(), "sb-off", specs); !errors.Is(err, ErrMountsUnavailable) {
		t.Fatalf("MountAll = %v, want ErrMountsUnavailable", err)
	}
	if err := m.Reestablish(context.Background(), "sb-off", specs); !errors.Is(err, ErrMountsUnavailable) {
		t.Fatalf("Reestablish = %v, want ErrMountsUnavailable", err)
	}
	if _, err := os.Stat(filepath.Join(m.rootDir, "sb-off")); !os.IsNotExist(err) {
		t.Fatalf("a refused set made its folder: %v", err)
	}
	if binds, err := m.MountAll(context.Background(), "sb-none", nil); err != nil || binds != nil {
		t.Fatalf("a create without mounts is untouched: %v, %+v", err, binds)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	n, err := New(logger, Config{RootDir: t.TempDir(), CredDir: t.TempDir(), Unavailable: "off"})
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	if !errors.Is(n.Available(), ErrMountsUnavailable) {
		t.Fatal("Config.Unavailable did not reach the manager")
	}
}
