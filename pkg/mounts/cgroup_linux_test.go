//go:build linux

package mounts

import (
	"bytes"
	"errors"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/pkg/mounts/adapters"
)

// fakeCgroupRoot stands in a cgroup v2 root holding the helpers' cgroup.
func fakeCgroupRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "cgroup.controllers"), []byte("cpu memory pids\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, helperCgroupName), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, helperCgroupName, "cgroup.procs"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestOpenHelperCgroup(t *testing.T) {
	tests := []struct {
		name    string
		root    func(t *testing.T) string
		wantErr string
	}{
		{"cgroup v2 root", fakeCgroupRoot, ""},
		{"no cgroup v2 hierarchy (v1 host)", func(t *testing.T) string { return t.TempDir() }, "no cgroup v2 hierarchy"},
		{"made directory is not a cgroup", func(t *testing.T) string {
			root := t.TempDir()
			if err := os.WriteFile(filepath.Join(root, "cgroup.controllers"), nil, 0o644); err != nil {
				t.Fatal(err)
			}
			return root
		}, "is not a cgroup"},
		{"cannot make the cgroup", func(t *testing.T) string {
			root := t.TempDir()
			if err := os.WriteFile(filepath.Join(root, "cgroup.controllers"), nil, 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, helperCgroupName), nil, 0o644); err != nil { // a file where the cgroup goes
				t.Fatal(err)
			}
			return root
		}, "not a cgroup"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir, err := openHelperCgroup(tt.root(t))
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("openHelperCgroup: %v", err)
				}
				_ = dir.Close()
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("err = %v, want %q", err, tt.wantErr)
			}
		})
	}
	if os.Geteuid() != 0 {
		root := t.TempDir()
		if err := os.WriteFile(filepath.Join(root, "cgroup.controllers"), nil, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(root, 0o555); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(root, 0o755) })
		if _, err := openHelperCgroup(root); err == nil || !errors.Is(err, os.ErrPermission) {
			t.Fatalf("openHelperCgroup on a read-only root = %v, want a permission error", err)
		}
	}
}

// startRecorder replaces startCmd: it records the cgroup each start asked
// for and, unless refuse says otherwise, starts the tool without it (a test
// cannot join a real cgroup).
type startRecorder struct {
	cgroupFDs []int
	refuse    func(cmd *exec.Cmd) error
}

func (r *startRecorder) install(t *testing.T) {
	t.Helper()
	prev := startCmd
	startCmd = func(cmd *exec.Cmd) error {
		fd := -1
		if cmd.SysProcAttr.UseCgroupFD {
			fd = cmd.SysProcAttr.CgroupFD
		}
		r.cgroupFDs = append(r.cgroupFDs, fd)
		if r.refuse != nil {
			if err := r.refuse(cmd); err != nil {
				return err
			}
		}
		cmd.SysProcAttr.UseCgroupFD = false
		return cmd.Start()
	}
	t.Cleanup(func() { startCmd = prev })
}

func managerWithCgroup(t *testing.T, root string) (*Manager, *bytes.Buffer) {
	t.Helper()
	m := newTestManager(t, nil)
	var logs bytes.Buffer
	m.logger = slog.New(slog.NewTextHandler(&logs, nil))
	m.cgroup = newHelperCgroup(m.logger, root)
	return m, &logs
}

// Every helper is cloned straight into the helpers' cgroup, and the
// descriptor is the cgroup directory opened once.
func TestSpawnHelperStartsInTheCgroup(t *testing.T) {
	m, logs := managerWithCgroup(t, fakeCgroupRoot(t))
	rec := &startRecorder{}
	rec.install(t)

	for i := range 2 {
		cmd, _, exit, err := m.spawnHelper(adapters.Plan{Argv: []string{"true"}}, filepath.Join(t.TempDir(), "0.log"))
		if err != nil {
			t.Fatalf("spawn %d: %v", i, err)
		}
		_ = killMount(cmd)
		<-exit.done
	}
	fd, ok := m.cgroup.fd()
	if !ok || len(rec.cgroupFDs) != 2 || rec.cgroupFDs[0] != fd || rec.cgroupFDs[1] != fd {
		t.Fatalf("starts asked for cgroup fds %v, want both %d (ok=%v)", rec.cgroupFDs, fd, ok)
	}
	if logs.Len() != 0 {
		t.Fatalf("logged with a working cgroup: %s", logs.String())
	}
}

// A kernel that refuses the clone into the cgroup (older than 5.7, a seccomp
// profile, a directory that is not a cgroup) turns the cgroup off, logs once,
// and the helper still starts, as it did before.
func TestSpawnHelperFallsBackWhenTheCloneIsRefused(t *testing.T) {
	m, logs := managerWithCgroup(t, fakeCgroupRoot(t))
	rec := &startRecorder{refuse: func(cmd *exec.Cmd) error {
		if cmd.SysProcAttr.UseCgroupFD {
			return errors.New("fork/exec: function not implemented")
		}
		return nil
	}}
	rec.install(t)

	for i := range 2 {
		cmd, _, exit, err := m.spawnHelper(adapters.Plan{Argv: []string{"true"}}, filepath.Join(t.TempDir(), "0.log"))
		if err != nil {
			t.Fatalf("spawn %d: %v", i, err)
		}
		_ = killMount(cmd)
		<-exit.done
	}
	if _, ok := m.cgroup.fd(); ok {
		t.Fatal("the cgroup stayed on after the kernel refused it")
	}
	// First spawn: refused in the cgroup, then started plain. Second: plain.
	if want := []int{rec.cgroupFDs[0], -1, -1}; len(rec.cgroupFDs) != 3 || rec.cgroupFDs[0] < 0 || rec.cgroupFDs[1] != -1 || rec.cgroupFDs[2] != -1 {
		t.Fatalf("cgroup fds per start = %v, want %v", rec.cgroupFDs, want)
	}
	if n := strings.Count(logs.String(), "mount helpers run in sandboxd's cgroup"); n != 1 || !strings.Contains(logs.String(), "function not implemented") {
		t.Fatalf("want one log naming the refusal, got:\n%s", logs.String())
	}
}

// A tool that cannot start at all is the tool's problem, not the cgroup's:
// the error comes back and the cgroup stays on.
func TestSpawnHelperMissingToolKeepsTheCgroup(t *testing.T) {
	m, logs := managerWithCgroup(t, fakeCgroupRoot(t))
	rec := &startRecorder{}
	rec.install(t)
	_, _, _, err := m.spawnHelper(adapters.Plan{Argv: []string{"/no/such/mount-tool"}}, filepath.Join(t.TempDir(), "0.log"))
	if err == nil || !errors.Is(toolStartError("/no/such/mount-tool", err), ErrMountToolUnavailable) {
		t.Fatalf("err = %v, want a missing-tool error", err)
	}
	if _, ok := m.cgroup.fd(); !ok {
		t.Fatal("a missing tool turned the cgroup off")
	}
	if logs.Len() != 0 {
		t.Fatalf("logged for a missing tool: %s", logs.String())
	}
}

// With the real kernel: a directory that is not a cgroup is refused by
// clone3 (EBADF), or clone3 itself by a seccomp profile (ENOSYS); either
// way the helper starts outside it.
func TestSpawnHelperRealCloneIntoANonCgroupFallsBack(t *testing.T) {
	m, logs := managerWithCgroup(t, fakeCgroupRoot(t))
	cmd, _, exit, err := m.spawnHelper(adapters.Plan{Argv: []string{"true"}}, filepath.Join(t.TempDir(), "0.log"))
	if err != nil {
		t.Fatalf("spawnHelper: %v", err)
	}
	_ = killMount(cmd)
	<-exit.done
	if _, ok := m.cgroup.fd(); ok {
		t.Fatal("the kernel accepted a plain directory as a cgroup")
	}
	if !strings.Contains(logs.String(), "mount helpers run in sandboxd's cgroup") {
		t.Fatalf("the fallback was not logged:\n%s", logs.String())
	}
}
