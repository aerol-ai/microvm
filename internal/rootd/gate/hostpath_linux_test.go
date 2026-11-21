//go:build linux

package gate

import (
	"os"
	"path/filepath"
	"testing"

	tasksapi "github.com/containerd/containerd/api/services/tasks/v1"
	"golang.org/x/sys/unix"

	"github.com/aerol-ai/microvm/internal/rootpolicy"
)

// fifoDir is a FIFO folder as the helper will lay it out: a folder per task
// holding that task's FIFOs. Owned by the test's user, which the checker is
// told to trust in place of root, so the test runs without root too.
func fifoDir(t *testing.T) (dir string, c hostPaths) {
	t.Helper()
	dir = t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "task"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(filepath.Join(dir, "task", "out"), 0o660); err != nil {
		t.Fatal(err)
	}
	return dir, hostPaths{owner: uint32(os.Getuid())}
}

func TestFIFOChecker(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, dir string) string // returns the path to check
		ok    bool
	}{
		{"a FIFO in a private folder", func(t *testing.T, dir string) string { return filepath.Join(dir, "task", "out") }, true},
		{"a FIFO in a sticky shared folder", func(t *testing.T, dir string) string {
			// unix.Chmod: os.Chmod drops 0o1000, Go's sticky bit is os.ModeSticky.
			if err := unix.Chmod(filepath.Join(dir, "task"), 0o1777); err != nil {
				t.Fatal(err)
			}
			return filepath.Join(dir, "task", "out")
		}, true},
		{"a symlink to a host file", func(t *testing.T, dir string) string {
			p := filepath.Join(dir, "task", "link")
			if err := os.Symlink("/etc/shadow", p); err != nil {
				t.Fatal(err)
			}
			return p
		}, false},
		{"a symlink to a FIFO", func(t *testing.T, dir string) string {
			p := filepath.Join(dir, "task", "link")
			if err := os.Symlink(filepath.Join(dir, "task", "out"), p); err != nil {
				t.Fatal(err)
			}
			return p
		}, false},
		{"a path through a symlinked folder", func(t *testing.T, dir string) string {
			if err := os.Symlink(filepath.Join(dir, "task"), filepath.Join(dir, "via")); err != nil {
				t.Fatal(err)
			}
			return filepath.Join(dir, "via", "out")
		}, false},
		{"a regular file", func(t *testing.T, dir string) string {
			p := filepath.Join(dir, "task", "file")
			if err := os.WriteFile(p, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			return p
		}, false},
		{"a folder", func(t *testing.T, dir string) string { return filepath.Join(dir, "task") }, false},
		{"a FIFO in a folder others can write", func(t *testing.T, dir string) string {
			if err := os.Chmod(filepath.Join(dir, "task"), 0o777); err != nil {
				t.Fatal(err)
			}
			return filepath.Join(dir, "task", "out")
		}, false},
		{"a FIFO under a regular file", func(t *testing.T, dir string) string {
			if err := os.WriteFile(filepath.Join(dir, "plain"), nil, 0o600); err != nil {
				t.Fatal(err)
			}
			return filepath.Join(dir, "plain", "out")
		}, false},
		{"missing", func(t *testing.T, dir string) string { return filepath.Join(dir, "task", "nope") }, false},
		{"relative", func(*testing.T, string) string { return "task/out" }, false},
		{"unclean", func(t *testing.T, dir string) string { return dir + "/task/../task/out" }, false},
		{"/", func(*testing.T, string) string { return "/" }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, c := fifoDir(t)
			p := tc.setup(t, dir)
			err := c.CheckStdio(p)
			if tc.ok {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				return
			}
			if rootpolicy.RuleOf(err) != rootpolicy.RuleTaskIO {
				t.Fatalf("err %v, want a task_io refusal", err)
			}
		})
	}
}

// TestFIFOCheckerOwners needs root to hand files to another user.
func TestFIFOCheckerOwners(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("needs root to chown")
	}
	t.Run("root's own FIFO passes the default checker", func(t *testing.T) {
		dir, _ := fifoDir(t)
		if err := defaultStdioChecker().CheckStdio(filepath.Join(dir, "task", "out")); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("a FIFO another user made", func(t *testing.T) {
		dir, c := fifoDir(t)
		if err := os.Lchown(filepath.Join(dir, "task", "out"), 65532, 65532); err != nil {
			t.Fatal(err)
		}
		if err := c.CheckStdio(filepath.Join(dir, "task", "out")); rootpolicy.RuleOf(err) != rootpolicy.RuleTaskIO {
			t.Fatalf("err %v", err)
		}
	})
	t.Run("a folder another user owns", func(t *testing.T) {
		dir, c := fifoDir(t)
		if err := os.Lchown(filepath.Join(dir, "task"), 65532, 65532); err != nil {
			t.Fatal(err)
		}
		if err := c.CheckStdio(filepath.Join(dir, "task", "out")); rootpolicy.RuleOf(err) != rootpolicy.RuleTaskIO {
			t.Fatalf("err %v", err)
		}
	})
}

// TestGateStdioOnDisk is finding 3 end to end: a task create whose stdout
// is a symlink to a host file is refused at the gate; one whose stdio are
// real FIFOs goes through.
func TestGateStdioOnDisk(t *testing.T) {
	dir, c := fifoDir(t)
	if err := os.Symlink("/etc/crontab", filepath.Join(dir, "task", "link")); err != nil {
		t.Fatal(err)
	}
	p := testPolicy()
	p.FIFODir = dir
	r := newRig(t, p, func(cfg *Config) { cfg.Stdio = c })
	r.storedContainer(goodContainer(t))
	_, err := r.invoke(nsCtx(), tCreate, &tasksapi.CreateTaskRequest{ContainerID: testID, Rootfs: overlayRootfs(), Stdout: filepath.Join(dir, "task", "link")})
	r.wantRefused(err, tCreate, string(rootpolicy.RuleTaskIO))
	if _, err := r.invoke(nsCtx(), tCreate, &tasksapi.CreateTaskRequest{ContainerID: testID, Rootfs: overlayRootfs(),
		Stdout: filepath.Join(dir, "task", "out"), Stderr: filepath.Join(dir, "task", "out")}); err != nil {
		t.Fatalf("real FIFOs refused: %v", err)
	}
}
