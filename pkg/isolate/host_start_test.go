package isolate

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestHostStartReportsAnEarlyExitAtOnce: a workerd that dies at start (a
// missing config, a bad flag) ends Start with its exit status well before
// the start timeout. Before, the wait never saw the exit and every such
// start cost the whole timeout with no cause.
func TestHostStartReportsAnEarlyExitAtOnce(t *testing.T) {
	falsePath, err := exec.LookPath("false")
	if err != nil {
		t.Skip("no `false` binary on PATH")
	}
	h, err := NewHost(HostConfig{WorkerdPath: falsePath, GroupKey: "early", RunDir: shortRunDir(t), StartTimeout: 20 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	err = h.Start(context.Background())
	if err == nil {
		_ = h.Stop()
		t.Fatal("Start succeeded with a workerd that exits")
	}
	if !strings.Contains(err.Error(), "exited during startup") {
		t.Fatalf("Start = %v, want an exit report", err)
	}
	if took := time.Since(start); took > 10*time.Second {
		t.Fatalf("Start took %s; the exit should end it at once", took)
	}
	// Start cleaned up after itself: Stop is a no-op and the sockets are gone.
	if err := h.Stop(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(h.hostSock); !os.IsNotExist(err) {
		t.Fatalf("bundle socket left behind: %v", err)
	}
}

// TestHostStartFailureArmsCleanUp walks Start's early failures: each one
// returns an error and leaves no listener behind.
func TestHostStartFailureArmsCleanUp(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T, h *Host)
	}{
		{"run dir is a file", func(t *testing.T, h *Host) {
			parent := shortRunDir(t)
			file := filepath.Join(parent, "f")
			if err := os.WriteFile(file, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			h.cfg.RunDir = filepath.Join(file, "run")
		}},
		{"bundle socket cannot bind", func(t *testing.T, h *Host) {
			h.hostSock = filepath.Join(h.cfg.RunDir, "missing-dir", "h.sock")
		}},
		{"deny socket cannot bind", func(t *testing.T, h *Host) {
			h.egressDenySock = filepath.Join(h.cfg.RunDir, "missing-dir", "d.sock")
		}},
		{"config cannot be written", func(t *testing.T, h *Host) {
			if err := os.Mkdir(filepath.Join(h.cfg.RunDir, controllerModuleName), 0o700); err != nil {
				t.Fatal(err)
			}
		}},
		{"workerd cannot start", func(t *testing.T, h *Host) {
			h.cfg.WorkerdPath = filepath.Join(h.cfg.RunDir, "no-such-workerd")
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, err := NewHost(HostConfig{WorkerdPath: "/bin/sh", GroupKey: "arms", RunDir: shortRunDir(t), StartTimeout: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			tc.setup(t, h)
			if err := h.Start(context.Background()); err == nil {
				_ = h.Stop()
				t.Fatal("Start succeeded")
			}
			if h.bundleSrv != nil {
				// A started bundle server was closed again.
				if err := h.bundleSrv.Close(); err != nil {
					t.Fatalf("bundle server still open: %v", err)
				}
			}
		})
	}
}

// TestApplyJailOffLinuxFailsClosed: off Linux the process half of the jail
// refuses as the file-system half does, never handing back a command that
// would run workerd unconfined.
func TestApplyJailOffLinuxFailsClosed(t *testing.T) {
	if runtime.GOOS == "linux" {
		if err := applyJail(exec.Command("true"), JailConfig{}, nil, nil); err == nil {
			t.Fatal("applyJail without a prepared file system succeeded")
		}
		return
	}
	cmd := exec.Command("true")
	if err := applyJail(cmd, JailConfig{Require: true}, nil, &jailRealized{}); err == nil {
		t.Fatal("applyJail succeeded off linux")
	}
	if cmd.Path != "true" && !strings.HasSuffix(cmd.Path, "/true") {
		t.Fatalf("command rewritten to %q on a refusal", cmd.Path)
	}
}

// TestSmallHelperArms covers the copy, guard and reason helpers' plain arms.
func TestSmallHelperArms(t *testing.T) {
	_ = EgressDialGuard()
	dir := t.TempDir()
	if err := copyFileMode(filepath.Join(dir, "missing"), filepath.Join(dir, "out"), 0o600); err == nil {
		t.Fatal("copy of a missing source succeeded")
	}
	src := filepath.Join(dir, "src")
	if err := os.WriteFile(src, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := copyFileMode(src, filepath.Join(dir, "no-dir", "out"), 0o600); err == nil {
		t.Fatal("copy into a missing dir succeeded")
	}
	if err := copyFileMode(src, filepath.Join(dir, "out"), 0o640); err != nil {
		t.Fatal(err)
	}
	if got := dialReason(os.ErrPermission); got != "blocked" {
		t.Fatalf("dialReason(plain) = %q", got)
	}
}
