package gvisorpids

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"
)

func TestLimits(t *testing.T) {
	cases := []struct {
		name       string
		pidsLimit  int64
		memoryMB   int
		wantSentry int64
		wantHost   int64
	}{
		// The bank campaign's default sandbox: 1 GiB caps the sentry at 1024,
		// and the host cgroup holds two host tasks per sandbox task plus the
		// sentry's own threads, so the sentry refuses the fork first.
		{"default sandbox", 4096, 1024, 1024, 2*1024 + 1024},
		{"memory above the node limit keeps the node limit", 4096, 8192, 4096, 2*4096 + 1024},
		{"memory equal to the node limit", 4096, 4096, 4096, 2*4096 + 1024},
		{"small sandbox gets the floor", 4096, 64, 128, 2*128 + 1024},
		{"floor never exceeds the node limit", 100, 64, 100, 2*100 + 1024},
		{"node limit below memory cap", 512, 1024, 512, 2*512 + 1024},
		{"no memory size uses the node limit", 4096, 0, 4096, 2*4096 + 1024},
		{"negative memory uses the node limit", 4096, -1, 4096, 2*4096 + 1024},
		{"unlimited node gets no limits", 0, 1024, 0, 0},
		{"negative node limit is unlimited", -1, 1024, 0, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sentry, host := Limits(tc.pidsLimit, tc.memoryMB)
			if sentry != tc.wantSentry || host != tc.wantHost {
				t.Fatalf("Limits(%d, %d) = (%d, %d), want (%d, %d)", tc.pidsLimit, tc.memoryMB, sentry, host, tc.wantSentry, tc.wantHost)
			}
			if sentry > 0 && host < hostTasksPerTask*sentry {
				t.Fatalf("host limit %d cannot hold %d sandbox tasks at %d host tasks each", host, sentry, hostTasksPerTask)
			}
		})
	}
}

// writePidsMax lays out root/rel with content, like gVisor's cgroupfs.
func writePidsMax(t *testing.T, root, rel, content string) string {
	t.Helper()
	path := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestApply(t *testing.T) {
	cases := []struct {
		name    string
		files   map[string]string // rel path -> current content
		limit   int64
		wantRel string
		want    string // content of wantRel after Apply
	}{
		// runsc's default in-sandbox layout (v1), as UC-320 read it: "max".
		{"v1 unlimited is lowered", map[string]string{"sys/fs/cgroup/pids/pids.max": "max\n"}, 1024, "sys/fs/cgroup/pids/pids.max", "1024"},
		{"v2 unlimited is lowered", map[string]string{"sys/fs/cgroup/pids.max": "max\n"}, 1024, "sys/fs/cgroup/pids.max", "1024"},
		{"v1 wins over v2", map[string]string{"sys/fs/cgroup/pids/pids.max": "max\n", "sys/fs/cgroup/pids.max": "max\n"}, 1024, "sys/fs/cgroup/pids/pids.max", "1024"},
		{"a higher number is lowered", map[string]string{"sys/fs/cgroup/pids/pids.max": "4096\n"}, 1024, "sys/fs/cgroup/pids/pids.max", "1024"},
		{"a lower number is kept", map[string]string{"sys/fs/cgroup/pids/pids.max": "512\n"}, 1024, "sys/fs/cgroup/pids/pids.max", "512\n"},
		{"an equal number is kept", map[string]string{"sys/fs/cgroup/pids/pids.max": "1024\n"}, 1024, "sys/fs/cgroup/pids/pids.max", "1024\n"},
		{"unparsable content is overwritten", map[string]string{"sys/fs/cgroup/pids/pids.max": "garbage"}, 1024, "sys/fs/cgroup/pids/pids.max", "1024"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			for rel, content := range tc.files {
				writePidsMax(t, root, rel, content)
			}
			got, err := Apply(root, tc.limit)
			if err != nil {
				t.Fatalf("Apply: %v", err)
			}
			if want := filepath.Join(root, tc.wantRel); got != want {
				t.Fatalf("Apply set %q, want %q", got, want)
			}
			if c := readFile(t, got); c != tc.want {
				t.Fatalf("%s = %q, want %q", tc.wantRel, c, tc.want)
			}
		})
	}
}

func TestApplyNoController(t *testing.T) {
	// containerd's default spec has no /sys/fs/cgroup mount: UC-320 read
	// "none" there, and Apply must say so instead of creating a file.
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "sys/fs/cgroup"), 0o755); err != nil {
		t.Fatal(err)
	}
	path, err := Apply(root, 1024)
	if !errors.Is(err, ErrNoPidsController) || path != "" {
		t.Fatalf("Apply = (%q, %v), want ErrNoPidsController", path, err)
	}
	if _, err := os.Stat(filepath.Join(root, "sys/fs/cgroup/pids.max")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Apply created pids.max: %v", err)
	}
}

func TestApplyRejectsNonPositive(t *testing.T) {
	for _, limit := range []int64{0, -5} {
		if _, err := Apply(t.TempDir(), limit); err == nil || errors.Is(err, ErrNoPidsController) {
			t.Fatalf("Apply(limit=%d) = %v, want a validation error", limit, err)
		}
	}
}

func TestApplyReadAndWriteErrors(t *testing.T) {
	t.Run("unreadable pids.max", func(t *testing.T) {
		root := t.TempDir()
		// A directory where the file should be: ReadFile fails with
		// something other than not-exist, and Apply must not skip to v2.
		if err := os.MkdirAll(filepath.Join(root, "sys/fs/cgroup/pids/pids.max"), 0o755); err != nil {
			t.Fatal(err)
		}
		writePidsMax(t, root, "sys/fs/cgroup/pids.max", "max\n")
		path, err := Apply(root, 1024)
		if err == nil || path != filepath.Join(root, "sys/fs/cgroup/pids/pids.max") {
			t.Fatalf("Apply = (%q, %v), want the v1 read error", path, err)
		}
	})
	t.Run("read-only pids.max", func(t *testing.T) {
		if runtime.GOOS == "windows" || os.Geteuid() == 0 {
			t.Skip("root writes through file modes")
		}
		root := t.TempDir()
		path := writePidsMax(t, root, "sys/fs/cgroup/pids/pids.max", "max\n")
		if err := os.Chmod(path, 0o444); err != nil {
			t.Fatal(err)
		}
		// An image whose USER is not root meets exactly this in gVisor.
		got, err := Apply(root, 1024)
		if !errors.Is(err, os.ErrPermission) || got != path {
			t.Fatalf("Apply = (%q, %v), want a permission error on %q", got, err, path)
		}
	})
}

func TestWriteExistingMissingFile(t *testing.T) {
	if err := writeExisting(filepath.Join(t.TempDir(), "absent"), "1"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("writeExisting on a missing file = %v, want not-exist (it must not create one)", err)
	}
}

func TestForRuntime(t *testing.T) {
	cases := []struct {
		name       string
		ociRuntime string
		pidsLimit  int64
		memoryMB   int
		wantHost   int64
		wantEnv    []string
	}{
		{"runsc default sandbox", "runsc", 4096, 1024, 3072, []string{EnvVar + "=1024"}},
		{"runsc large sandbox", "runsc", 4096, 8192, 9216, []string{EnvVar + "=4096"}},
		{"runsc unlimited node", "runsc", 0, 1024, 0, nil},
		{"runc default runtime", "", 4096, 1024, 4096, nil},
		{"runc by name", "runc", 4096, 1024, 4096, nil},
		{"runc unlimited node", "", 0, 1024, 0, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			host, env := ForRuntime(tc.ociRuntime, tc.pidsLimit, tc.memoryMB)
			if host != tc.wantHost || !slices.Equal(env, tc.wantEnv) {
				t.Fatalf("ForRuntime(%q, %d, %d) = (%d, %v), want (%d, %v)", tc.ociRuntime, tc.pidsLimit, tc.memoryMB, host, env, tc.wantHost, tc.wantEnv)
			}
		})
	}
}

func TestWriteExistingWriteError(t *testing.T) {
	// /dev/full accepts the open and fails every write (ENOSPC).
	if _, err := os.Stat("/dev/full"); err != nil {
		t.Skip("no /dev/full on this platform")
	}
	if err := writeExisting("/dev/full", "1024"); err == nil {
		t.Fatal("writeExisting to /dev/full succeeded, want the write error")
	}
}
