package capacity

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// cgTree writes files under a fake cgroup root: path -> {file: contents}.
func cgTree(t *testing.T, tree map[string]map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for dir, files := range tree {
		d := filepath.Join(root, filepath.FromSlash(dir))
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		for name, body := range files {
			if err := os.WriteFile(filepath.Join(d, name), []byte(body+"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	return root
}

// The F10 worker's layout (Kubernetes Phase 0): the pod and its container
// carry the pod's limits; sandboxes/ is capped below them; the machine's
// root has none.
const (
	podSlice  = "/kubepods.slice/kubepods-pod1.slice"
	scope     = podSlice + "/cri-containerd-a.scope"
	sandboxes = scope + "/sandboxes"
)

func TestReadCgroupLimit(t *testing.T) {
	for _, tc := range []struct {
		name     string
		tree     map[string]map[string]string
		group    string
		want     CgroupLimit
		errMatch string
	}{
		{
			name: "worker pod: tightest of each, memory from sandboxes/",
			tree: map[string]map[string]string{
				"/":       {"cpu.max": "max 100000", "memory.max": "max"},
				podSlice:  {"cpu.max": "1500000 100000", "memory.max": "57982058496"},
				scope:     {"cpu.max": "1500000 100000", "memory.max": "57982058496"},
				sandboxes: {"memory.max": "53687091200"},
			},
			group: sandboxes,
			want:  CgroupLimit{CPUs: 15, MemoryBytes: 53687091200, MemoryPath: sandboxes},
		},
		{
			name:  "no limits anywhere",
			tree:  map[string]map[string]string{"/": {}, scope: {"cpu.max": "max 100000", "memory.max": "max"}},
			group: scope,
			want:  CgroupLimit{},
		},
		{
			name:  "fractional CPUs",
			tree:  map[string]map[string]string{scope: {"cpu.max": "50000 100000"}},
			group: scope,
			want:  CgroupLimit{CPUs: 0.5},
		},
		{
			name:  "a group namespaced to the root (non-privileged pod)",
			tree:  map[string]map[string]string{"/": {"cpu.max": "300000 100000", "memory.max": "12884901888"}},
			group: "/",
			want:  CgroupLimit{CPUs: 3, MemoryBytes: 12884901888, MemoryPath: "/"},
		},
		{
			name:     "malformed cpu.max",
			tree:     map[string]map[string]string{scope: {"cpu.max": "300000"}},
			group:    scope,
			errMatch: "cpu.max",
		},
		{
			name:     "malformed memory.max",
			tree:     map[string]map[string]string{scope: {"memory.max": "lots"}},
			group:    scope,
			errMatch: "memory.max",
		},
		{
			name:     "zero quota",
			tree:     map[string]map[string]string{scope: {"cpu.max": "0 100000"}},
			group:    scope,
			errMatch: "bad quota",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ReadCgroupLimit(cgTree(t, tc.tree), tc.group)
			if tc.errMatch != "" {
				if err == nil || !strings.Contains(err.Error(), tc.errMatch) {
					t.Fatalf("err = %v, want one naming %q", err, tc.errMatch)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestReadCgroupLimitUnreadable(t *testing.T) {
	root := t.TempDir()
	// A directory where the file should be: os.ReadFile fails with something
	// other than "not there".
	if err := os.MkdirAll(filepath.Join(root, "g", "memory.max"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadCgroupLimit(root, "/g"); err == nil {
		t.Fatal("an unreadable memory.max must be an error, not no limit")
	}
	if err := os.MkdirAll(filepath.Join(root, "h", "cpu.max"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadCgroupLimit(root, "/h"); err == nil {
		t.Fatal("an unreadable cpu.max must be an error, not no limit")
	}
}

func TestHostInfoClampedTo(t *testing.T) {
	host := HostInfo{CPUCores: 16, MemoryTotalMB: 63000, DiskTotalGB: 100}
	for _, tc := range []struct {
		name string
		host HostInfo
		l    CgroupLimit
		want HostInfo
	}{
		{"pod smaller than the machine", host, CgroupLimit{CPUs: 15, MemoryBytes: 53687091200},
			HostInfo{CPUCores: 15, MemoryTotalMB: 51200, DiskTotalGB: 100}},
		{"no limit keeps the machine", host, CgroupLimit{}, host},
		{"a limit above the machine keeps the machine", host, CgroupLimit{CPUs: 64, MemoryBytes: 1 << 40}, host},
		{"half a CPU is one core", host, CgroupLimit{CPUs: 0.5}, HostInfo{CPUCores: 1, MemoryTotalMB: 63000, DiskTotalGB: 100}},
		{"3.9 CPUs round down", host, CgroupLimit{CPUs: 3.9}, HostInfo{CPUCores: 3, MemoryTotalMB: 63000, DiskTotalGB: 100}},
		{"nothing detected takes the limit", HostInfo{}, CgroupLimit{CPUs: 3, MemoryBytes: 12884901888},
			HostInfo{CPUCores: 3, MemoryTotalMB: 12288}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.host.ClampedTo(tc.l)
			if got.CPUCores != tc.want.CPUCores || got.MemoryTotalMB != tc.want.MemoryTotalMB || got.DiskTotalGB != tc.want.DiskTotalGB {
				t.Fatalf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}

type fixedProbe struct {
	mb  int
	err error
}

func (p fixedProbe) FreeMB() (int, error) { return p.mb, p.err }

func TestCgroupMemProbe(t *testing.T) {
	const gib = int64(1 << 30)
	l := CgroupLimit{MemoryBytes: gib, MemoryPath: sandboxes}
	for _, tc := range []struct {
		name     string
		current  string
		fallback MemProbe
		want     int
		wantErr  bool
	}{
		{"room left under the cgroup", "805306368", fixedProbe{mb: 60000}, 256, false},
		{"the machine is fuller than the cgroup", "0", fixedProbe{mb: 100}, 100, false},
		{"over the limit reads as none", "2147483648", fixedProbe{mb: 60000}, 0, false},
		{"no fallback", "805306368", nil, 256, false},
		{"fallback fails", "0", fixedProbe{err: errors.New("meminfo")}, 0, true},
		{"memory.current unreadable", "", fixedProbe{mb: 60000}, 0, true},
		{"memory.current malformed", "lots", fixedProbe{mb: 60000}, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			files := map[string]string{}
			if tc.current != "" {
				files["memory.current"] = tc.current
			}
			root := cgTree(t, map[string]map[string]string{sandboxes: files})
			got, err := NewCgroupMemProbe(root, l, tc.fallback).FreeMB()
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, want error %v", err, tc.wantErr)
			}
			if !tc.wantErr && got != tc.want {
				t.Fatalf("FreeMB = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestCgroupMemProbeCachesAndPassesThrough(t *testing.T) {
	root := cgTree(t, map[string]map[string]string{sandboxes: {"memory.current": "0"}})
	p := NewCgroupMemProbe(root, CgroupLimit{MemoryBytes: 1 << 30, MemoryPath: sandboxes}, nil)
	first, err := p.FreeMB()
	if err != nil || first != 1024 {
		t.Fatalf("first = %d, %v", first, err)
	}
	// A burst of admissions within the cache window reads the file once.
	if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(sandboxes), "memory.current"), []byte("1073741824\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if again, _ := p.FreeMB(); again != first {
		t.Fatalf("within the cache window: %d, want the cached %d", again, first)
	}

	fallback := fixedProbe{mb: 7}
	if got := NewCgroupMemProbe(root, CgroupLimit{}, fallback); got != MemProbe(fallback) {
		t.Fatalf("with no memory limit the probe must be the fallback itself, got %T", got)
	}
}
