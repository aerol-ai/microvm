package usagemetrics

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeCgroup makes a fake cgroup v2 group under root with the given files.
func writeCgroup(t *testing.T, root, group string, files map[string]string) {
	t.Helper()
	dir := filepath.Join(root, filepath.FromSlash(group))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestReadCgroup(t *testing.T) {
	const cpuStat = "usage_usec 2500000\nuser_usec 2000000\nsystem_usec 500000\n"
	cases := []struct {
		name    string
		group   string // the group passed to ReadCgroup
		files   map[string]string
		want    Consumed
		wantErr string
	}{
		{
			name:  "working set is memory.current less the inactive file cache",
			group: "/aerolvm/sb-1",
			files: map[string]string{
				"cpu.stat":       cpuStat,
				"memory.current": "10485760\n",
				"memory.stat":    "anon 4194304\ninactive_file 2097152\nactive_file 1048576\n",
			},
			want: Consumed{CPUSeconds: 2.5, MemoryBytes: 8 << 20},
		},
		{
			name:  "no memory.stat counts all of memory.current",
			group: "/aerolvm/sb-1",
			files: map[string]string{"cpu.stat": cpuStat, "memory.current": "4096"},
			want:  Consumed{CPUSeconds: 2.5, MemoryBytes: 4096},
		},
		{
			name:  "memory.stat without inactive_file counts all of memory.current",
			group: "/aerolvm/sb-1",
			files: map[string]string{"cpu.stat": cpuStat, "memory.current": "4096", "memory.stat": "anon 4096\n"},
			want:  Consumed{CPUSeconds: 2.5, MemoryBytes: 4096},
		},
		{
			name:  "a cache larger than the total never makes memory negative",
			group: "/aerolvm/sb-1",
			files: map[string]string{"cpu.stat": cpuStat, "memory.current": "4096", "memory.stat": "inactive_file 8192\n"},
			want:  Consumed{CPUSeconds: 2.5, MemoryBytes: 4096},
		},
		{
			name:  "a group with no leading slash is read below the root",
			group: "kubepods/pod1/sandboxes/sb-2",
			files: map[string]string{"cpu.stat": cpuStat, "memory.current": "1"},
			want:  Consumed{CPUSeconds: 2.5, MemoryBytes: 1},
		},
		{
			name:    "a group that does not exist is an error",
			group:   "/aerolvm/missing",
			wantErr: "no such file",
		},
		{
			name:    "cpu.stat without usage_usec is an error",
			group:   "/aerolvm/sb-1",
			files:   map[string]string{"cpu.stat": "user_usec 1\n", "memory.current": "1"},
			wantErr: "usage_usec",
		},
		{
			name:    "a bad usage_usec is an error",
			group:   "/aerolvm/sb-1",
			files:   map[string]string{"cpu.stat": "usage_usec many\n", "memory.current": "1"},
			wantErr: "bad usage_usec",
		},
		{
			name:    "no memory.current is an error",
			group:   "/aerolvm/sb-1",
			files:   map[string]string{"cpu.stat": cpuStat},
			wantErr: "memory.current",
		},
		{
			name:    "a bad memory.current is an error",
			group:   "/aerolvm/sb-1",
			files:   map[string]string{"cpu.stat": cpuStat, "memory.current": "max"},
			wantErr: "bad value",
		},
		{
			name:    "a bad inactive_file is an error",
			group:   "/aerolvm/sb-1",
			files:   map[string]string{"cpu.stat": cpuStat, "memory.current": "1", "memory.stat": "inactive_file x\n"},
			wantErr: "bad inactive_file",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			if tc.files != nil {
				writeCgroup(t, root, tc.group, tc.files)
			}
			got, err := ReadCgroup(root, tc.group)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("ReadCgroup() error = %v, want one containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ReadCgroup() error = %v", err)
			}
			if got != tc.want {
				t.Fatalf("ReadCgroup() = %+v, want %+v", got, tc.want)
			}
		})
	}
}

// A group name can never point outside the cgroup root: ".." is cleaned
// away before the root is joined.
func TestReadCgroupStaysBelowRoot(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "cgroup")
	writeCgroup(t, base, "/outside", map[string]string{"cpu.stat": "usage_usec 1\n", "memory.current": "1"})
	writeCgroup(t, root, "/outside", map[string]string{"cpu.stat": "usage_usec 7000000\n", "memory.current": "7"})
	got, err := ReadCgroup(root, "../outside")
	if err != nil {
		t.Fatalf("ReadCgroup() error = %v", err)
	}
	if got.CPUSeconds != 7 {
		t.Fatalf("ReadCgroup(\"../outside\") read %+v; want the group below the root", got)
	}
}

// A memory.stat that cannot be read for a reason other than being absent
// fails the reading rather than silently counting the cache.
func TestReadCgroupMemoryStatUnreadable(t *testing.T) {
	root := t.TempDir()
	writeCgroup(t, root, "/sb", map[string]string{"cpu.stat": "usage_usec 1\n", "memory.current": "1"})
	// A directory where the file should be: reading it fails with an error
	// that is neither "no such file" nor "key not found".
	if err := os.Mkdir(filepath.Join(root, "sb", "memory.stat"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadCgroup(root, "/sb"); err == nil {
		t.Fatal("ReadCgroup() error = nil, want the memory.stat read error")
	}
}
