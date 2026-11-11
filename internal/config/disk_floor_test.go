package config

import (
	"strings"
	"testing"
)

// C27: SB_DISK_FLOOR_RATIO is off unless set, and a value that does not
// parse or is out of range refuses the boot instead of turning it off.
func TestDiskFloorConfig(t *testing.T) {
	t.Setenv("SB_PAT_TOKEN", "tok")
	t.Setenv("SB_PUBLIC_HOST", "127.0.0.1")
	t.Setenv("SB_DB_PATH", t.TempDir()+"/db.sqlite")
	t.Setenv("SB_CONTAINER_RUNTIME", "docker")
	t.Setenv("SB_TOOLBOX_BINARY_PATH", t.TempDir()+"/toolboxd")

	for _, tc := range []struct {
		name, ratio, path string
		want              float64
		err               string
	}{
		{name: "off by default"},
		{name: "ten percent", ratio: "0.10", want: 0.10},
		{name: "explicit zero", ratio: "0"},
		{name: "with a path", ratio: " 0.2 ", path: " /data/sandboxes ", want: 0.2},
		{name: "a percent sign", ratio: "10%", err: `SB_DISK_FLOOR_RATIO must be 0 (off) or a fraction below 1 such as 0.10, got "10%"`},
		{name: "a whole percent", ratio: "10", err: "SB_DISK_FLOOR_RATIO must be 0 (off) or a fraction below 1"},
		{name: "one refuses every create", ratio: "1", err: "SB_DISK_FLOOR_RATIO must be 0 (off) or a fraction below 1"},
		{name: "negative", ratio: "-0.1", err: "SB_DISK_FLOOR_RATIO must be 0 (off) or a fraction below 1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SB_DISK_FLOOR_RATIO", tc.ratio)
			t.Setenv("SB_DISK_FLOOR_PATH", tc.path)
			cfg, err := Load()
			if tc.err != "" {
				if err == nil || !strings.Contains(err.Error(), tc.err) {
					t.Fatalf("Load() error = %v, want %q", err, tc.err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Load(): %v", err)
			}
			if cfg.DiskFloorRatio != tc.want || cfg.DiskFloorPath != strings.TrimSpace(tc.path) {
				t.Fatalf("ratio %v path %q, want %v %q", cfg.DiskFloorRatio, cfg.DiskFloorPath, tc.want, strings.TrimSpace(tc.path))
			}
		})
	}
}
