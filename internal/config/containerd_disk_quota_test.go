package config

import (
	"strings"
	"testing"
)

// C27: SB_CONTAINERD_DISK_QUOTA is off unless set, parsed strictly, and only
// the containerd engine takes it.
func TestContainerdDiskQuotaConfig(t *testing.T) {
	t.Setenv("SB_PAT_TOKEN", "tok")
	t.Setenv("SB_PUBLIC_HOST", "127.0.0.1")
	t.Setenv("SB_DB_PATH", t.TempDir()+"/db.sqlite")
	t.Setenv("SB_CONTAINER_RUNTIME", "docker")
	t.Setenv("SB_TOOLBOX_BINARY_PATH", t.TempDir()+"/toolboxd")
	t.Setenv("SB_CONTAINERD_SOCKET", "/run/containerd/containerd.sock")
	t.Setenv("SB_CONTAINERD_NAMESPACE", "aerolvm")

	for _, tc := range []struct {
		name, engine, value string
		want                bool
		err                 string
	}{
		{name: "off by default", engine: "containerd"},
		{name: "on", engine: "containerd", value: "true", want: true},
		{name: "explicitly off", engine: "containerd", value: "false"},
		{name: "off on docker is fine", engine: "docker", value: "false"},
		{name: "a typo refuses the boot", engine: "containerd", value: "yes please", err: `SB_CONTAINERD_DISK_QUOTA must be true or false, got "yes please"`},
		{name: "docker cannot enforce it", engine: "docker", value: "true", err: "SB_CONTAINERD_DISK_QUOTA=true needs SB_CONTAINER_ENGINE=containerd"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SB_CONTAINER_ENGINE", tc.engine)
			t.Setenv("SB_CONTAINERD_DISK_QUOTA", tc.value)
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
			if cfg.ContainerdDiskQuota != tc.want {
				t.Fatalf("ContainerdDiskQuota = %v, want %v", cfg.ContainerdDiskQuota, tc.want)
			}
		})
	}
}
