package config

import (
	"strings"
	"testing"
)

// C2: SB_DOCKER_ENABLED=false is a containerd host with no Docker at all.
func TestDockerEnabledConfig(t *testing.T) {
	for _, tc := range []struct {
		name, value, engine, pool, netns string
		wantDisabled                     bool
		wantErr                          string
	}{
		{name: "default: Docker on"},
		{name: "explicitly on", value: "true"},
		{name: "off with containerd", value: "false", engine: "containerd", wantDisabled: true},
		{name: "off needs the containerd engine", value: "false", engine: "docker", wantErr: "needs SB_CONTAINER_ENGINE=containerd"},
		{name: "off with the default engine", value: "false", wantErr: "needs SB_CONTAINER_ENGINE=containerd"},
		{name: "off refuses the Docker warm pool", value: "false", engine: "containerd", pool: "true", wantErr: "SB_DOCKER_POOL_ENABLED=true needs Docker"},
		{name: "off refuses the Docker netns pool", value: "false", engine: "containerd", netns: "true", wantErr: "SB_DOCKER_NETNS_POOL_ENABLED=true needs Docker"},
		{name: "a typo is refused", value: "nope", wantErr: "SB_DOCKER_ENABLED must be true or false"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SB_DOCKER_ENABLED", tc.value)
			t.Setenv("SB_CONTAINER_ENGINE", tc.engine)
			t.Setenv("SB_DOCKER_POOL_ENABLED", tc.pool)
			t.Setenv("SB_DOCKER_NETNS_POOL_ENABLED", tc.netns)
			t.Setenv("SB_ENTERPRISE_MODE", "false")
			t.Setenv("SB_PAT_TOKEN", "pat-token")
			cfg, err := Load()
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("Load = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if cfg.DockerDisabled != tc.wantDisabled {
				t.Fatalf("DockerDisabled = %v, want %v", cfg.DockerDisabled, tc.wantDisabled)
			}
		})
	}
}
