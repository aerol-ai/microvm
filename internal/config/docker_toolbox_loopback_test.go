package config

import (
	"strings"
	"testing"
)

func TestDockerToolboxLoopback(t *testing.T) {
	t.Setenv("SB_PAT_TOKEN", "tok")
	t.Setenv("SB_PUBLIC_HOST", "127.0.0.1")
	t.Setenv("SB_DB_PATH", t.TempDir()+"/db.sqlite")
	t.Setenv("SB_CONTAINER_RUNTIME", "docker")
	t.Setenv("SB_TOOLBOX_BINARY_PATH", t.TempDir()+"/toolboxd")

	t.Run("default_off", func(t *testing.T) {
		cfg, err := Load()
		if err != nil {
			t.Fatal(err)
		}
		if cfg.DockerToolboxLoopback {
			t.Fatal("SB_DOCKER_TOOLBOX_LOOPBACK must default to off")
		}
	})

	t.Run("enabled_single_node", func(t *testing.T) {
		t.Setenv("SB_DOCKER_TOOLBOX_LOOPBACK", "true")
		cfg, err := Load()
		if err != nil {
			t.Fatal(err)
		}
		if !cfg.DockerToolboxLoopback {
			t.Fatal("expected loopback toolbox enabled")
		}
	})

	for _, tc := range []struct {
		name string
		env  map[string]string
		want string
	}{
		{"cluster", map[string]string{"SB_ENABLE_CLUSTER": "true"}, "SB_ENABLE_CLUSTER"},
		{"warm_pool", map[string]string{"SB_DOCKER_POOL_ENABLED": "true"}, "SB_DOCKER_POOL_ENABLED"},
		{"netns_pool", map[string]string{"SB_DOCKER_NETNS_POOL_ENABLED": "true"}, "SB_DOCKER_NETNS_POOL_ENABLED"},
		{"host_network", map[string]string{"SB_DOCKER_NETWORK": "host"}, "SB_DOCKER_NETWORK=host"},
	} {
		t.Run("rejects_"+tc.name, func(t *testing.T) {
			t.Setenv("SB_DOCKER_TOOLBOX_LOOPBACK", "true")
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			_, err := Load()
			want := "SB_DOCKER_TOOLBOX_LOOPBACK cannot be combined with " + tc.want
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("Load() error = %v, want %q", err, want)
			}
		})
	}
}
