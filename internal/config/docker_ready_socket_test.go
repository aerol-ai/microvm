package config

import (
	"testing"
)

func TestDockerReadySocketEffectiveGating(t *testing.T) {
	t.Setenv("SB_PAT_TOKEN", "tok")
	t.Setenv("SB_PUBLIC_HOST", "127.0.0.1")
	t.Setenv("SB_DB_PATH", t.TempDir()+"/db.sqlite")
	t.Setenv("SB_CONTAINER_RUNTIME", "docker")
	t.Setenv("SB_TOOLBOX_BINARY_PATH", t.TempDir()+"/toolboxd")

	t.Run("non_cluster_disabled_even_when_knob_true", func(t *testing.T) {
		t.Setenv("SB_ENABLE_CLUSTER", "false")
		t.Setenv("SB_DOCKER_READY_SOCKET_ENABLED", "true")
		cfg, err := Load()
		if err != nil {
			t.Fatal(err)
		}
		if cfg.DockerReadySocketEffective() {
			t.Fatal("expected push disabled on non-cluster host")
		}
	})

	t.Run("cluster_enabled_by_default", func(t *testing.T) {
		t.Setenv("SB_ENABLE_CLUSTER", "true")
		t.Setenv("SB_CLUSTER_BOOTSTRAP", "true")
		t.Setenv("SB_CLUSTER_INSECURE_GOSSIP", "true")
		t.Setenv("SB_CLUSTER_INSECURE_CREDENTIALS", "true")
		t.Setenv("SB_DOCKER_READY_SOCKET_ENABLED", "true")
		cfg, err := Load()
		if err != nil {
			t.Fatal(err)
		}
		if !cfg.DockerReadySocketEffective() {
			t.Fatal("expected push enabled on cluster host")
		}
	})

	t.Run("cluster_knob_false_disables", func(t *testing.T) {
		t.Setenv("SB_ENABLE_CLUSTER", "true")
		t.Setenv("SB_CLUSTER_BOOTSTRAP", "true")
		t.Setenv("SB_CLUSTER_INSECURE_GOSSIP", "true")
		t.Setenv("SB_CLUSTER_INSECURE_CREDENTIALS", "true")
		t.Setenv("SB_DOCKER_READY_SOCKET_ENABLED", "false")
		cfg, err := Load()
		if err != nil {
			t.Fatal(err)
		}
		if cfg.DockerReadySocketEffective() {
			t.Fatal("expected kill switch to disable push")
		}
	})
}

func TestDockerReadySocketDirDerived(t *testing.T) {
	cfg := Config{MountsCredentialsRuntimeDir: "/run/sandboxd/creds"}
	if got := cfg.DockerReadySocketDir(); got != "/run/sandboxd/creds/docker/ready" {
		t.Fatalf("dir = %q", got)
	}
}
