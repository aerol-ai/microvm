package config

import (
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
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

	t.Run("pool_enabled_single_node", func(t *testing.T) {
		t.Setenv("SB_ENABLE_CLUSTER", "false")
		t.Setenv("SB_DOCKER_READY_SOCKET_ENABLED", "true")
		t.Setenv("SB_DOCKER_POOL_ENABLED", "true")
		cfg, err := Load()
		if err != nil {
			t.Fatal(err)
		}
		if !cfg.DockerReadySocketEffective() {
			t.Fatal("expected push enabled when docker warm pool is on")
		}
		if !cfg.DockerPoolEffective() {
			t.Fatal("expected pool effective")
		}
	})

	t.Run("pool_disabled_without_ready_socket", func(t *testing.T) {
		t.Setenv("SB_ENABLE_CLUSTER", "false")
		t.Setenv("SB_DOCKER_READY_SOCKET_ENABLED", "false")
		t.Setenv("SB_DOCKER_POOL_ENABLED", "true")
		cfg, err := Load()
		if err != nil {
			t.Fatal(err)
		}
		if cfg.DockerPoolEffective() {
			t.Fatal("pool requires ready socket knob")
		}
	})

	t.Run("containerd_pool_effective", func(t *testing.T) {
		t.Setenv("SB_ENABLE_CLUSTER", "false")
		t.Setenv("SB_CONTAINER_ENGINE", "containerd")
		t.Setenv("SB_DOCKER_READY_SOCKET_ENABLED", "true")
		t.Setenv("SB_CONTAINERD_POOL_ENABLED", "true")
		cfg, err := Load()
		if err != nil {
			t.Fatal(err)
		}
		if !cfg.ContainerdPoolEffective() {
			t.Fatal("expected containerd pool effective")
		}
	})

	// Plan PR #1000 item L2: the containerd pool alone must turn on the
	// containerd driver's ready socket, and must not change the docker gate.
	t.Run("containerd_pool_single_node_turns_on_containerd_ready_socket", func(t *testing.T) {
		t.Setenv("SB_ENABLE_CLUSTER", "false")
		t.Setenv("SB_CONTAINER_ENGINE", "containerd")
		t.Setenv("SB_CONTAINERD_POOL_ENABLED", "true")
		t.Setenv("SB_DOCKER_POOL_ENABLED", "false")
		cfg, err := Load()
		if err != nil {
			t.Fatal(err)
		}
		if !cfg.ContainerdReadySocketEffective() {
			t.Fatal("containerd pool on, but the containerd ready socket is off")
		}
		if cfg.DockerReadySocketEffective() {
			t.Fatal("docker ready-socket gate must not change for the containerd pool")
		}
	})

	t.Run("containerd_pool_requires_engine", func(t *testing.T) {
		t.Setenv("SB_ENABLE_CLUSTER", "false")
		t.Setenv("SB_CONTAINER_ENGINE", "docker")
		t.Setenv("SB_DOCKER_READY_SOCKET_ENABLED", "true")
		t.Setenv("SB_CONTAINERD_POOL_ENABLED", "true")
		cfg, err := Load()
		if err != nil {
			t.Fatal(err)
		}
		if cfg.ContainerdPoolEffective() {
			t.Fatal("containerd pool must not run on docker engine default")
		}
	})

	t.Run("cluster_enabled_by_default", func(t *testing.T) {
		t.Setenv("SB_ENABLE_CLUSTER", "true")
		t.Setenv("SB_CLUSTER_BOOTSTRAP", "true")
		t.Setenv("SB_CLUSTER_INSECURE_GOSSIP", "true")
		t.Setenv("SB_CLUSTER_INSECURE_CREDENTIALS", "true")
		t.Setenv("SB_CLUSTER_TLS_DIR", t.TempDir())
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
		t.Setenv("SB_CLUSTER_TLS_DIR", t.TempDir())
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

func TestContainerdReadySocketEffective(t *testing.T) {
	ctd := models.ContainerEngineContainerd
	cases := []struct {
		name       string
		cfg        Config
		wantCtd    bool
		wantDocker bool
	}{
		{"all off", Config{ContainerEngine: ctd}, false, false},
		{"knob only, single node", Config{ContainerEngine: ctd, DockerReadySocketEnabled: true}, false, false},
		{"containerd pool, single node", Config{ContainerEngine: ctd, DockerReadySocketEnabled: true, ContainerdPoolEnabled: true}, true, false},
		{"containerd pool, kill switch", Config{ContainerEngine: ctd, ContainerdPoolEnabled: true}, false, false},
		{"containerd pool knob on docker engine", Config{ContainerEngine: models.ContainerEngineDocker, DockerReadySocketEnabled: true, ContainerdPoolEnabled: true}, false, false},
		{"cluster", Config{ContainerEngine: ctd, DockerReadySocketEnabled: true, EnableCluster: true}, true, true},
		{"docker pool", Config{ContainerEngine: ctd, DockerReadySocketEnabled: true, DockerPoolEnabled: true}, true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.cfg.ContainerdReadySocketEffective(); got != tc.wantCtd {
				t.Fatalf("ContainerdReadySocketEffective = %v, want %v", got, tc.wantCtd)
			}
			if got := tc.cfg.DockerReadySocketEffective(); got != tc.wantDocker {
				t.Fatalf("DockerReadySocketEffective = %v, want %v", got, tc.wantDocker)
			}
		})
	}
}

func TestDockerReadySocketDirDerived(t *testing.T) {
	cfg := Config{MountsCredentialsRuntimeDir: "/run/sandboxd/creds"}
	if got := cfg.DockerReadySocketDir(); got != "/run/sandboxd/creds/docker/ready" {
		t.Fatalf("dir = %q", got)
	}
}
