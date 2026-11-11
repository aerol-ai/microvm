package config

import (
	"strings"
	"testing"
)

func TestLoadContainerEngine(t *testing.T) {
	t.Run("default is docker (dark default)", func(t *testing.T) {
		t.Setenv("SB_PAT_TOKEN", "operator-pat")
		cfg, err := Load()
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if cfg.ContainerEngine != "docker" {
			t.Fatalf("default ContainerEngine = %q, want docker", cfg.ContainerEngine)
		}
	})

	t.Run("containerd accepted with defaults for socket/namespace", func(t *testing.T) {
		t.Setenv("SB_PAT_TOKEN", "operator-pat")
		t.Setenv("SB_CONTAINER_ENGINE", "containerd")
		cfg, err := Load()
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if cfg.ContainerEngine != "containerd" {
			t.Fatalf("ContainerEngine = %q, want containerd", cfg.ContainerEngine)
		}
		if cfg.ContainerdSocket == "" || cfg.ContainerdNamespace == "" {
			t.Fatal("containerd socket/namespace defaults must be non-empty")
		}
		if cfg.ContainerdRunDir != DefaultContainerdRunDir {
			t.Fatalf("run dir = %q, want %q", cfg.ContainerdRunDir, DefaultContainerdRunDir)
		}
	})

	t.Run("unknown engine rejected", func(t *testing.T) {
		t.Setenv("SB_PAT_TOKEN", "operator-pat")
		t.Setenv("SB_CONTAINER_ENGINE", "podman")
		_, err := Load()
		if err == nil || !strings.Contains(err.Error(), "SB_CONTAINER_ENGINE") {
			t.Fatalf("err = %v, want SB_CONTAINER_ENGINE rejection", err)
		}
	})

	t.Run("case-insensitive normalization", func(t *testing.T) {
		t.Setenv("SB_PAT_TOKEN", "operator-pat")
		t.Setenv("SB_CONTAINER_ENGINE", "Containerd")
		cfg, err := Load()
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if cfg.ContainerEngine != "containerd" {
			t.Fatalf("ContainerEngine = %q, want normalized containerd", cfg.ContainerEngine)
		}
	})
}

// SB_CONTAINERD_CGROUP_PARENT puts every containerd sandbox's cgroup under one
// parent (plans/kubernetes-v2-architecture.md C7). Only a clean absolute path
// below the root is taken, and only on the containerd engine.
func TestLoadContainerdCgroupParent(t *testing.T) {
	for _, tc := range []struct {
		name, engine, parent, wantErr string
	}{
		{"unset keeps the default", "containerd", "", ""},
		{"pod group accepted", "containerd", "/kubepods.slice/kubepods-podx.slice/cri-containerd-y.scope/sandboxes", ""},
		{"relative refused", "containerd", "sandboxes", "SB_CONTAINERD_CGROUP_PARENT"},
		{"root refused", "containerd", "/", "SB_CONTAINERD_CGROUP_PARENT"},
		{"unclean refused", "containerd", "/a/../b", "SB_CONTAINERD_CGROUP_PARENT"},
		{"trailing slash refused", "containerd", "/a/", "SB_CONTAINERD_CGROUP_PARENT"},
		{"docker engine refused", "docker", "/a", "needs SB_CONTAINER_ENGINE=containerd"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SB_PAT_TOKEN", "operator-pat")
			t.Setenv("SB_CONTAINER_ENGINE", tc.engine)
			t.Setenv("SB_CONTAINERD_CGROUP_PARENT", tc.parent)
			cfg, err := Load()
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want it to mention %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if cfg.ContainerdCgroupParent != tc.parent {
				t.Fatalf("ContainerdCgroupParent = %q, want %q", cfg.ContainerdCgroupParent, tc.parent)
			}
		})
	}
}
