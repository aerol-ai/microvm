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
