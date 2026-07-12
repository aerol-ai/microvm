package service

import (
	"errors"
	"testing"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/models"
)

func TestOCIEngineRouting(t *testing.T) {
	dockerRT := &recordingRuntime{}
	containerdRT := &recordingRuntime{}

	t.Run("docker host routes new creates to docker driver", func(t *testing.T) {
		svc := &Service{cfg: config.Config{ContainerEngine: models.ContainerEngineDocker}, docker: dockerRT}
		rt, err := svc.ociEngineForNewCreate()
		if err != nil || rt != dockerRT {
			t.Fatalf("ociEngineForNewCreate(docker) = (%T, %v), want docker", rt, err)
		}
	})

	t.Run("containerd host routes new creates to containerd driver", func(t *testing.T) {
		svc := &Service{cfg: config.Config{ContainerEngine: models.ContainerEngineContainerd}, docker: dockerRT}
		svc.SetContainerdRuntime(containerdRT)
		rt, err := svc.ociEngineForNewCreate()
		if err != nil || rt != containerdRT {
			t.Fatalf("ociEngineForNewCreate(containerd) = (%T, %v), want containerd", rt, err)
		}
	})

	t.Run("containerd host without driver returns ErrContainerEngineNotRegistered", func(t *testing.T) {
		svc := &Service{cfg: config.Config{ContainerEngine: models.ContainerEngineContainerd}, docker: dockerRT}
		if _, err := svc.ociEngineForNewCreate(); !errors.Is(err, models.ErrContainerEngineNotRegistered) {
			t.Fatalf("err = %v, want ErrContainerEngineNotRegistered", err)
		}
	})

	t.Run("engine=containerd row routes to containerd driver", func(t *testing.T) {
		svc := &Service{cfg: config.Config{}, docker: dockerRT}
		svc.SetContainerdRuntime(containerdRT)
		sb := &models.Sandbox{Runtime: models.RuntimeDocker, Engine: models.ContainerEngineContainerd}
		rt, err := svc.runtimeForSandbox(sb)
		if err != nil || rt != containerdRT {
			t.Fatalf("runtimeForSandbox(engine=containerd) = (%T, %v), want containerd", rt, err)
		}
	})

	t.Run("engine=containerd row on docker-only node errors, does not fall to docker", func(t *testing.T) {
		svc := &Service{cfg: config.Config{}, docker: dockerRT}
		sb := &models.Sandbox{Runtime: models.RuntimeDocker, Engine: models.ContainerEngineContainerd}
		if _, err := svc.runtimeForSandbox(sb); !errors.Is(err, models.ErrContainerEngineNotRegistered) {
			t.Fatalf("err = %v, want ErrContainerEngineNotRegistered", err)
		}
	})

	t.Run("legacy engine-empty docker row routes to docker", func(t *testing.T) {
		svc := &Service{cfg: config.Config{}, docker: dockerRT}
		sb := &models.Sandbox{Runtime: models.RuntimeDocker, Engine: ""}
		rt, err := svc.runtimeForSandbox(sb)
		if err != nil || rt != dockerRT {
			t.Fatalf("runtimeForSandbox(legacy docker) = (%T, %v), want docker", rt, err)
		}
	})

	// Regression: an unrecognized runtime string must resolve terminally to
	// the docker engine, NOT recurse between runtimeForSandbox and
	// ociEngineForSandbox (which would stack-overflow the daemon). This test
	// completing at all proves the recursion is broken.
	t.Run("unknown runtime resolves to docker without recursion", func(t *testing.T) {
		svc := &Service{cfg: config.Config{}, docker: dockerRT}
		sb := &models.Sandbox{Runtime: "totally-unknown-runtime"}
		rt, err := svc.runtimeForSandbox(sb)
		if err != nil || rt != dockerRT {
			t.Fatalf("runtimeForSandbox(unknown) = (%T, %v), want docker", rt, err)
		}
	})
}
