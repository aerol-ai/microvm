package service

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
)

func TestPlatformVolumesStoreNilAndIDEntropyWave24(t *testing.T) {
	s := enabledVolumeService(t)
	s.store = nil
	req := &models.CreateSandboxRequest{
		PlatformVolumes: []models.PlatformVolumeMount{{Name: "data", Path: "/data"}},
	}
	if _, err := s.resolvePlatformVolumes(context.Background(), req, models.RuntimeDocker); err == nil {
		t.Fatal("expected store nil")
	}
	s2 := enabledVolumeService(t)
	setRandReader(t, &scriptedRandReader{errs: []error{errors.New("no id")}})
	if _, err := s2.CreatePlatformVolume(context.Background(), "data"); err == nil {
		t.Fatal("expected id entropy fail")
	}
}

func TestResolvePlatformVolumesErrorArmsWave8(t *testing.T) {
	ctx := context.Background()
	s := enabledVolumeService(t)

	req := models.CreateSandboxRequest{
		Image: "alpine", PlatformVolumes: []models.PlatformVolumeMount{{Name: "data", Path: "/workspace"}},
	}
	s.cfg.PlatformVolumes.Enabled = false
	if _, err := s.resolvePlatformVolumes(ctx, &req, models.RuntimeDocker); !errors.Is(err, models.ErrPlatformVolumesDisabled) {
		t.Fatalf("disabled = %v", err)
	}
	s.cfg.PlatformVolumes.Enabled = true
	for _, rt := range []string{models.RuntimeFirecracker, models.RuntimeWasm, models.RuntimeIsolate} {
		if _, err := s.resolvePlatformVolumes(ctx, &req, rt); !errors.Is(err, models.ErrPlatformVolumesUnsupportedRuntime) {
			t.Fatalf("%s = %v", rt, err)
		}
	}
	bad := models.CreateSandboxRequest{
		Image: "alpine", PlatformVolumes: []models.PlatformVolumeMount{{Name: "../bad", Path: "/x"}},
	}
	if _, err := s.resolvePlatformVolumes(ctx, &bad, models.RuntimeDocker); err == nil {
		t.Fatal("expected sanitize failure")
	}
	s.store = nil
	if _, err := s.resolvePlatformVolumes(ctx, &req, models.RuntimeDocker); err == nil || !strings.Contains(err.Error(), "store is not configured") {
		t.Fatalf("nil store = %v", err)
	}

	s2 := enabledVolumeService(t)
	setRandReader(t, &scriptedRandReader{errs: []error{errors.New("no entropy")}})
	if _, err := s2.resolvePlatformVolumes(ctx, &req, models.RuntimeDocker); err == nil {
		t.Fatal("expected volume id entropy failure")
	}
}

func TestResolvePlatformVolumesForReplicationWave8(t *testing.T) {
	s := enabledVolumeService(t)
	ctx := context.Background()
	s.cfg.PlatformVolumes.Enabled = false
	req := &models.CreateSandboxRequest{
		PlatformVolumes: []models.PlatformVolumeMount{{Name: "d", Path: "/w"}},
	}
	if err := s.ResolvePlatformVolumesForReplication(ctx, req); !errors.Is(err, models.ErrPlatformVolumesDisabled) {
		t.Fatalf("disabled = %v", err)
	}
	s.cfg.PlatformVolumes.Enabled = true
	if err := s.ResolvePlatformVolumesForReplication(ctx, nil); err != nil {
		t.Fatalf("nil req = %v", err)
	}
	bad := &models.CreateSandboxRequest{
		Image: "alpine",
		PlatformVolumes: []models.PlatformVolumeMount{
			{Name: "../bad", Path: "/x"},
		},
	}
	if err := s.ResolvePlatformVolumesForReplication(ctx, bad); err == nil {
		t.Fatal("expected sanitize failure")
	}
	if _, err := s.CreatePlatformVolume(ctx, "data"); err != nil {
		t.Fatal(err)
	}
	ok := &models.CreateSandboxRequest{
		Image:           "alpine",
		PlatformVolumes: []models.PlatformVolumeMount{{Name: "data", Path: "/workspace", ReadOnly: true}},
	}
	if err := s.ResolvePlatformVolumesForReplication(ctx, ok); err != nil {
		t.Fatalf("ResolvePlatformVolumesForReplication: %v", err)
	}
	if len(ok.Mounts) == 0 || len(ok.PlatformVolumes) != 0 {
		t.Fatalf("mounts=%d platformVolumes=%d", len(ok.Mounts), len(ok.PlatformVolumes))
	}
	miss := &models.CreateSandboxRequest{
		PlatformVolumes: []models.PlatformVolumeMount{{Name: "missing", Path: "/w"}},
	}
	if err := s.ResolvePlatformVolumesForReplication(ctx, miss); err == nil {
		t.Fatal("expected missing volume")
	}
	empty := &models.CreateSandboxRequest{Image: "alpine"}
	if err := s.ResolvePlatformVolumesForReplication(ctx, empty); err != nil {
		t.Fatalf("empty: %v", err)
	}
	s.store = nil
	again := &models.CreateSandboxRequest{
		PlatformVolumes: []models.PlatformVolumeMount{{Name: "data", Path: "/w"}},
	}
	if err := s.ResolvePlatformVolumesForReplication(ctx, again); err == nil {
		t.Fatal("expected nil store")
	}
}

func TestCleanupCreatedPlatformVolumesWave8(t *testing.T) {
	s := enabledVolumeService(t)
	ctx := context.Background()
	v, err := s.CreatePlatformVolume(ctx, "scratch")
	if err != nil {
		t.Fatal(err)
	}
	s.cleanupCreatedPlatformVolumes(ctx, []models.VolumeAttachment{
		{Tenant: v.Tenant, VolumeID: v.ID, CreatedVolume: true},
		{Tenant: v.Tenant, VolumeID: "missing", CreatedVolume: true},
		{CreatedVolume: false},
	})
}

func TestPlatformVolumesResolveErrorsWave9(t *testing.T) {
	ctx := context.Background()
	s := enabledVolumeService(t)
	req := models.CreateSandboxRequest{
		PlatformVolumes: []models.PlatformVolumeMount{{Name: "../bad", Path: "/data"}},
	}
	if _, err := s.resolvePlatformVolumes(ctx, &req, models.RuntimeDocker); err == nil {
		t.Fatal("expected sanitize name failure")
	}
	setRandReader(t, &scriptedRandReader{errs: []error{errors.New("no vol id")}})
	req2 := models.CreateSandboxRequest{
		PlatformVolumes: []models.PlatformVolumeMount{{Name: "data", Path: "/data"}},
	}
	if _, err := s.resolvePlatformVolumes(ctx, &req2, models.RuntimeDocker); err == nil {
		t.Fatal("expected volume id entropy failure")
	}
}
