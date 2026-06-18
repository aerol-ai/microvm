package service

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/volumes"
)

func volumesTestStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func enabledS3Cfg() config.Config {
	return config.Config{
		PATToken: "operator-pat",
		PlatformVolumes: config.PlatformVolumesConfig{
			Enabled:  true,
			Backend:  config.PlatformVolumesBackendS3,
			S3Bucket: "aerol-volumes",
			S3Prefix: "volumes",
		},
	}
}

// UC-16: a request that references platform volumes while the operator has them
// disabled is rejected with the 412-mapped sentinel.
func TestResolvePlatformVolumes_Disabled(t *testing.T) {
	s := &Service{cfg: config.Config{PATToken: "op"}} // Enabled defaults to false
	req := models.CreateSandboxRequest{
		PlatformVolumes: []models.PlatformVolumeMount{{Name: "data", Path: "/workspace"}},
	}
	err := s.resolvePlatformVolumes(context.Background(), &req, models.RuntimeDocker)
	if !errors.Is(err, models.ErrPlatformVolumesDisabled) {
		t.Fatalf("err = %v, want ErrPlatformVolumesDisabled", err)
	}
}

// No platform volumes is always a no-op, even when disabled.
func TestResolvePlatformVolumes_NoneIsNoop(t *testing.T) {
	s := &Service{cfg: config.Config{}}
	req := models.CreateSandboxRequest{Mounts: []models.MountSpec{{Type: models.MountTypeS3, Source: "b", Target: "/x"}}}
	if err := s.resolvePlatformVolumes(context.Background(), &req, models.RuntimeDocker); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(req.Mounts) != 1 {
		t.Fatalf("mounts mutated: %d", len(req.Mounts))
	}
}

// UC-15: firecracker and wasm cannot bind host paths, so platform volumes are
// rejected up front regardless of backend config.
func TestResolvePlatformVolumes_RuntimeGate(t *testing.T) {
	s := &Service{cfg: enabledS3Cfg()}
	for _, rt := range []string{models.RuntimeFirecracker, models.RuntimeWasm} {
		t.Run(rt, func(t *testing.T) {
			req := models.CreateSandboxRequest{
				PlatformVolumes: []models.PlatformVolumeMount{{Name: "data", Path: "/workspace"}},
			}
			err := s.resolvePlatformVolumes(context.Background(), &req, rt)
			if !errors.Is(err, models.ErrPlatformVolumesUnsupportedRuntime) {
				t.Fatalf("runtime %q: err = %v, want ErrPlatformVolumesUnsupportedRuntime", rt, err)
			}
		})
	}
}

// gvisor binds work just like docker, so platform volumes are allowed there.
func TestResolvePlatformVolumes_GvisorAllowed(t *testing.T) {
	s := &Service{cfg: enabledS3Cfg()}
	req := models.CreateSandboxRequest{
		PlatformVolumes: []models.PlatformVolumeMount{{Name: "data", Path: "/workspace"}},
	}
	if err := s.resolvePlatformVolumes(context.Background(), &req, models.RuntimeGvisor); err != nil {
		t.Fatalf("gvisor should allow platform volumes: %v", err)
	}
	if len(req.Mounts) != 1 {
		t.Fatalf("expected 1 synthesized mount, got %d", len(req.Mounts))
	}
}

// Docker happy path: a named volume becomes a tenant-scoped s3 MountSpec
// appended to req.Mounts, preserving any pre-existing mounts.
func TestResolvePlatformVolumes_DockerS3(t *testing.T) {
	s := &Service{cfg: enabledS3Cfg()}
	// Authenticated user token → per-tenant scope (t- prefix).
	ctx := controlplane.ContextWithAccess(context.Background(), controlplane.Access{
		Identity: controlplane.Identity{OwnerRef: "tenant-xyz"},
		Operator: false,
	})
	req := models.CreateSandboxRequest{
		Mounts:          []models.MountSpec{{Type: models.MountTypeS3, Source: "other", Target: "/pre"}},
		PlatformVolumes: []models.PlatformVolumeMount{{Name: "Data", Path: "/workspace", ReadOnly: true}},
	}
	if err := s.resolvePlatformVolumes(ctx, &req, models.RuntimeDocker); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(req.Mounts) != 2 {
		t.Fatalf("expected 2 mounts (pre-existing + volume), got %d", len(req.Mounts))
	}
	vol := req.Mounts[1]
	if vol.Type != models.MountTypeS3 {
		t.Fatalf("volume type = %q", vol.Type)
	}
	// bucket/prefix/<tenant>/<sanitized-name>; name lowercased.
	if !strings.HasPrefix(vol.Source, "aerol-volumes/volumes/t-") || !strings.HasSuffix(vol.Source, "/data") {
		t.Fatalf("volume source = %q", vol.Source)
	}
	if !vol.ReadOnly {
		t.Fatal("read-only not propagated")
	}
	if err := vol.Validate(s.cfg.ToolboxMountPath); err != nil {
		t.Fatalf("synthesized volume fails MountSpec.Validate: %v", err)
	}
}

// Operator PAT path (no per-tenant identity) falls back to the op- scope and
// still works for single-tenant self-host.
func TestResolvePlatformVolumes_OperatorScope(t *testing.T) {
	s := &Service{cfg: enabledS3Cfg()}
	req := models.CreateSandboxRequest{
		PlatformVolumes: []models.PlatformVolumeMount{{Name: "data", Path: "/workspace"}},
	}
	// No access in context → operator/internal path.
	if err := s.resolvePlatformVolumes(context.Background(), &req, models.RuntimeDocker); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(req.Mounts[0].Source, "/op-") {
		t.Fatalf("expected op- scope, source = %q", req.Mounts[0].Source)
	}
}

// UC-13b: within-request quota — two volumes in one create against a cap of 1
// is rejected even with no pre-existing rows.
func TestResolvePlatformVolumes_QuotaWithinRequest(t *testing.T) {
	cfg := enabledS3Cfg()
	cfg.PlatformVolumes.MaxPerTenant = 1
	s := &Service{cfg: cfg, store: volumesTestStore(t)}
	req := models.CreateSandboxRequest{
		PlatformVolumes: []models.PlatformVolumeMount{
			{Name: "a", Path: "/a"},
			{Name: "b", Path: "/b"},
		},
	}
	err := s.resolvePlatformVolumes(context.Background(), &req, models.RuntimeDocker)
	if !errors.Is(err, models.ErrPlatformVolumeQuota) {
		t.Fatalf("err = %v, want ErrPlatformVolumeQuota", err)
	}
}

// UC-13b: cross-request quota — a tenant already at the cap (rows in the store)
// is rejected on the next single-volume create.
func TestResolvePlatformVolumes_QuotaAcrossRequests(t *testing.T) {
	cfg := enabledS3Cfg()
	cfg.PlatformVolumes.MaxPerTenant = 2
	st := volumesTestStore(t)
	s := &Service{cfg: cfg, store: st}
	ctx := context.Background()

	tenant, err := tenantScopeForTest(s, ctx)
	if err != nil {
		t.Fatalf("tenant scope: %v", err)
	}
	// Pre-seed the tenant at the cap.
	for _, id := range []string{"v1", "v2"} {
		if err := st.CreateVolume(ctx, &models.Volume{ID: id, Tenant: tenant, Name: id, Backend: "s3"}); err != nil {
			t.Fatalf("seed %s: %v", id, err)
		}
	}
	req := models.CreateSandboxRequest{
		PlatformVolumes: []models.PlatformVolumeMount{{Name: "c", Path: "/c"}},
	}
	if err := s.resolvePlatformVolumes(ctx, &req, models.RuntimeDocker); !errors.Is(err, models.ErrPlatformVolumeQuota) {
		t.Fatalf("err = %v, want ErrPlatformVolumeQuota (tenant already at cap)", err)
	}
}

// tenantScopeForTest resolves the scope the service would compute for the
// background (operator) context, so a test can seed store rows under the same
// tenant key resolvePlatformVolumes will count.
func tenantScopeForTest(s *Service, ctx context.Context) (string, error) {
	return volumes.TenantScope(callerFromContext(ctx, s.cfg.PATToken))
}

// An invalid volume name surfaces as an error (not a silent skip).
func TestResolvePlatformVolumes_BadName(t *testing.T) {
	s := &Service{cfg: enabledS3Cfg()}
	req := models.CreateSandboxRequest{
		PlatformVolumes: []models.PlatformVolumeMount{{Name: "../escape", Path: "/x"}},
	}
	if err := s.resolvePlatformVolumes(context.Background(), &req, models.RuntimeDocker); err == nil {
		t.Fatal("expected error for traversal name")
	}
}
