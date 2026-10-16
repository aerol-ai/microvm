package clustercreate

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
)

// fakeKernelMountTools puts no-op `mount` and `umount` first on PATH so the
// NFS platform-volume adapter's kernel mount succeeds without root or a real
// server, letting a create that carries a platform volume run end to end.
func fakeKernelMountTools(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	for _, name := range []string{"mount", "umount"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
			t.Fatalf("write fake %s: %v", name, err)
		}
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func nfsPlatformVolumes(maxPerTenant int) func(*config.Config) {
	return func(cfg *config.Config) {
		cfg.PATToken = "operator-pat"
		cfg.PlatformVolumes = config.PlatformVolumesConfig{
			Enabled:      true,
			Backend:      config.PlatformVolumesBackendNFS,
			NFSServer:    "nfs.internal",
			NFSExport:    "/exports/volumes",
			MaxPerTenant: maxPerTenant,
		}
	}
}

// UC-81..84 regression. With cluster mode on, every create (even on a single
// node) takes the reserved path, and a platform volume named for the first
// time has no row until that create makes it. The reserved path used to
// resolve the replicated spec in place before the local create, so a
// first-use volume failed with "sandbox not found" (404) and an existing one
// was handed to the create leg as a bare mount, skipping its attachment row.
func TestCreateOnSelectedNode_ReservedPlatformVolume(t *testing.T) {
	fakeKernelMountTools(t)

	cases := []struct {
		name         string
		preexisting  bool  // create the volume before the sandbox
		otherVolume  bool  // another volume already holds the tenant's quota
		maxPerTenant int   // 0 = unlimited
		createErr    error // runtime failure on the create leg
		wantErr      string
	}{
		{name: "first_use_volume_is_created_and_promoted_concrete"},
		{name: "existing_volume_is_reused_and_attached", preexisting: true},
		{name: "failed_create_does_not_leak_first_use_volume", createErr: errors.New("runtime boom"), wantErr: "runtime boom"},
		{name: "first_use_still_charges_the_tenant_quota", otherVolume: true, maxPerTenant: 1, wantErr: models.ErrPlatformVolumeQuota.Error()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			stub := &clusterStub{Noop: cluster.NewNoop("node-a", "http://node-a", "")}
			rt := newFakeRuntime()
			rt.createErr = tc.createErr
			svc, _ := newCreateServiceWithConfig(t, stub, rt, true, nfsPlatformVolumes(tc.maxPerTenant))

			var pre *models.Volume
			if tc.preexisting {
				v, err := svc.CreatePlatformVolume(ctx, "data")
				if err != nil {
					t.Fatalf("CreatePlatformVolume(data): %v", err)
				}
				pre = v
			}
			if tc.otherVolume {
				if _, err := svc.CreatePlatformVolume(ctx, "other"); err != nil {
					t.Fatalf("CreatePlatformVolume(other): %v", err)
				}
			}

			req := models.CreateSandboxRequest{
				Image:           "alpine:3.20",
				PlatformVolumes: []models.PlatformVolumeMount{{Name: "data", Path: "/vol"}},
			}
			resp, err := CreateOnSelectedNode(ctx, svc, nil, req, "sb-vol", CreateOptions{PromoteWithSpec: true})
			vol, volErr := svc.GetPlatformVolumeByName(ctx, "data")

			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want %q", err, tc.wantErr)
				}
				if len(stub.recordCalls) != 0 {
					t.Fatalf("RecordPlacement calls = %d, want 0 after a failed create", len(stub.recordCalls))
				}
				if stub.cancels != 1 {
					t.Fatalf("CancelReservation calls = %d, want 1", stub.cancels)
				}
				// The row this create would have made must not outlive it.
				if !errors.Is(volErr, store.ErrNotFound) {
					t.Fatalf("volume after failed create = %+v, %v; want not found", vol, volErr)
				}
				return
			}

			if err != nil {
				t.Fatalf("CreateOnSelectedNode: %v", err)
			}
			if resp.Sandbox.ID != "sb-vol" {
				t.Fatalf("sandbox id = %q, want sb-vol", resp.Sandbox.ID)
			}
			if volErr != nil {
				t.Fatalf("volume row after create: %v", volErr)
			}
			if pre != nil && vol.ID != pre.ID {
				t.Fatalf("volume id = %q, want the existing %q", vol.ID, pre.ID)
			}
			if len(stub.recordCalls) != 1 || stub.recordCalls[0].spec == nil {
				t.Fatalf("RecordPlacement calls = %+v, want one promote with a spec", stub.recordCalls)
			}
			// A failover recreate has no caller identity, so the promoted spec
			// must carry the tenant-scoped mount, not the bare volume name.
			spec := stub.recordCalls[0].spec
			if len(spec.PlatformVolumes) != 0 {
				t.Fatalf("promoted PlatformVolumes = %+v, want resolved away", spec.PlatformVolumes)
			}
			if len(spec.Mounts) != 1 || spec.Mounts[0].Type != models.MountTypeNFS ||
				spec.Mounts[0].Source != vol.Source || spec.Mounts[0].Target != "/vol" {
				t.Fatalf("promoted mounts = %+v, want one nfs mount of %q at /vol", spec.Mounts, vol.Source)
			}
			// The create leg recorded the attachment, so the volume cannot be
			// deleted out from under the running sandbox.
			if err := svc.DeletePlatformVolume(ctx, vol.ID); !errors.Is(err, models.ErrPlatformVolumeInUse) {
				t.Fatalf("DeletePlatformVolume while attached = %v, want ErrPlatformVolumeInUse", err)
			}
		})
	}
}
