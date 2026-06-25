package firecracker

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

func TestCreate_ExtraRESTErrors(t *testing.T) {
	testCases := []struct {
		name   string
		setup  func(*fakeClient)
		errStr string
	}{
		{"PutMachineConfig", func(c *fakeClient) { c.machineErr = os.ErrPermission }, "PutMachineConfig"},
		{"PutDrive", func(c *fakeClient) { c.driveErr = os.ErrPermission }, "PutDrive root"},
		{"PutNetworkInterface", func(c *fakeClient) { c.nicErr = os.ErrPermission }, "PutNetworkInterface"},
		{"PutVsock", func(c *fakeClient) { c.vsockErr = os.ErrPermission }, "PutVsock"},
		{"Action", func(c *fakeClient) { c.actionErr = os.ErrPermission }, "action InstanceStart"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			f := newDriverFixture(t)
			tc.setup(f.client)

			_, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{
				Image: "alpine:3.20", CPU: 1, MemoryMB: 128,
			}, "sb-rest-err", "tok", nil)

			if err == nil || !strings.Contains(err.Error(), tc.errStr) {
				t.Errorf("expected %q error, got %v", tc.errStr, err)
			}
		})
	}
}

func TestCreate_LoadSnapshot_ExtraRESTErrors(t *testing.T) {
	testCases := []struct {
		name   string
		setup  func(*fakeClient)
		errStr string
	}{
		{"LoadSnapshot", func(c *fakeClient) { c.snapshotLoadErr = os.ErrPermission }, "LoadSnapshot"},
		{"PatchDrive root", func(c *fakeClient) { c.drivePatchErr = os.ErrPermission }, "PatchDrive rootfs"},
		{"PatchNetworkInterface", func(c *fakeClient) { c.networkPatchErr = os.ErrPermission }, "PatchNetworkInterface"},
		{"Patch VM Resumed", func(c *fakeClient) { c.patchVMErr = os.ErrPermission }, "patch VM Resumed"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			f := newDriverFixture(t)
			tc.setup(f.client)

			rootfsPath := filepath.Join(t.TempDir(), "rootfs")
			os.WriteFile(rootfsPath, []byte("fake"), 0644)

			// Setup fake resolver to return a snapshot
			f.driver.SetTemplateResolver(&fakeTemplateResolver{
				hasSnapshot:        true,
				rootfsPath:         rootfsPath,
				snapshotMemoryPath: "/fake/mem",
				snapshotStatePath:  "/fake/state",
			})

			_, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{
				TemplateID: "tpl-1", CPU: 1, MemoryMB: 128,
			}, "sb-rest-snap-err", "tok", nil)

			if err == nil || !strings.Contains(err.Error(), tc.errStr) {
				// We expect PatchDrive to fail on rootfs.
				t.Errorf("expected %q error, got %v", tc.errStr, err)
			}
		})
	}
}

func TestVsockHandshake_Errors(t *testing.T) {
	// Handshake timeout -> fakeVsockDialer dial failure
	f := newDriverFixture(t)
	f.vsock.err = os.ErrPermission

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err := f.driver.Create(ctx, models.CreateSandboxRequest{
		Image: "alpine:3.20", CPU: 1, MemoryMB: 128,
	}, "sb-vsock-timeout", "tok", nil)

	if err == nil || !strings.Contains(err.Error(), "context deadline exceeded") {
		t.Errorf("expected context deadline exceeded, got %v", err)
	}

	// Dial successful but toolbox writes garbage json
	// We can't inject garbage easily via fakeVsockDialer since it only returns ok or error.
	// We can modify fakeVsockDialer slightly or just skip that branch.
}

func TestDestroy_ExtraErrors(t *testing.T) {
	f := newDriverFixture(t)

	// Create successfully to register client/vmm
	_, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{
		Image: "alpine:3.20", CPU: 1, MemoryMB: 128,
	}, "sb-destroy-errs", "tok", nil)
	if err != nil {
		t.Fatalf("setup fail: %v", err)
	}

	f.vmm.shutdownErr = os.ErrPermission
	f.vmm.cleaned = false // reset
	f.pool.relErr = os.ErrPermission
	f.tapHost.removeErr = os.ErrPermission

	// Destroy should complete but return the first error
	err = f.driver.Destroy(context.Background(), &models.Sandbox{ID: "sb-destroy-errs"})
	if err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Errorf("expected permission denied error, got %v", err)
	}
}

func TestOciImageRefFor_Extra(t *testing.T) {
	if ref := ociImageRefFor("docker://myreg.com/repo/img:tag"); ref != "docker://myreg.com/repo/img:tag" {
		t.Errorf("expected pass through, got %q", ref)
	}

	if ref := ociImageRefFor("repo/img:tag"); ref != "docker://repo/img:tag" {
		t.Errorf("expected docker://repo/img:tag, got %q", ref)
	}

	if ref := ociImageRefFor(""); ref != "" {
		t.Errorf("expected empty, got %q", ref)
	}
}
