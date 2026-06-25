package firecracker

import (
	"context"
	"os"
	"strings"
	"testing"
)

func TestSnapshotTemplate_RESTErrors_Extra(t *testing.T) {
	d := &Driver{
		cfg:       Config{KernelImage: "/kernel", RunDir: t.TempDir()},
		pool:      newFakePool(),
		tapHost:   &fakeTapHost{},
		vsockDial: newFakeVsockDialer(),
	}
	d.SetSpawner(func(cfg Config, id string) (VMMHandle, error) {
		return &warmDestroyHandle{spawned: &fakeSpawnedHandle{}, runDir: t.TempDir()}, nil
	})

	testCases := []struct {
		name   string
		setup  func(*fakeClient)
		errStr string
	}{
		{"PutMachineConfig", func(c *fakeClient) { c.machineErr = os.ErrPermission }, "PutMachineConfig"},
		{"PutBootSource", func(c *fakeClient) { c.bootErr = os.ErrPermission }, "PutBootSource"},
		{"PutDrive root", func(c *fakeClient) { c.driveErr = os.ErrPermission }, "PutDrive root"},
		{"PutNetworkInterface", func(c *fakeClient) { c.nicErr = os.ErrPermission }, "PutNetworkInterface"},
		{"PutVsock", func(c *fakeClient) { c.vsockErr = os.ErrPermission }, "PutVsock"},
		{"Action InstanceStart", func(c *fakeClient) { c.actionErr = os.ErrPermission }, "action InstanceStart"},
		{"Patch VM Paused", func(c *fakeClient) { c.patchVMErr = os.ErrPermission }, "patch VM Paused"},
		{"CreateSnapshot", func(c *fakeClient) { c.snapshotCreateErr = os.ErrPermission }, "CreateSnapshot"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			client := newFakeClient()
			tc.setup(client)
			d.SetClientFactory(func(_ string) VMMClient { return client })

			req := TemplateSnapshotRequest{
				TemplateID:    "tpl-" + strings.ReplaceAll(tc.name, " ", ""),
				RootfsPath:    "/tmp/rootfs",
				OutMemoryPath: "/tmp/mem",
				OutStatePath:  "/tmp/state",
				GuestCID:      3,
			}
			// Write dummy rootfs
			os.WriteFile(req.RootfsPath, []byte("data"), 0644)

			_, err := d.SnapshotTemplate(context.Background(), req)
			if err == nil || !strings.Contains(err.Error(), tc.errStr) {
				t.Errorf("expected %q error, got %v", tc.errStr, err)
			}
		})
	}
}

func TestSnapshotTemplate_HashErrors_Extra(t *testing.T) {
	d := &Driver{
		cfg:       Config{KernelImage: "/kernel", RunDir: t.TempDir()},
		pool:      newFakePool(),
		tapHost:   &fakeTapHost{},
		vsockDial: newFakeVsockDialer(),
	}
	d.SetSpawner(func(cfg Config, id string) (VMMHandle, error) {
		return &warmDestroyHandle{spawned: &fakeSpawnedHandle{}, runDir: t.TempDir()}, nil
	})
	d.SetClientFactory(func(_ string) VMMClient { return newFakeClient() })

	req := TemplateSnapshotRequest{
		TemplateID:    "tpl-hash",
		RootfsPath:    "/tmp/rootfs-hash",
		OutMemoryPath: "/tmp/mem-hash",
		OutStatePath:  "/tmp/state-hash",
		GuestCID:      3,
	}
	os.WriteFile(req.RootfsPath, []byte("data"), 0644)

	// Since fakeClient creates the snapshot files, hashFile will succeed.
	// We can delete them right after SnapshotTemplate? No, it hashes inside SnapshotTemplate.
	// If we use a custom fakeClient that does NOT create the snapshot files, hashFile will fail.
	client := newFakeClient()
	client.snapshotCreateErr = nil
	// we want to prevent fakeClient from creating files, so we pass empty paths to SnapshotCreate
	// but the driver passes OutMemoryPath and OutStatePath to CreateSnapshot.
	// Alternatively, we remove the file during CreateSnapshot using a custom client wrapper.
}
