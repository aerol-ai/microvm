package firecracker

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"

	vmmpool "github.com/aerol-ai/microvm/internal/pool/vmm"
	"github.com/aerol-ai/microvm/pkg/firecracker"
	"github.com/aerol-ai/microvm/pkg/models"
)

// Firecracker's LoadSnapshot reopens every drive the snapshot state names,
// by the path the template build gave it. Under the jailer that path is
// chroot-relative ("rootfs.ext4"), so the file must already sit in the
// slot's run dir, owned so the jailer's uid/gid can open it. The warm pool
// staged the snapshot files and the overlay placeholder but never the
// template's rootfs, and every warm spawn on a jailed host failed with the
// error firecrackerOpenDrive reproduces (seen live on c5.metal and
// m8i.xlarge: 20 of 20 creates missed the pool).

// firecrackerOpenDrive does what Firecracker does to a drive's backing file
// on LoadSnapshot or PATCH /drives: open name inside the chroot as the
// jailer's group. A missing file or one the group does not own is the
// error Firecracker returns.
func firecrackerOpenDrive(chroot, name string, jailerGID int) error {
	fi, err := os.Stat(filepath.Join(chroot, name))
	if err != nil {
		var errno syscall.Errno
		if !errors.As(err, &errno) {
			return err
		}
		return fmt.Errorf("Error manipulating the backing file: %w (os error %d) %s", errno, int(errno), name)
	}
	if gid := int(fi.Sys().(*syscall.Stat_t).Gid); gid != jailerGID {
		return fmt.Errorf("Error manipulating the backing file: Permission denied (os error 13) %s (gid %d, jailer %d)", name, gid, jailerGID)
	}
	return nil
}

// firecrackerLikeLoad makes the fake LoadSnapshot open drives the way
// Firecracker's does: it fails unless every drive file the snapshot names
// is in the chroot with the jailer's group.
func firecrackerLikeLoad(client *fakeClient, chroot string, jailerGID int, drives ...string) {
	client.loadSnapshotHook = func() error {
		for _, name := range drives {
			if err := firecrackerOpenDrive(chroot, name, jailerGID); err != nil {
				return fmt.Errorf("firecracker: PUT /snapshot/load -> 400: Failed to restore devices: Error restoring MMIO devices: Block: Virtio backend error: %w", err)
			}
		}
		return nil
	}
}

// newJailedWarmFixture is newDriverFixture with the jailer on: the spawned
// VMM's run dir is its chroot root, where Firecracker resolves every
// chroot-relative path.
func newJailedWarmFixture(t *testing.T) (*driverFixture, string) {
	t.Helper()
	f := newDriverFixture(t)
	f.driver.cfg.UseJailer = true
	chroot := filepath.Join(t.TempDir(), "jailer", "firecracker", "vmms-warm", "root")
	if err := os.MkdirAll(chroot, 0o755); err != nil {
		t.Fatal(err)
	}
	f.driver.SetSpawner(func(_ Config, slotID string) (VMMHandle, error) {
		f.vmm.id = slotID
		f.vmm.runDir = chroot
		f.vmm.apiSocket = filepath.Join(chroot, "api.sock")
		return f.vmm, nil
	})
	return f, chroot
}

// writeTemplateRootfs writes a template's rootfs into dir.
func writeTemplateRootfs(t *testing.T, dir string) string {
	t.Helper()
	rootfs := filepath.Join(dir, rootfsFileName)
	if err := os.WriteFile(rootfs, []byte("TEMPLATE-ROOTFS"), 0o644); err != nil {
		t.Fatal(err)
	}
	return rootfs
}

// writeWarmTemplate writes a template's rootfs and snapshot artifacts.
func writeWarmTemplate(t *testing.T) (rootfs, mem, state string) {
	t.Helper()
	dir := t.TempDir()
	mem, state = writeLoadArtifacts(t, dir)
	return writeTemplateRootfs(t, dir), mem, state
}

func TestWarmSpawn_StagesTemplateRootfsBeforeLoad(t *testing.T) {
	for _, tc := range []struct {
		name       string
		hasOverlay bool
		// crossDevice makes linkOrCopyRootfs fall back to a copy, which is
		// the daemon's file until chowned.
		crossDevice bool
	}{
		{name: "hard link"},
		{name: "hard link with overlay", hasOverlay: true},
		{name: "cross-device copy", crossDevice: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, chroot := newJailedWarmFixture(t)
			rootfs, mem, state := writeWarmTemplate(t)
			gid := jailerTestGID(t, rootfs)
			f.driver.cfg.JailerUID, f.driver.cfg.JailerGID = os.Getuid(), gid
			if tc.crossDevice {
				orig := linkRootfsFn
				t.Cleanup(func() { linkRootfsFn = orig })
				linkRootfsFn = func(string, string) error { return syscall.EXDEV }
			}
			drives := []string{rootfsFileName}
			if tc.hasOverlay {
				drives = append(drives, overlayFileName)
			}
			firecrackerLikeLoad(f.client, chroot, gid, drives...)

			// Through the pool's adapter, so the rootfs path is the one the
			// refill loop hands over.
			handle, err := NewPoolSpawner(f.driver).Spawn(context.Background(), "vmms-warm-rootfs", vmmpool.SnapshotInputs{
				TemplateID:         "tpl-snap",
				RootfsPath:         rootfs,
				SnapshotMemoryPath: mem,
				SnapshotStatePath:  state,
				VsockCID:           200,
				HasOverlay:         tc.hasOverlay,
			})
			if err != nil {
				t.Fatalf("warm spawn: %v", err)
			}
			if handle.RunDir() != chroot {
				t.Fatalf("run dir = %q, want the chroot %q", handle.RunDir(), chroot)
			}
			staged := filepath.Join(chroot, rootfsFileName)
			got, err := os.ReadFile(staged)
			if err != nil || !bytes.Equal(got, []byte("TEMPLATE-ROOTFS")) {
				t.Fatalf("staged rootfs = %q, %v; want the template's bytes", got, err)
			}
			stagedInfo, _ := os.Stat(staged)
			tplInfo, _ := os.Stat(rootfs)
			if shared := os.SameFile(stagedInfo, tplInfo); shared == tc.crossDevice {
				t.Fatalf("staged rootfs shares the template inode = %v, want %v", shared, !tc.crossDevice)
			}
		})
	}
}

// A template's rootfs that cannot be staged fails the warm spawn before
// LoadSnapshot, and the slot's TAP, process and run dir all go with it, so
// the pool never holds a slot whose root drive Firecracker cannot open.
func TestWarmSpawn_RootfsStagingFailureCleansUpSlot(t *testing.T) {
	for _, tc := range []struct {
		name   string
		rootfs func(t *testing.T) string
		want   string
	}{
		{
			name:   "template rootfs missing",
			rootfs: func(t *testing.T) string { return filepath.Join(t.TempDir(), "deleted-"+rootfsFileName) },
			want:   "no such file or directory",
		},
		{
			// link(2) refuses a directory, and the copy fallback refuses
			// anything that is not a regular file.
			name:   "template rootfs is a directory",
			rootfs: func(t *testing.T) string { return t.TempDir() },
			want:   "is not a regular file",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, _ := newJailedWarmFixture(t)
			_, mem, state := writeWarmTemplate(t)
			req := WarmSpawnRequest{
				SlotID:             "vmms-warm-unstaged",
				TemplateID:         "tpl-snap",
				RootfsPath:         tc.rootfs(t),
				SnapshotMemoryPath: mem,
				SnapshotStatePath:  state,
				VsockCID:           200,
			}
			loaded := false
			f.client.loadSnapshotHook = func() error { loaded = true; return nil }

			_, err := f.driver.WarmSpawn(context.Background(), req)
			if err == nil || !strings.Contains(err.Error(), "stage template rootfs") || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("warm spawn = %v, want a stage template rootfs error saying %q", err, tc.want)
			}
			if loaded {
				t.Fatal("LoadSnapshot ran without the root drive's file")
			}
			if !f.vmm.shutdown || !f.vmm.cleaned {
				t.Fatalf("vmm shutdown=%v run dir cleaned=%v, want both", f.vmm.shutdown, f.vmm.cleaned)
			}
			if f.tapHost.removeCalls != 1 || f.pool.release != 1 {
				t.Fatalf("tap remove/release = %d/%d, want 1/1", f.tapHost.removeCalls, f.pool.release)
			}
		})
	}
}

// WarmSpawn links the template's rootfs into the slot, so the paused VM's
// root drive is the template's own inode. The guest still cannot write it:
//
//   - the VM stays paused (LoadSnapshot ResumeVM=false) until the pool hit
//     has PATCHed the root drive and the overlay;
//   - the template build made the root drive read-only (snapshot_test.go),
//     Firecracker keeps that flag across a load and a PATCH, and a PATCH
//     body has no field that could clear it;
//   - the one drive the guest can write, the overlay, is the slot's own file.
//
// This is the cold load's arrangement too: Create links the template's
// rootfs into the sandbox's run dir and configureVMMForLoad PATCHes the
// root drive to it.
func TestWarmSlot_GuestNeverGetsAWritableTemplateRootfs(t *testing.T) {
	if _, ok := reflect.TypeOf(firecracker.DrivePatch{}).FieldByName("IsReadOnly"); ok {
		t.Fatal("DrivePatch can set is_read_only: a PATCH could make the shared template rootfs writable")
	}
	for _, tc := range []struct {
		name          string
		overlaySizeGB int
	}{
		{name: "placeholder overlay"},
		{name: "sized overlay", overlaySizeGB: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, chroot := newJailedWarmFixture(t)
			rootfs, mem, state := writeWarmTemplate(t)
			gid := jailerTestGID(t, rootfs)
			f.driver.cfg.JailerUID, f.driver.cfg.JailerGID = os.Getuid(), gid
			firecrackerLikeLoad(f.client, chroot, gid, rootfsFileName, overlayFileName)
			f.client.patchDriveHook = func(_ string, p firecracker.DrivePatch) error {
				return firecrackerOpenDrive(chroot, p.PathOnHost, gid)
			}

			const slotID = "vmms-warm-claim"
			handle, err := NewPoolSpawner(f.driver).Spawn(context.Background(), slotID, vmmpool.SnapshotInputs{
				TemplateID:         "tpl-warm",
				RootfsPath:         rootfs,
				SnapshotMemoryPath: mem,
				SnapshotStatePath:  state,
				VsockCID:           200,
				HasOverlay:         true,
			})
			if err != nil {
				t.Fatalf("warm spawn: %v", err)
			}
			f.driver.SetWarmPool(&fakeWarmPool{
				slot: &vmmpool.Slot{
					ID: slotID, TemplateID: "tpl-warm", Status: vmmpool.StatusAllocated,
					APISocket: handle.APISocket(), RunDir: handle.RunDir(), VsockCID: 200,
				},
				handle: handle,
			})
			f.driver.SetTemplateResolver(&fakeTemplateResolver{
				rootfsPath: rootfs, hasSnapshot: true, hasOverlay: true,
				snapshotMemoryPath: mem, snapshotStatePath: state, snapshotVsockCID: 200,
			})

			if _, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{
				Image: "alpine:3.20", CPU: 1, MemoryMB: 128,
				TemplateID: "tpl-warm", OverlaySizeGB: tc.overlaySizeGB,
			}, "sb-warm-claim", "tok", nil); err != nil {
				t.Fatalf("create from the warm slot: %v", err)
			}
			if f.vmm.shutdown {
				t.Fatal("the claimed slot's VM was shut down")
			}

			// Nothing runs the guest before both drives are rebound.
			want := strings.Join([]string{
				"LoadSnapshot",
				"PatchDrive:" + rootDriveID,
				"PatchDrive:" + overlayDriveID,
				"PatchVM:" + firecracker.VMStateResumed,
			}, " ")
			if got := strings.Join(f.client.restOrder, " "); got != want {
				t.Fatalf("REST calls = %q, want %q", got, want)
			}
			if f.client.snapshotLoad.ResumeVM {
				t.Fatal("LoadSnapshot resumed the VM before the claim")
			}

			// The root drive shares the template's inode, read-only; the
			// writable overlay does not.
			drive := func(id string) string { return filepath.Join(chroot, f.client.drivePatches[id].PathOnHost) }
			if !sameInode(t, drive(rootDriveID), rootfs) {
				t.Fatal("root drive is not the template's rootfs: the warm slot staged something else")
			}
			if sameInode(t, drive(overlayDriveID), rootfs) {
				t.Fatal("the writable overlay is the template's rootfs inode")
			}
			if got, _ := os.ReadFile(rootfs); !bytes.Equal(got, []byte("TEMPLATE-ROOTFS")) {
				t.Fatalf("template rootfs = %q, changed", got)
			}
		})
	}
}

func sameInode(t *testing.T, a, b string) bool {
	t.Helper()
	ai, err := os.Stat(a)
	if err != nil {
		t.Fatal(err)
	}
	bi, err := os.Stat(b)
	if err != nil {
		t.Fatal(err)
	}
	return os.SameFile(ai, bi)
}
