package firecracker

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"

	vmmpool "github.com/aerol-ai/microvm/internal/pool/vmm"
	"github.com/aerol-ai/microvm/pkg/firecracker"
	"github.com/aerol-ai/microvm/pkg/models"
)

// A warm slot's root drive is the template's own rootfs, linked into the
// slot's jail and shared with every other VM of that template. Like the
// cold load (chrootSharedFile), the warm pool keeps that file root's with
// the jailer's group and mode 0640, from the refill through the claim.
// These tests follow every chown, not only the last one, so a file given
// to the jailer's user and given back later still fails them.

const (
	warmOwnerJailerUID = 990
	warmOwnerJailerGID = 990
)

// ownerHistory replaces chownStaged and keeps every call in order. It
// does not change the file (only root may give a file to root), so the
// owner a test reads is the last one recorded for that inode.
type ownerHistory struct {
	mu    sync.Mutex
	calls []ownerCall
}

type ownerCall struct {
	path     string
	info     os.FileInfo
	uid, gid int
}

func recordOwnerHistory(t *testing.T) *ownerHistory {
	t.Helper()
	h := &ownerHistory{}
	orig, origRoot := chownStaged, stagerIsRoot
	chownStaged = func(path string, uid, gid int) error {
		info, err := os.Stat(path)
		if err != nil {
			return err
		}
		h.mu.Lock()
		h.calls = append(h.calls, ownerCall{path: path, info: info, uid: uid, gid: gid})
		h.mu.Unlock()
		return nil
	}
	stagerIsRoot = func() bool { return true }
	t.Cleanup(func() { chownStaged, stagerIsRoot = orig, origRoot })
	return h
}

func (h *ownerHistory) len() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.calls)
}

// of returns, in order, the chowns of the file at path (by inode) from
// call from on.
func (h *ownerHistory) of(t *testing.T, path string, from int) []ownerCall {
	t.Helper()
	want, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []ownerCall
	for _, c := range h.calls[from:] {
		if os.SameFile(c.info, want) {
			out = append(out, c)
		}
	}
	return out
}

// jailerMayWrite answers what the kernel would for a process running as
// the jailer's user and group: may it open the file for writing, or
// change its mode? The owner is the one recorded last (the file's own
// when nothing was recorded).
func jailerMayWrite(t *testing.T, h *ownerHistory, path string) bool {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	st := info.Sys().(*syscall.Stat_t)
	uid, gid := int(st.Uid), int(st.Gid)
	if calls := h.of(t, path, 0); len(calls) > 0 {
		last := calls[len(calls)-1]
		if last.uid != -1 {
			uid = last.uid
		}
		if last.gid != -1 {
			gid = last.gid
		}
	}
	mode := info.Mode().Perm()
	switch {
	case uid == warmOwnerJailerUID:
		return true // the owner may chmod it writable
	case gid == warmOwnerJailerGID:
		return mode&0o020 != 0
	default:
		return mode&0o002 != 0
	}
}

// neverJailers fails the test when any recorded chown gave the file at
// path to the jailer's user.
func neverJailers(t *testing.T, h *ownerHistory, path, when string, from int) {
	t.Helper()
	for _, c := range h.of(t, path, from) {
		if c.uid == warmOwnerJailerUID {
			t.Errorf("%s: %s was given to the jailer's user (%d:%d)", when, filepath.Base(c.path), c.uid, c.gid)
		}
	}
}

// TestWarmSlot_TemplateRootfsNeverJailersFile: a warm refill links the
// template's rootfs (or copies it across filesystems) into the slot's
// jail as root's, group the jailer's, mode 0640, before LoadSnapshot; and
// the claim leaves it as it is. At no point is it the jailer's user's,
// and the jailer's user can never write it.
func TestWarmSlot_TemplateRootfsNeverJailersFile(t *testing.T) {
	for _, tc := range []struct {
		name          string
		crossDevice   bool
		overlaySizeGB int
	}{
		{name: "hard link, placeholder overlay"},
		{name: "hard link, sized overlay", overlaySizeGB: 1},
		{name: "cross-device copy", crossDevice: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			owners := recordOwnerHistory(t)
			f, chroot := newJailedWarmFixture(t)
			f.driver.cfg.JailerUID, f.driver.cfg.JailerGID = warmOwnerJailerUID, warmOwnerJailerGID
			rootfs, mem, state := writeWarmTemplate(t)
			if tc.crossDevice {
				orig := linkRootfsFn
				t.Cleanup(func() { linkRootfsFn = orig })
				linkRootfsFn = func(string, string) error { return syscall.EXDEV }
			}
			staged := filepath.Join(chroot, rootfsFileName)

			// Firecracker opens the root drive on LoadSnapshot and again on
			// the claim's PATCH; both times it must already be root's.
			checkRootDrive := func(when string) error {
				calls := owners.of(t, staged, 0)
				if len(calls) == 0 {
					return fmt.Errorf("%s: the root drive's file was never staged for the jailer", when)
				}
				if last := calls[len(calls)-1]; last.uid != 0 || last.gid != warmOwnerJailerGID {
					return fmt.Errorf("%s: the root drive's file is %d:%d, want 0:%d", when, last.uid, last.gid, warmOwnerJailerGID)
				}
				if jailerMayWrite(t, owners, staged) {
					return fmt.Errorf("%s: the jailer's user may write the root drive's file", when)
				}
				return nil
			}
			f.client.loadSnapshotHook = func() error { return checkRootDrive("LoadSnapshot") }
			f.client.patchDriveHook = func(id string, _ firecracker.DrivePatch) error {
				if id != rootDriveID {
					return nil
				}
				return checkRootDrive("claim PATCH")
			}

			const slotID = "vmms-warm-owner"
			handle, err := NewPoolSpawner(f.driver).Spawn(context.Background(), slotID, vmmpool.SnapshotInputs{
				TemplateID: "tpl-owner", RootfsPath: rootfs,
				SnapshotMemoryPath: mem, SnapshotStatePath: state,
				VsockCID: 200, HasOverlay: true,
			})
			if err != nil {
				t.Fatalf("warm spawn: %v", err)
			}
			if shared := sameInode(t, staged, rootfs); shared == tc.crossDevice {
				t.Fatalf("staged rootfs shares the template's file = %v, want %v", shared, !tc.crossDevice)
			}
			neverJailers(t, owners, staged, "refill", 0)
			neverJailers(t, owners, rootfs, "refill", 0)
			if info, _ := os.Stat(staged); info.Mode().Perm() != 0o640 {
				t.Fatalf("staged rootfs mode %v, want 0640", info.Mode().Perm())
			}

			// The slot waits in the pool, then a create claims it.
			beforeClaim := owners.len()
			f.driver.SetWarmPool(&fakeWarmPool{
				slot: &vmmpool.Slot{
					ID: slotID, TemplateID: "tpl-owner", Status: vmmpool.StatusAllocated,
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
				TemplateID: "tpl-owner", OverlaySizeGB: tc.overlaySizeGB,
			}, "sb-warm-owner", "tok", nil); err != nil {
				t.Fatalf("create from the warm slot: %v", err)
			}
			if f.vmm.shutdown {
				t.Fatal("the claimed slot's VM was shut down")
			}
			if got := f.client.drivePatches[rootDriveID].PathOnHost; got != rootfsFileName {
				t.Fatalf("root drive patched to %q, want the chroot name %q", got, rootfsFileName)
			}
			// The claim does not touch the root drive's owner at all: no
			// give-back is needed, and none is paid on the create path.
			if calls := owners.of(t, staged, beforeClaim); len(calls) != 0 {
				t.Fatalf("the claim chowned the root drive's file %d times: %+v", len(calls), calls)
			}
			if jailerMayWrite(t, owners, staged) || jailerMayWrite(t, owners, rootfs) {
				t.Fatal("after the claim the jailer's user may write the template's rootfs")
			}
			// The guest's own overlay is still the jailer's to write.
			if tc.overlaySizeGB > 0 {
				overlay := filepath.Join(chroot, overlayFileName)
				calls := owners.of(t, overlay, beforeClaim)
				if len(calls) == 0 || calls[len(calls)-1].uid != warmOwnerJailerUID {
					t.Fatalf("the sandbox's own overlay was not given to the jailer: %+v", calls)
				}
			}
		})
	}
}

// TestWarmSlot_DirectModeClaimUsesHostPath: without the jailer there is no
// chroot, so the claim names the slot's rootfs by its host path, as
// before, and still changes nothing on it.
func TestWarmSlot_DirectModeClaimUsesHostPath(t *testing.T) {
	owners := recordOwnerHistory(t)
	f := newDriverFixture(t)
	rootfs, mem, state := writeWarmTemplate(t)
	const slotID = "vmms-warm-direct"
	handle, err := NewPoolSpawner(f.driver).Spawn(context.Background(), slotID, vmmpool.SnapshotInputs{
		TemplateID: "tpl-direct", RootfsPath: rootfs,
		SnapshotMemoryPath: mem, SnapshotStatePath: state,
		VsockCID: 200, HasOverlay: true,
	})
	if err != nil {
		t.Fatalf("warm spawn: %v", err)
	}
	f.driver.SetWarmPool(&fakeWarmPool{
		slot: &vmmpool.Slot{
			ID: slotID, TemplateID: "tpl-direct", Status: vmmpool.StatusAllocated,
			APISocket: handle.APISocket(), RunDir: handle.RunDir(), VsockCID: 200,
		},
		handle: handle,
	})
	f.driver.SetTemplateResolver(&fakeTemplateResolver{
		rootfsPath: rootfs, hasSnapshot: true, hasOverlay: true,
		snapshotMemoryPath: mem, snapshotStatePath: state, snapshotVsockCID: 200,
	})
	if _, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{
		Image: "alpine:3.20", CPU: 1, MemoryMB: 128, TemplateID: "tpl-direct",
	}, "sb-warm-direct", "tok", nil); err != nil {
		t.Fatalf("create from the warm slot: %v", err)
	}
	want := filepath.Join(handle.RunDir(), rootfsFileName)
	if got := f.client.drivePatches[rootDriveID].PathOnHost; got != want {
		t.Fatalf("root drive patched to %q, want the host path %q", got, want)
	}
	if !sameInode(t, want, rootfs) {
		t.Fatal("the slot's rootfs is not the template's file")
	}
	if n := owners.len(); n != 0 {
		t.Fatalf("direct mode chowned %d files", n)
	}
}
