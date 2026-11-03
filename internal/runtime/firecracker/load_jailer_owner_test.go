package firecracker

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// LoadSnapshot reopens every drive the snapshot names, read-write, as the
// jailer's uid/gid. A rootfs still owned by root at that moment fails the
// load with "Permission denied (os error 13) rootfs.ext4": every Start of a
// stopped sandbox under the jailer did, because the restore copies the rootfs
// in as root and chowned it only after the load. These tests check, inside
// LoadSnapshot, that the rootfs already has the jailer's group.

// jailerTestGID returns a gid this process may chown path to that differs
// from path's current group, so the chown is observable without root.
func jailerTestGID(t *testing.T, path string) int {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		t.Skip("no unix file ownership on this platform")
	}
	current := int(st.Gid)
	if os.Getuid() == 0 {
		return current + 4242
	}
	groups, err := os.Getgroups()
	if err != nil {
		t.Skipf("getgroups: %v", err)
	}
	for _, g := range groups {
		if g != current {
			return g
		}
	}
	t.Skip("the test user is in no second group to chown to")
	return 0
}

// requireGroupAtLoad makes the fake LoadSnapshot fail unless path already
// belongs to gid.
func requireGroupAtLoad(client *fakeClient, path string, gid int) {
	client.loadSnapshotHook = func() error {
		fi, err := os.Stat(path)
		if err != nil {
			return err
		}
		if got := int(fi.Sys().(*syscall.Stat_t).Gid); got != gid {
			return fmt.Errorf("%s has gid %d at LoadSnapshot, want the jailer's %d: firecracker could not open it", filepath.Base(path), got, gid)
		}
		return nil
	}
}

func writeLoadArtifacts(t *testing.T, dir string) (mem, state string) {
	t.Helper()
	mem, state = filepath.Join(dir, sandboxSnapshotMemoryFileName), filepath.Join(dir, sandboxSnapshotStateFileName)
	for _, p := range []string{mem, state} {
		if err := os.WriteFile(p, []byte("artifact"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return mem, state
}

func TestStoppedSandboxRestoreChownsRootfsBeforeLoad(t *testing.T) {
	runDir := t.TempDir()
	rootfs := filepath.Join(runDir, rootfsFileName)
	// What startFromSandboxSnapshot's copyFile leaves: the daemon's file.
	if err := os.WriteFile(rootfs, []byte("rootfs"), 0o644); err != nil {
		t.Fatal(err)
	}
	mem, state := writeLoadArtifacts(t, t.TempDir())
	gid := jailerTestGID(t, rootfs)
	d := &Driver{cfg: Config{UseJailer: true, JailerUID: os.Getuid(), JailerGID: gid}}
	client := newFakeClient()
	requireGroupAtLoad(client, rootfs, gid)

	if err := d.configureSandboxSnapshotRestore(context.Background(), client, &sandboxSnapshotManifest{},
		mem, state, rootfs, &TapSlot{TapName: "tap0"}, ""); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if patch := client.drivePatches[rootDriveID]; patch.PathOnHost != rootfsFileName {
		t.Fatalf("root drive patch path = %q, want %q", patch.PathOnHost, rootfsFileName)
	}
}

func TestTemplateLoadChownsCopiedRootfsBeforeLoad(t *testing.T) {
	f := newDriverFixture(t)
	runDir := t.TempDir()
	rootfs := filepath.Join(runDir, rootfsFileName)
	// What linkOrCopyRootfs leaves when the templates dir is on another
	// filesystem: a copy the daemon owns, not a link to the template's inode.
	if err := os.WriteFile(rootfs, []byte("rootfs"), 0o644); err != nil {
		t.Fatal(err)
	}
	mem, state := writeLoadArtifacts(t, t.TempDir())
	gid := jailerTestGID(t, rootfs)
	f.driver.cfg.UseJailer = true
	f.driver.cfg.JailerUID, f.driver.cfg.JailerGID = os.Getuid(), gid
	client := newFakeClient()
	requireGroupAtLoad(client, rootfs, gid)

	if err := f.driver.configureVMMForLoad(context.Background(), client, &TemplateResolution{
		SnapshotMemoryPath: mem,
		SnapshotStatePath:  state,
	}, rootfs, &TapSlot{TapName: "tap0"}, ""); err != nil {
		t.Fatalf("template load: %v", err)
	}
	if patch := client.drivePatches[rootDriveID]; patch.PathOnHost != rootfsFileName {
		t.Fatalf("root drive patch path = %q, want %q", patch.PathOnHost, rootfsFileName)
	}
}

// A rootfs that cannot be staged stops a template load before LoadSnapshot,
// so Firecracker never opens a disk it cannot use.
func TestTemplateLoadStopsWhenTheRootfsCannotBeStaged(t *testing.T) {
	f := newDriverFixture(t)
	f.driver.cfg.UseJailer = true
	// Ids this process may chown its own files to, with at least one of them
	// non-zero so staging always chowns: as root, any gid; otherwise its own.
	gid := os.Getgid()
	if os.Getuid() == 0 {
		gid = 4242
	}
	f.driver.cfg.JailerUID, f.driver.cfg.JailerGID = os.Getuid(), gid
	mem, state := writeLoadArtifacts(t, t.TempDir())
	client := newFakeClient()
	loaded := false
	client.loadSnapshotHook = func() error { loaded = true; return nil }

	err := f.driver.configureVMMForLoad(context.Background(), client, &TemplateResolution{
		SnapshotMemoryPath: mem,
		SnapshotStatePath:  state,
	}, filepath.Join(t.TempDir(), rootfsFileName), &TapSlot{TapName: "tap0"}, "")
	if err == nil || !strings.Contains(err.Error(), "stage snapshot rootfs") {
		t.Fatalf("template load with a missing rootfs: got %v, want a stage snapshot rootfs error", err)
	}
	if loaded {
		t.Fatal("LoadSnapshot ran although the rootfs could not be staged")
	}
}
