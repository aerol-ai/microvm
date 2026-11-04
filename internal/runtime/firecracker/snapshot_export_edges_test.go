package firecracker

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
)

func TestCreateSnapshotFailsWhenTheExportDirCannotBeMade(t *testing.T) {
	f, _, _ := stoppedSandboxForSnapshot(t, "sb-exportdir")
	base, _ := f.driver.sandboxSnapshotBase()
	// A file where the export dir goes.
	if err := os.WriteFile(filepath.Join(filepath.Dir(base), snapshotExportDirName), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := f.driver.CreateSnapshot(context.Background(), "sb-exportdir", "r:1"); err == nil {
		t.Fatal("an export dir that cannot be made gave no error")
	}
}

func TestSweepSnapshotExportsWithNothingThere(t *testing.T) {
	f := newDriverFixture(t)
	f.driver.SweepSnapshotExports() // no _exports dir yet
	f.driver.cfg.TemplatesDir, f.driver.cfg.RunDir = "", ""
	f.driver.SweepSnapshotExports() // no base dir configured
}

// A store may hand back no release func; the source still gets a no-op one.
type nilReleaseStore struct{ recordingImageStore }

func (*nilReleaseStore) OpenImage(context.Context, string) (string, func(), bool, error) {
	return "oci-archive:/x.tar", nil, true, nil
}

func TestRootfsSourceGivesANoOpReleaseWhenTheStoreGivesNone(t *testing.T) {
	f := newDriverFixture(t)
	f.driver.SetImageStore(&nilReleaseStore{})
	src, _, release, err := f.driver.rootfsSource(context.Background(), "aerolvm-snapshot/abc:latest", "", nil)
	if err != nil || src != "oci-archive:/x.tar" || release == nil {
		t.Fatalf("src %q err %v release nil=%v", src, err, release == nil)
	}
	release()
}

func TestCreateSnapshotNeedsADirForSavedSandboxes(t *testing.T) {
	f := newDriverFixture(t)
	f.driver.SetImageStore(&recordingImageStore{})
	f.driver.cfg.TemplatesDir, f.driver.cfg.RunDir = "", ""
	if _, err := f.driver.CreateSnapshot(context.Background(), "sb-nodir", "r:1"); !errors.Is(err, models.ErrRuntimeNotImplemented) {
		t.Fatalf("err = %v, want not implemented", err)
	}
}

func TestCreateSnapshotFailsWhenTheWorkDirCannotBeMade(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root writes into mode-500 dirs")
	}
	f, _, _ := stoppedSandboxForSnapshot(t, "sb-workdir")
	dir, err := f.driver.snapshotExportDir()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	if _, err := f.driver.CreateSnapshot(context.Background(), "sb-workdir", "r:1"); err == nil {
		t.Fatal("a work dir that cannot be made gave no error")
	}
}

// lockDir makes dir undeletable for a non-root user (its entries cannot be
// unlinked) and gives the permission back before the test's temp dirs go.
func lockDir(t *testing.T, dir string) {
	t.Helper()
	writeGuestFile(t, dir, "/held", "x")
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
}

// A work dir that will not go is only logged: the image is already in the
// store, and the boot sweep gets the dir next time.
func TestCreateSnapshotOnlyWarnsWhenItsWorkDirStays(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root removes entries of mode-500 dirs")
	}
	f, store, guest := stoppedSandboxForSnapshot(t, "sb-stuck")
	var locked string
	// The helper's client is made once the disk copy is in the work dir.
	guest.clientHook = func(*fakeClient) {
		base, _ := f.driver.snapshotExportDir()
		work, _ := filepath.Glob(filepath.Join(base, "sb-stuck-*"))
		if len(work) != 1 {
			t.Fatalf("work dirs %v", work)
		}
		locked = filepath.Join(work[0], "srv")
		if err := os.Mkdir(locked, 0o700); err != nil {
			t.Fatal(err)
		}
		lockDir(t, locked)
	}
	if _, err := f.driver.CreateSnapshot(context.Background(), "sb-stuck", "r:1"); err != nil {
		t.Fatalf("CreateSnapshot: %v, want the snapshot to stand", err)
	}
	if _, ok := store.imported["r:1"]; !ok {
		t.Fatal("nothing was imported")
	}
	if _, err := os.Stat(locked); err != nil {
		t.Fatalf("the locked dir is gone (%v); the test did not reach the warning", err)
	}
}

func TestSweepSnapshotExportsWarnsOnWhatItCannotRemove(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root removes entries of mode-500 dirs")
	}
	f := newDriverFixture(t)
	dir, err := f.driver.snapshotExportDir()
	if err != nil {
		t.Fatal(err)
	}
	locked := filepath.Join(dir, "sb-crashed-1", "srv")
	if err := os.MkdirAll(locked, 0o700); err != nil {
		t.Fatal(err)
	}
	lockDir(t, locked)
	f.driver.SweepSnapshotExports()
	if _, err := os.Stat(locked); err != nil {
		t.Fatalf("the locked dir is gone (%v); the test did not reach the warning", err)
	}
}
