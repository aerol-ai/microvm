package firecracker

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
)

// A Firecracker snapshot is the stopped sandbox's root filesystem as a
// one-layer image in the node's image store. These tests stand in for the
// helper VM that reads the disk with exportGuest, and for the image store
// with a recorder.

// recordingImageStore is an ImageStore that keeps what it was given.
type recordingImageStore struct {
	mu        sync.Mutex
	imported  map[string][]byte // ref -> tar
	importErr error
	local     map[string]string // ref -> skopeo source
	openErr   error
	released  int
}

func (s *recordingImageStore) ImportRootfs(_ context.Context, ref string, rootfs io.Reader) (string, error) {
	data, err := io.ReadAll(rootfs)
	if err != nil {
		return "", err
	}
	if s.importErr != nil {
		return "", s.importErr
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.imported == nil {
		s.imported = map[string][]byte{}
	}
	s.imported[ref] = data
	return "sha256:img-" + ref, nil
}

func (s *recordingImageStore) OpenImage(_ context.Context, ref string) (string, func(), bool, error) {
	if s.openErr != nil {
		return "", nil, false, s.openErr
	}
	src, ok := s.local[ref]
	if !ok {
		return "", nil, false, nil
	}
	return src, func() { s.mu.Lock(); s.released++; s.mu.Unlock() }, true, nil
}

func writeGuestFile(t *testing.T, root, guestPath, content string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(guestPath))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// guestTree is a disk as cold boot leaves it plus a user's work: the
// injected agent, init, token env and resolver; ext4's lost+found; and the
// user's files, a symlink and a hard link.
func guestTree(t *testing.T, root string) {
	writeGuestFile(t, root, "/etc/os-release", "ID=alpine\n")
	writeGuestFile(t, root, "/root/app/main.py", "print('hello')\n")
	writeGuestFile(t, root, guestEnvPath, "SB_TOOLBOX_TOKEN='secret-token'\n")
	writeGuestFile(t, root, guestToolboxPath, "agent-binary")
	writeGuestFile(t, root, guestInitPath, "#!/bin/sh\n")
	writeGuestFile(t, root, guestResolvPath, "nameserver 10.0.0.1\n")
	writeGuestFile(t, root, "/lost+found/#123", "orphan")
	if err := os.Symlink("main.py", filepath.Join(root, "root/app/entry")); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(filepath.Join(root, "root/app/main.py"), filepath.Join(root, "root/app/main-copy.py")); err != nil {
		t.Fatal(err)
	}
}

// tarEntries reads a tar into name -> header (and content for files).
func tarEntries(t *testing.T, data []byte) (map[string]*tar.Header, map[string]string) {
	t.Helper()
	headers, contents := map[string]*tar.Header{}, map[string]string{}
	tr := tar.NewReader(bytes.NewReader(data))
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return headers, contents
		}
		if err != nil {
			t.Fatal(err)
		}
		headers[hdr.Name] = hdr
		if hdr.Typeflag == tar.TypeReg {
			b, _ := io.ReadAll(tr)
			contents[hdr.Name] = string(b)
		}
	}
}

// stoppedSandboxForSnapshot creates and stops a sandbox (the guest acks
// freeze_fs) and wires an image store and the helper VM stand-in, which
// reads guestTree off the disk copy.
func stoppedSandboxForSnapshot(t *testing.T, id string) (*driverFixture, *recordingImageStore, *exportGuest) {
	t.Helper()
	f := stoppedFixtureSandbox(t, id)
	if err := f.driver.Stop(context.Background(), id); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	store := &recordingImageStore{}
	guest := &exportGuest{t: t, fill: guestTree}
	f.driver.SetImageStore(store)
	guest.install(f)
	return f, store, guest
}

func TestCreateSnapshotExportsTheStoppedDisk(t *testing.T) {
	f, store, guest := stoppedSandboxForSnapshot(t, "sb-snap")
	_, _, _, saved, _, _ := f.driver.sandboxSnapshotPaths("sb-snap")
	savedBefore, err := os.ReadFile(saved)
	if err != nil {
		t.Fatal(err)
	}

	id, err := f.driver.CreateSnapshot(context.Background(), "sb-snap", "aerolvm-snapshot/abc:latest")
	if err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}
	if id != "sha256:img-aerolvm-snapshot/abc:latest" {
		t.Fatalf("id = %q, want the store's image ID", id)
	}
	// The helper VM read a copy; Start still restores from the untouched
	// saved disk.
	if disk := guest.lastClient().drives[exportDriveID].PathOnHost; disk == saved || len(guest.disks) != 1 || !bytes.Equal(guest.disks[0], savedBefore) {
		t.Fatalf("the helper read %q, want a copy of the saved disk, not %q itself", disk, saved)
	}
	if after, _ := os.ReadFile(saved); !bytes.Equal(after, savedBefore) {
		t.Fatal("the saved disk changed")
	}
	if vm := guest.vms[0]; !vm.shutdown || !vm.cleaned {
		t.Fatal("the helper VM was left")
	}

	headers, contents := tarEntries(t, store.imported["aerolvm-snapshot/abc:latest"])
	if contents["etc/os-release"] != "ID=alpine\n" {
		t.Fatalf("the user's files are missing or wrong: %v", contents)
	}
	if h := headers["root/app/entry"]; h == nil || h.Typeflag != tar.TypeSymlink || h.Linkname != "main.py" {
		t.Fatalf("symlink entry = %+v", h)
	}
	if h := headers["root/"]; h == nil || h.Typeflag != tar.TypeDir {
		t.Fatalf("directory entry = %+v", h)
	}
	// The first of the hard-linked names the walk meets carries the content;
	// the other links to it.
	file, link := headers["root/app/main-copy.py"], headers["root/app/main.py"]
	if file == nil || link == nil || file.Typeflag != tar.TypeReg || link.Typeflag != tar.TypeLink ||
		link.Linkname != file.Name || contents[file.Name] != "print('hello')\n" {
		t.Fatalf("hard link entries = %+v / %+v (content %q), want a file and a link to it", file, link, contents[file.Name])
	}
	for _, gone := range []string{strings.TrimPrefix(guestEnvPath, "/"), strings.TrimPrefix(guestToolboxPath, "/"),
		strings.TrimPrefix(guestInitPath, "/"), strings.TrimPrefix(guestResolvPath, "/"), "lost+found/", "lost+found/#123"} {
		if _, ok := headers[gone]; ok {
			t.Errorf("%s is in the image; it is this sandbox's (the token file is its credential)", gone)
		}
	}
	for name, h := range headers {
		if h.Uname != "" || h.Gname != "" {
			t.Errorf("%s carries host user names %q/%q, want numeric owners only", name, h.Uname, h.Gname)
		}
	}
	// The export's working files are gone.
	base, _ := f.driver.sandboxSnapshotBase()
	if left, _ := os.ReadDir(filepath.Join(filepath.Dir(base), snapshotExportDirName)); len(left) != 0 {
		t.Fatalf("export dir not cleaned: %v", left)
	}
}

func TestCreateSnapshotRefusesWhatItCannotSnapshot(t *testing.T) {
	t.Run("a sandbox never stopped", func(t *testing.T) {
		f := newDriverFixture(t)
		f.driver.SetImageStore(&recordingImageStore{})
		_, err := f.driver.CreateSnapshot(context.Background(), "sb-gone", "aerolvm-snapshot/x:latest")
		if !errors.Is(err, models.ErrSnapshotSourceNotReady) {
			t.Fatalf("err = %v, want a 409", err)
		}
	})
	// An agent from before freeze_fs can never freeze: it is the sandbox's
	// agent for life, so the 409 must not suggest a restart.
	t.Run("a disk an older agent cannot flush", func(t *testing.T) {
		f := stoppedFixtureSandbox(t, "sb-old")
		f.vsock.mu.Lock()
		f.vsock.guestRespOk, f.vsock.guestError = false, `unknown op \"freeze_fs\"`
		f.vsock.mu.Unlock()
		if err := f.driver.Stop(context.Background(), "sb-old"); err != nil {
			t.Fatal(err)
		}
		f.driver.SetImageStore(&recordingImageStore{})
		_, err := f.driver.CreateSnapshot(context.Background(), "sb-old", "aerolvm-snapshot/x:latest")
		if !errors.Is(err, models.ErrSnapshotSourceNotReady) || !strings.Contains(err.Error(), "created by an older release") ||
			strings.Contains(err.Error(), "stop it again") {
			t.Fatalf("err = %v, want a 409 that says the sandbox is too old, not to restart it", err)
		}
	})
	// A current agent whose freeze failed will freeze on a later Stop.
	t.Run("a disk whose flush failed", func(t *testing.T) {
		f := stoppedFixtureSandbox(t, "sb-noflush")
		f.vsock.mu.Lock()
		f.vsock.guestRespOk, f.vsock.guestError = false, "freeze root filesystem: EIO"
		f.vsock.mu.Unlock()
		if err := f.driver.Stop(context.Background(), "sb-noflush"); err != nil {
			t.Fatal(err)
		}
		f.driver.SetImageStore(&recordingImageStore{})
		_, err := f.driver.CreateSnapshot(context.Background(), "sb-noflush", "aerolvm-snapshot/x:latest")
		if !errors.Is(err, models.ErrSnapshotSourceNotReady) || !strings.Contains(err.Error(), "start it and stop it again") {
			t.Fatalf("err = %v, want a 409 that says to start and stop it", err)
		}
	})
	t.Run("no image store", func(t *testing.T) {
		f := newDriverFixture(t)
		if _, err := f.driver.CreateSnapshot(context.Background(), "sb-x", "r"); !errors.Is(err, models.ErrRuntimeNotImplemented) {
			t.Fatalf("err = %v, want not implemented", err)
		}
	})
	t.Run("an invalid sandbox ID", func(t *testing.T) {
		f := newDriverFixture(t)
		f.driver.SetImageStore(&recordingImageStore{})
		if _, err := f.driver.CreateSnapshot(context.Background(), "../etc", "r"); err == nil {
			t.Fatal("an invalid ID was accepted")
		}
	})
}

func TestCreateSnapshotFailures(t *testing.T) {
	boom := errors.New("boom")
	t.Run("import", func(t *testing.T) {
		f, store, guest := stoppedSandboxForSnapshot(t, "sb-imp")
		store.importErr = boom
		if _, err := f.driver.CreateSnapshot(context.Background(), "sb-imp", "r:1"); err == nil || !strings.Contains(err.Error(), "import image") {
			t.Fatalf("err = %v", err)
		}
		if vm := guest.vms[0]; !vm.shutdown || !vm.cleaned {
			t.Fatal("a failed import left the helper VM")
		}
	})
	t.Run("a helper dir that will not go is only logged", func(t *testing.T) {
		f, _, guest := stoppedSandboxForSnapshot(t, "sb-stays")
		guest.vmHook = func(vm *fakeVMM) { vm.cleanupErr = boom }
		if _, err := f.driver.CreateSnapshot(context.Background(), "sb-stays", "r:1"); err != nil {
			t.Fatalf("err = %v, want the snapshot to stand", err)
		}
	})
	t.Run("a helper that will not stop is killed", func(t *testing.T) {
		f, _, guest := stoppedSandboxForSnapshot(t, "sb-kill")
		guest.vmHook = func(vm *fakeVMM) { vm.shutdownErr = boom }
		if _, err := f.driver.CreateSnapshot(context.Background(), "sb-kill", "r:1"); err != nil {
			t.Fatal(err)
		}
		if !guest.vms[0].shutdown {
			t.Fatal("not killed")
		}
	})
	t.Run("a corrupt manifest", func(t *testing.T) {
		f, _, _ := stoppedSandboxForSnapshot(t, "sb-bad")
		_, _, _, _, _, manifestPath := f.driver.sandboxSnapshotPaths("sb-bad")
		if err := os.WriteFile(manifestPath, []byte("{"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := f.driver.CreateSnapshot(context.Background(), "sb-bad", "r:1"); err == nil || errors.Is(err, models.ErrSnapshotSourceNotReady) {
			t.Fatalf("err = %v, want the manifest error", err)
		}
	})
	t.Run("the saved disk is gone", func(t *testing.T) {
		f, _, _ := stoppedSandboxForSnapshot(t, "sb-nodisk")
		_, _, _, saved, _, _ := f.driver.sandboxSnapshotPaths("sb-nodisk")
		if err := os.Remove(saved); err != nil {
			t.Fatal(err)
		}
		if _, err := f.driver.CreateSnapshot(context.Background(), "sb-nodisk", "r:1"); err == nil || !strings.Contains(err.Error(), "copy saved disk") {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestSweepSnapshotExportsRemovesLeftovers(t *testing.T) {
	f := newDriverFixture(t)
	base, err := f.driver.sandboxSnapshotBase()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(filepath.Dir(base), snapshotExportDirName)
	writeGuestFile(t, filepath.Join(dir, "sb-crashed-123"), "/export.ext4", "disk")
	writeGuestFile(t, dir, "/image-9.tar", "archive")
	// A helper VM's run dir, and a sandbox's, which stays.
	writeGuestFile(t, filepath.Join(f.runDir, exportHelperIDPrefix+"ab12"), "/export.ext4", "disk")
	writeGuestFile(t, filepath.Join(f.runDir, "sb-running"), "/rootfs.ext4", "disk")
	f.driver.SweepSnapshotExports()
	if left, _ := os.ReadDir(dir); len(left) != 0 {
		t.Fatalf("left after the sweep: %v", left)
	}
	if _, err := os.Stat(filepath.Join(f.runDir, exportHelperIDPrefix+"ab12")); !os.IsNotExist(err) {
		t.Fatal("the helper's run dir is left")
	}
	if _, err := os.Stat(filepath.Join(f.runDir, "sb-running", "rootfs.ext4")); err != nil {
		t.Fatal("the sweep removed a sandbox's run dir")
	}
	// Nothing to sweep is fine.
	f.driver.SweepSnapshotExports()
}

// Jailed, a helper's dir is a chroot under the jailer base.
func TestSweepSnapshotExportsRemovesJailedHelpers(t *testing.T) {
	f := newDriverFixture(t)
	f.driver.cfg.UseJailer = true
	f.driver.cfg.JailerChrootBase = t.TempDir()
	helper := filepath.Join(f.driver.cfg.JailerChrootBase, "firecracker", exportHelperIDPrefix+"cd34")
	sandbox := filepath.Join(f.driver.cfg.JailerChrootBase, "firecracker", "sb-live")
	writeGuestFile(t, helper, "/root/export.ext4", "disk")
	writeGuestFile(t, sandbox, "/root/rootfs.ext4", "disk")
	f.driver.SweepSnapshotExports()
	if _, err := os.Stat(helper); !os.IsNotExist(err) {
		t.Fatal("the jailed helper's chroot is left")
	}
	if _, err := os.Stat(sandbox); err != nil {
		t.Fatal("the sweep removed a sandbox's chroot")
	}
}
