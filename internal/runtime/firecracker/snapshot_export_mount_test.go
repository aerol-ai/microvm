package firecracker

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
)

// fakeMountBins puts mount and umount scripts first on PATH. They log their
// arguments to log, and exit with the codes in mountExit/umountExit.
func fakeMountBins(t *testing.T, mountExit, umountExit string) (log string) {
	t.Helper()
	bin := t.TempDir()
	log = filepath.Join(bin, "calls")
	for name, code := range map[string]string{"mount": mountExit, "umount": umountExit} {
		script := "#!/bin/sh\necho \"" + name + " $*\" >> " + log + "\necho \"" + name + " said no\" >&2\nexit " + code + "\n"
		if err := os.WriteFile(filepath.Join(bin, name), []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	return log
}

func TestLoopMounterMountsReadWriteAndUnmounts(t *testing.T) {
	log := fakeMountBins(t, "0", "0")
	unmount, err := loopMounter{}.Mount(context.Background(), "/x/rootfs.ext4", "/x/mnt")
	if err != nil {
		t.Fatalf("Mount: %v", err)
	}
	if err := unmount(); err != nil {
		t.Fatalf("unmount: %v", err)
	}
	calls, _ := os.ReadFile(log)
	want := "mount -o loop,noatime,nodev,nosuid /x/rootfs.ext4 /x/mnt\numount /x/mnt\n"
	if string(calls) != want {
		t.Fatalf("calls = %q, want %q", calls, want)
	}
}

func TestLoopMounterReportsFailures(t *testing.T) {
	fakeMountBins(t, "32", "0")
	if _, err := (loopMounter{}).Mount(context.Background(), "/x/rootfs.ext4", "/x/mnt"); err == nil || !strings.Contains(err.Error(), "mount said no") {
		t.Fatalf("mount failure: %v", err)
	}
	fakeMountBins(t, "0", "16")
	unmount, err := loopMounter{}.Mount(context.Background(), "/x/rootfs.ext4", "/x/mnt")
	if err != nil {
		t.Fatal(err)
	}
	if err := unmount(); err == nil || !strings.Contains(err.Error(), "umount said no") {
		t.Fatalf("umount failure: %v", err)
	}
}

func TestDiskMounterDefaultsToTheLoopMounter(t *testing.T) {
	f := newDriverFixture(t)
	if _, ok := f.driver.diskMounter().(loopMounter); !ok {
		t.Fatalf("default mounter = %T, want loopMounter", f.driver.diskMounter())
	}
}

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

func TestWriteRootfsTarFailsOnAnUnreadableFile(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root reads mode-000 files")
	}
	root := t.TempDir()
	writeGuestFile(t, root, "/secret", "x")
	if err := os.Chmod(filepath.Join(root, "secret"), 0); err != nil {
		t.Fatal(err)
	}
	if err := writeRootfsTar(io.Discard, root); err == nil {
		t.Fatal("an unreadable file gave no error")
	}
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

// A socket a guest program left on its disk does not stop the export.
func TestWriteRootfsTarLeavesOutSockets(t *testing.T) {
	// Short path: a unix socket name is capped near 100 bytes.
	root, err := os.MkdirTemp("", "fcs")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	writeGuestFile(t, root, "/etc/hostname", "box")
	ln, err := net.Listen("unix", filepath.Join(root, "agent.sock"))
	if err != nil {
		t.Skipf("no unix sockets here: %v", err)
	}
	defer ln.Close()
	var buf bytes.Buffer
	if err := writeRootfsTar(&buf, root); err != nil {
		t.Fatalf("writeRootfsTar: %v", err)
	}
	headers, _ := tarEntries(t, buf.Bytes())
	if _, ok := headers["agent.sock"]; ok {
		t.Fatal("the socket is in the image")
	}
	if _, ok := headers["etc/hostname"]; !ok {
		t.Fatal("the files next to the socket are missing")
	}
}

// failAfter accepts limit bytes, then fails every write: the import side of
// the pipe going away mid-stream.
type failAfter struct{ limit, n int }

func (w *failAfter) Write(p []byte) (int, error) {
	if w.n+len(p) > w.limit {
		return 0, errors.New("reader gone")
	}
	w.n += len(p)
	return len(p), nil
}

func TestWriteRootfsTarStopsWhenTheReaderGoes(t *testing.T) {
	root := t.TempDir()
	writeGuestFile(t, root, "/data", strings.Repeat("x", 100))
	var whole bytes.Buffer
	if err := writeRootfsTar(&whole, root); err != nil {
		t.Fatal(err)
	}
	// The stream is header(s), one 512-byte content block, then the
	// 1024-byte trailer.
	headerBytes := whole.Len() - 512 - 1024
	for name, limit := range map[string]int{"in a header": 0, "in a file's content": headerBytes} {
		t.Run(name, func(t *testing.T) {
			err := writeRootfsTar(&failAfter{limit: limit}, root)
			if err == nil || !strings.Contains(err.Error(), "reader gone") {
				t.Fatalf("err = %v, want the write error", err)
			}
		})
	}
}

// File names on a Linux disk are bytes, not UTF-8; the export keeps them.
func TestWriteRootfsTarKeepsNamesThatAreNotUTF8(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "caf\xe9")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Skipf("this filesystem wants UTF-8 names: %v", err)
	}
	writeGuestFile(t, dir, "/menu", "soup")
	var buf bytes.Buffer
	if err := writeRootfsTar(&buf, root); err != nil {
		t.Fatalf("writeRootfsTar: %v", err)
	}
	headers, _ := tarEntries(t, buf.Bytes())
	if _, ok := headers["caf\xe9/menu"]; !ok {
		t.Fatalf("entries %v, want caf\\xe9/menu", headers)
	}
}
