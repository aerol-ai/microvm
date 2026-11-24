package firecracker

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/rootfstar"
)

// A disk saved as an image in privilege mode split (M1 PR 18): the export
// VM is one more VM of the root helper's, its image is built by the
// helper's mkfs in a jail of its own, and the disk copy goes in as the
// jailer's under the overlay's name.

// splitExportConn is the export VM's agent: it answers each op, and to
// export_rootfs checks the disk copy is in its chroot and streams a tree.
type splitExportConn struct {
	t    *testing.T
	root string
	out  bytes.Buffer
}

func (c *splitExportConn) Write(p []byte) (int, error) {
	var msg struct {
		Op string `json:"op"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(p), &msg); err != nil {
		return 0, err
	}
	c.out.WriteString(`{"ok":true}` + "\n")
	if msg.Op == "export_rootfs" {
		if _, err := os.Stat(filepath.Join(c.root, overlayFileName)); err != nil {
			c.t.Errorf("the disk copy is not in the export VM's chroot: %v", err)
		}
		tree := c.t.TempDir()
		writeGuestFile(c.t, tree, "/etc/hostname", "box\n")
		if err := rootfstar.Write(&c.out, tree); err != nil {
			c.t.Errorf("tar: %v", err)
		}
	}
	return len(p), nil
}
func (c *splitExportConn) Read(p []byte) (int, error) { return c.out.Read(p) }
func (c *splitExportConn) Close() error               { return nil }

// splitExportDriver is a split driver with a toolbox binary, an image store
// and an agent in every VM it dials.
func splitExportDriver(t *testing.T, f *fakeSplit) (*Driver, *fakeClient, *recordingImageStore) {
	t.Helper()
	d, client, _, _ := splitDriver(t, f)
	tb := filepath.Join(t.TempDir(), "toolboxd")
	if err := os.WriteFile(tb, []byte("toolboxd"), 0o755); err != nil {
		t.Fatal(err)
	}
	d.cfg.ToolboxBinaryPath, d.cfg.Mkfs4Bin = tb, ""
	store := &recordingImageStore{}
	d.SetImageStore(store)
	d.SetVsockDialer(dialerFunc(func(_ context.Context, socketPath string, _, _ uint32) (io.ReadWriteCloser, error) {
		return &splitExportConn{t: t, root: filepath.Dir(socketPath)}, nil
	}))
	return d, client, store
}

var exportIDs = regexp.MustCompile(`export-[0-9a-f]{12}`)

// calls are f's helper calls from n on, with each export ID's random part
// named by its order: export-1, export-2.
func exportCalls(f *fakeSplit, n int) []string {
	seen := map[string]string{}
	var out []string
	for _, c := range f.seen()[n:] {
		out = append(out, exportIDs.ReplaceAllStringFunc(c, func(id string) string {
			if _, ok := seen[id]; !ok {
				seen[id] = "export-" + string(rune('0'+len(seen)+1))
			}
			return seen[id]
		}))
	}
	return out
}

// savedSandbox gives sandbox id a stopped snapshot whose guest was flushed.
func savedSandbox(t *testing.T, d *Driver, id string) {
	t.Helper()
	dir, _, _, rootfs, _, manifest := d.sandboxSnapshotPaths(id)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rootfs, []byte("saved-disk"), 0o600); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(sandboxSnapshotManifest{Version: 1, SandboxID: id, VsockCID: 7, GuestFlush: guestFlushDone, CreatedAt: time.Now()})
	if err := os.WriteFile(manifest, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestSplitExportStoppedDisk: a stopped sandbox's disk saved as an image in
// split mode. The export VM's image is built once by the helper's mkfs in a
// jail of its own; the export VM gets its image read-only and the disk
// copy as the jailer's, its sockets after the start, and its jail goes.
func TestSplitExportStoppedDisk(t *testing.T) {
	f := newFakeSplit(t)
	d, client, store := splitExportDriver(t, f)
	savedSandbox(t, d, "sb-s")
	if _, err := d.CreateSnapshot(context.Background(), "sb-s", "aerolvm-snapshot/s:latest"); err != nil {
		t.Fatal(err)
	}
	got := exportCalls(f, 0)
	build := []string{"prepare export-1", "", "stop export-1"}
	if len(got) < 3 || got[0] != build[0] || !strings.HasPrefix(got[1], "mkfs export-1 rootfs.ext4 ") || got[2] != build[2] {
		t.Fatalf("image build calls %v", got)
	}
	vm := []string{"prepare export-2", "spawn export-2", "share export-2 rootfs.ext4", "prepare export-2 overlay.ext4", "prepare export-2", "stop export-2"}
	if !slices.Equal(got[3:9], vm) {
		t.Fatalf("export VM calls\n got %v\nwant %v", got[3:], vm)
	}
	if root, disk := client.drives[rootDriveID], client.drives[exportDriveID]; root.PathOnHost != rootfsFileName || !root.IsReadOnly || disk.PathOnHost != overlayFileName || disk.IsReadOnly {
		t.Fatalf("drives: root %+v, disk %+v", root, disk)
	}
	if _, ok := store.imported["aerolvm-snapshot/s:latest"]; !ok {
		t.Fatal("no image imported")
	}
	// The image is built once per toolbox build.
	n := len(f.seen())
	if _, err := d.CreateSnapshot(context.Background(), "sb-s", "aerolvm-snapshot/s:2"); err != nil {
		t.Fatal(err)
	}
	if got := exportCalls(f, n); got[0] != "prepare export-1" || strings.HasPrefix(got[1], "mkfs") {
		t.Fatalf("a second export built the image again: %v", got)
	}
	// A refused mkfs fails the export, and the build's jail goes.
	f2 := newFakeSplit(t)
	d2, _, _ := splitExportDriver(t, f2)
	savedSandbox(t, d2, "sb-s")
	f2.mkfsErr = errUnitTest("refused: host")
	if _, err := d2.CreateSnapshot(context.Background(), "sb-s", "img"); err == nil || !strings.Contains(err.Error(), "refused") {
		t.Fatalf("a refused mkfs: %v", err)
	}
	if got := exportCalls(f2, 0); !slices.Equal(got, []string{"prepare export-1", got[1], "stop export-1"}) {
		t.Fatalf("calls after a refused mkfs: %v", got)
	}
}

// TestSplitExportRunningDisk: a running sandbox's disk is handed out by the
// helper and copied into the export VM's stage folder while the guest is
// frozen.
func TestSplitExportRunningDisk(t *testing.T) {
	f := newFakeSplit(t)
	d, _, _ := splitExportDriver(t, f)
	root, stage := f.jail("sb-r")
	for _, dir := range []string{root, stage} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, rootfsFileName), []byte("live-disk"), 0o600); err != nil {
		t.Fatal(err)
	}
	d.mu.Lock()
	d.vmms["sb-r"] = &splitVMM{h: f, id: "sb-r", root: root, stage: stage}
	d.guestCID["sb-r"] = 7
	d.mu.Unlock()
	if _, err := d.CreateSnapshot(context.Background(), "sb-r", "img"); err != nil {
		t.Fatal(err)
	}
	got := exportCalls(f, 0)
	i := slices.Index(got, "hand-out sb-r rootfs.ext4")
	if i < 0 || got[i-1] != "prepare export-2" || got[i+1] != "spawn export-2" {
		t.Fatalf("the running disk was not handed out into the export VM: %v", got)
	}
}

// TestOwnPathStageFolders: in split mode a file right in a VM's stage
// folder is sandboxd's own; the chroot beside it, a deeper path and the
// same path in single mode are not.
func TestOwnPathStageFolders(t *testing.T) {
	f := newFakeSplit(t)
	d, _, _, _ := splitDriver(t, f)
	root, stage := f.jail("export-0123456789ab")
	for _, tc := range []struct {
		p  string
		ok bool
	}{
		{filepath.Join(stage, overlayFileName), true},
		{filepath.Join(root, overlayFileName), false},
		{filepath.Join(stage, "sub", overlayFileName), false},
		{filepath.Join(stage, "..", "root", overlayFileName), false},
		{filepath.Join(f.base, "firecracker", "..", "elsewhere"), false},
	} {
		if _, err := d.ownPath(tc.p); (err == nil) != tc.ok {
			t.Errorf("ownPath(%s) = %v, want ok %v", tc.p, err, tc.ok)
		}
	}
	single := New(Config{RunDir: t.TempDir(), UseJailer: true, JailerChrootBase: f.base}, nil)
	if _, err := single.ownPath(filepath.Join(stage, overlayFileName)); err == nil {
		t.Fatal("a stage folder in single mode")
	}
	// A copy out into a chroot is refused before the helper hands anything out.
	n := len(f.seen())
	other, _ := f.jail("sb-other")
	if err := d.splitCopyOut(context.Background(), root, chrootFile{rootfsFileName, filepath.Join(other, overlayFileName)}); err == nil {
		t.Fatal("a copy into another VM's chroot")
	}
	if got := f.seen()[n:]; len(got) != 0 {
		t.Fatalf("helper calls for a refused copy: %v", got)
	}
}

// TestSplitSweepSnapshotExports: at boot the export VMs' jails a crash left
// go through the helper by their IDs; work dirs are sandboxd's own.
func TestSplitSweepSnapshotExports(t *testing.T) {
	f := newFakeSplit(t)
	d, _, _, _ := splitDriver(t, f)
	jail, _ := f.jail("export-0123456789ab")
	if err := os.MkdirAll(jail, 0o755); err != nil {
		t.Fatal(err)
	}
	exports, err := d.snapshotExportDir()
	if err != nil {
		t.Fatal(err)
	}
	work := filepath.Join(exports, "sb-1-123")
	if err := os.MkdirAll(work, 0o700); err != nil {
		t.Fatal(err)
	}
	d.SweepSnapshotExports()
	if !slices.Contains(f.seen(), "stop export-0123456789ab") {
		t.Fatalf("the leftover export VM's jail was not stopped: %v", f.seen())
	}
	if _, err := os.Stat(work); !os.IsNotExist(err) {
		t.Fatal("the export's work dir is left")
	}
}

// TestSplitBuildInJailFailures: a build whose disk cannot be moved to its
// place, or whose jail ID is no VM's, fails, and the jail goes either way.
func TestSplitBuildInJailFailures(t *testing.T) {
	f := newFakeSplit(t)
	d, _, _, _ := splitDriver(t, f)
	build := func(out string) error { return os.WriteFile(out, []byte("ext4"), 0o600) }
	missing := filepath.Join(d.cfg.TemplatesDir, "no-such-folder", "image.ext4")
	if err := d.splitBuildInJail(context.Background(), "export-0123456789ab", "export VM image", missing, build); err == nil || !strings.Contains(err.Error(), "move to") {
		t.Fatalf("a disk with nowhere to go: %v", err)
	}
	if got := f.seen(); !slices.Equal(got, []string{"prepare export-0123456789ab", "stop export-0123456789ab"}) {
		t.Fatalf("helper calls %v", got)
	}
	if err := d.splitBuildInJail(context.Background(), "../export", "export VM image", filepath.Join(d.cfg.TemplatesDir, "x.ext4"), build); err == nil {
		t.Fatal("a jail ID up the tree")
	}
}

type errUnitTest string

func (e errUnitTest) Error() string { return string(e) }
