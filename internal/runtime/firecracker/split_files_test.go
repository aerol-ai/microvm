package firecracker

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"

	"github.com/aerol-ai/microvm/internal/network/tap/taphost"
	"github.com/aerol-ai/microvm/internal/rootpolicy"
	"github.com/aerol-ai/microvm/pkg/models"
)

// splitTemplate is a template with a snapshot, its files in a folder of the
// test's: what the template resolver answers.
func splitTemplate(t *testing.T, cid uint32) *TemplateResolution {
	t.Helper()
	dir := t.TempDir()
	res := &TemplateResolution{TemplateID: "tpl-1", RootfsPath: filepath.Join(dir, rootfsFileName), HasSnapshot: true, HasOverlay: true,
		SnapshotMemoryPath: filepath.Join(dir, sandboxSnapshotMemoryFileName), SnapshotStatePath: filepath.Join(dir, sandboxSnapshotStateFileName),
		SnapshotVsockCID: cid}
	for _, p := range []string{res.RootfsPath, res.SnapshotMemoryPath, res.SnapshotStatePath} {
		if err := os.WriteFile(p, []byte(filepath.Base(p)), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return res
}

// TestSplitSnapshotLoad (M1 PR 14b): a create from a template's snapshot in
// split mode. The template's memory, state and root disk go into the chroot
// read-only in one helper call, as sandboxd's own files; the overlay goes in
// as the jailer's; the TAP's neighbor gets the snapshot's MAC from its CID;
// the helper shares the vsock socket after the load. The template's files
// stay where they were.
func TestSplitSnapshotLoad(t *testing.T) {
	f := newFakeSplit(t)
	d, client, vsock, _ := splitDriver(t, f)
	tpl := splitTemplate(t, 7)
	d.SetTemplateResolver(fakeResolver{res: tpl})
	if _, err := d.Create(context.Background(), models.CreateSandboxRequest{TemplateID: "tpl-1", CPU: 1, MemoryMB: 128}, "sb-l", "tok", nil); err != nil {
		t.Fatal(err)
	}
	want := []string{"prepare sb-l", "snaptap fctap-test 7", "spawn sb-l",
		"share sb-l snapshot.memory,snapshot.state,rootfs.ext4", "prepare sb-l overlay.ext4", "prepare sb-l"}
	if got := f.seen(); !slices.Equal(got, want) {
		t.Fatalf("helper calls\n got %v\nwant %v", got, want)
	}
	load := client.snapshotLoad
	if load == nil || load.SnapshotPath != sandboxSnapshotStateFileName || load.MemBackend.BackendPath != sandboxSnapshotMemoryFileName ||
		client.drivePatches[rootDriveID].PathOnHost != rootfsFileName || client.drivePatches[overlayDriveID].PathOnHost != overlayFileName {
		t.Fatalf("API paths: load %+v patches %+v", load, client.drivePatches)
	}
	root, _ := f.jail("sb-l")
	if vsock.lastSocketPath != filepath.Join(root, hostVsockUDSName) {
		t.Fatalf("vsock dialed at %s", vsock.lastSocketPath)
	}
	for _, p := range []string{tpl.RootfsPath, tpl.SnapshotMemoryPath, tpl.SnapshotStatePath} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("the template's %s is gone: %v", filepath.Base(p), err)
		}
	}
	// The chroot's memory file is the template's very file.
	if !sameFileAs(tpl.SnapshotMemoryPath, filepath.Join(root, sandboxSnapshotMemoryFileName)) {
		t.Fatal("the chroot's memory file is not the template's")
	}
}

// TestSplitStopAndStart (M1 PR 14b): a stop has the helper hand the VM's
// snapshot and disks to sandboxd's group and copies each out into the
// sandbox's snapshot folder, before the VM ends; a start copies the disks
// into the stage folder, shares the saved memory and state read-only,
// restores the TAP with the snapshot's MAC, and shares the VM's sockets.
func TestSplitStopAndStart(t *testing.T) {
	f := newFakeSplit(t)
	d, client, _, _ := splitDriver(t, f)
	ctx := context.Background()
	if _, err := d.Create(ctx, models.CreateSandboxRequest{Image: "alpine:3.20", CPU: 1, MemoryMB: 128, OverlaySizeGB: 1}, "sb-ss", "tok", nil); err != nil {
		t.Fatal(err)
	}
	root, _ := f.jail("sb-ss")
	client.snapshotBase = root // firecracker writes its snapshot in its chroot
	before := len(f.seen())
	if err := d.Stop(ctx, "sb-ss"); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	wantStop := []string{"hand-out sb-ss saved.memory,saved.state", "hand-out sb-ss rootfs.ext4", "hand-out sb-ss overlay.ext4",
		"stop sb-ss", "untap fctap-test", "stop sb-ss"}
	if got := f.seen()[before:]; !slices.Equal(got, wantStop) {
		t.Fatalf("stop's helper calls\n got %v\nwant %v", got, wantStop)
	}
	_, memPath, statePath, rootfsPath, overlayPath, _ := d.sandboxSnapshotPaths("sb-ss")
	for _, p := range []string{memPath, statePath, rootfsPath, overlayPath} {
		fi, err := os.Stat(p)
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("saved %s: %v %v", filepath.Base(p), fi, err)
		}
	}
	if b, _ := os.ReadFile(memPath); string(b) != "fake-snapshot-"+rootpolicy.FirecrackerSavedMemory {
		t.Fatalf("saved memory holds %q", b)
	}

	before = len(f.seen())
	if _, err := d.StartWithIdentity(ctx, "sb-ss", "sb-ss", "tok"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	wantStart := []string{"prepare sb-ss", "snaptap fctap-test 3", "spawn sb-ss", "share sb-ss snapshot.memory,snapshot.state",
		"prepare sb-ss rootfs.ext4", "prepare sb-ss overlay.ext4", "prepare sb-ss"}
	if got := f.seen()[before:]; !slices.Equal(got, wantStart) {
		t.Fatalf("start's helper calls\n got %v\nwant %v", got, wantStart)
	}
	if load := client.snapshotLoad; load.SnapshotPath != sandboxSnapshotStateFileName || load.MemBackend.BackendPath != sandboxSnapshotMemoryFileName {
		t.Fatalf("LoadSnapshot %+v", load)
	}
	// The saved snapshot stays sandboxd's: a later move reads it.
	if !sameFileAs(memPath, filepath.Join(root, sandboxSnapshotMemoryFileName)) {
		t.Fatal("the chroot's memory file is not the saved one")
	}
	// A stop after a start: the VM's chroot holds the saved snapshot under
	// the usual names, sandboxd's and read-only to the VM, so firecracker
	// writes the new one under names of its own.
	client.snapshotBase = root
	if err := d.Stop(ctx, "sb-ss"); err != nil {
		t.Fatal(err)
	}
	if c := client.snapshotCreate; c.MemFilePath != rootpolicy.FirecrackerSavedMemory || c.SnapshotPath != rootpolicy.FirecrackerSavedState {
		t.Fatalf("CreateSnapshot wrote %s and %s, want the saved names", c.MemFilePath, c.SnapshotPath)
	}
	// A move of the stopped sandbox carries the folder sandboxd owns.
	if err := d.ExportSandboxSnapshot(ctx, "sb-ss", io.Discard); err != nil {
		t.Fatalf("export: %v", err)
	}
}

// TestSplitStopFailures: a hand-out the helper refuses fails the stop
// before the VM ends, and the VM runs on.
func TestSplitStopFailures(t *testing.T) {
	f := newFakeSplit(t)
	d, client, _, _ := splitDriver(t, f)
	ctx := context.Background()
	if _, err := d.Create(ctx, models.CreateSandboxRequest{Image: "alpine", CPU: 1, MemoryMB: 128}, "sb-sf", "tok", nil); err != nil {
		t.Fatal(err)
	}
	root, _ := f.jail("sb-sf")
	client.snapshotBase = root
	f.outErr = errors.New("refused: host")
	if err := d.Stop(ctx, "sb-sf"); err == nil || !strings.Contains(err.Error(), "refused: host") {
		t.Fatalf("a refused hand-out: %v", err)
	}
	if slices.Contains(f.seen(), "stop sb-sf") {
		t.Fatal("the VM was ended though its snapshot was not saved")
	}
	if got := client.vmStates[len(client.vmStates)-1]; got != "Resumed" {
		t.Fatalf("the VM was left %s", got)
	}
}

// TestSplitTemplateSnapshot (M1 PR 14b): a template's snapshot VM in split
// mode: its disk shared read-only, a placeholder overlay as the jailer's,
// the snapshot handed out and copied to the template's folder.
func TestSplitTemplateSnapshot(t *testing.T) {
	f := newFakeSplit(t)
	d, client, _, _ := splitDriver(t, f)
	dir := t.TempDir()
	disk := filepath.Join(dir, rootfsFileName)
	if err := os.WriteFile(disk, []byte("ext4"), 0o600); err != nil {
		t.Fatal(err)
	}
	root, stage := f.jail(snapshotVMMIDPrefix + "t1")
	client.snapshotBase = root
	// A crashed build left its disk in the stage folder.
	if err := os.MkdirAll(stage, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stage, rootfsFileName), []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := d.SnapshotTemplate(context.Background(), TemplateSnapshotRequest{TemplateID: "t1", RootfsPath: disk,
		OutMemoryPath: filepath.Join(dir, "snapshot.memory"), OutStatePath: filepath.Join(dir, "snapshot.state"), GuestCID: 9, MemoryMB: 128, VCPU: 1})
	if err != nil {
		t.Fatal(err)
	}
	if res.Checksum == "" || res.MemorySizeBytes == 0 {
		t.Fatalf("result %+v", res)
	}
	want := []string{"prepare tpl-snap-t1", "snaptap fctap-test 9", "spawn tpl-snap-t1", "share tpl-snap-t1 rootfs.ext4",
		"prepare tpl-snap-t1 overlay.ext4", "prepare tpl-snap-t1", "hand-out tpl-snap-t1 saved.memory,saved.state",
		"stop tpl-snap-t1", "untap fctap-test", "stop tpl-snap-t1"}
	if got := f.seen(); !slices.Equal(got, want) {
		t.Fatalf("helper calls\n got %v\nwant %v", got, want)
	}
	if _, err := os.Stat(disk); err != nil {
		t.Fatalf("the template's disk is gone: %v", err)
	}
}

// TestSplitTemplateDisk: a template's disk is built in its snapshot VM's
// jail and moved to the template's folder; the jail goes either way.
func TestSplitTemplateDisk(t *testing.T) {
	f := newFakeSplit(t)
	d, _, _, _ := splitDriver(t, f)
	out := filepath.Join(t.TempDir(), rootfsFileName)
	_, stage := f.jail(snapshotVMMIDPrefix + "t2")
	err := d.SplitTemplateDisk(context.Background(), "t2", out, func(stageOut string) error {
		if stageOut != filepath.Join(stage, rootfsFileName) {
			t.Errorf("built at %s", stageOut)
		}
		return os.WriteFile(stageOut, []byte("ext4"), 0o600)
	})
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(out); string(b) != "ext4" {
		t.Fatalf("the template's disk holds %q", b)
	}
	if got := f.seen(); !slices.Equal(got, []string{"prepare tpl-snap-t2", "stop tpl-snap-t2"}) {
		t.Fatalf("calls %v", got)
	}
	if err := d.SplitTemplateDisk(context.Background(), "t2", out, func(string) error { return errors.New("skopeo: 404") }); err == nil {
		t.Fatal("a failed build")
	}
	if err := d.SplitTemplateDisk(context.Background(), "a.b", out, nil); err == nil {
		t.Fatal("a template id that is no VM id")
	}
	if err := New(Config{}, nil).SplitTemplateDisk(context.Background(), "t2", out, nil); err == nil {
		t.Fatal("SplitTemplateDisk in single mode")
	}
}

// TestSplitShareAndCopyOut: the seam's own checks.
func TestSplitShareAndCopyOut(t *testing.T) {
	f := newFakeSplit(t)
	d, _, _, _ := splitDriver(t, f)
	ctx := context.Background()
	root, stage := f.jail("sb-x")
	if _, _, err := f.PrepareFirecracker(ctx, "sb-x"); err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(t.TempDir(), "memory")
	if err := os.WriteFile(src, []byte("m"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Not a jail folder; not a name to share.
	if err := d.splitShare(ctx, "/elsewhere", sharedFile{sandboxSnapshotMemoryFileName, src}); err == nil {
		t.Fatal("a share outside a jail")
	}
	if err := d.splitShare(ctx, stage, sharedFile{overlayFileName, src}); err == nil {
		t.Fatal("the overlay shared read-only")
	}
	// Shared once; asked again, nothing is sent.
	if err := d.splitShare(ctx, root, sharedFile{sandboxSnapshotMemoryFileName, src}); err != nil {
		t.Fatal(err)
	}
	n := len(f.seen())
	if err := d.splitShare(ctx, stage, sharedFile{sandboxSnapshotMemoryFileName, src}); err != nil || len(f.seen()) != n {
		t.Fatalf("a second share: %v (%v)", err, f.seen()[n:])
	}
	// On another filesystem, the file is copied into the stage folder.
	old := linkRootfsFn
	t.Cleanup(func() { linkRootfsFn = old })
	linkRootfsFn = func(string, string) error { return &os.LinkError{Op: "link", Err: syscall.EXDEV} }
	if err := d.splitShare(ctx, stage, sharedFile{sandboxSnapshotStateFileName, src}); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(root, sandboxSnapshotStateFileName)); string(b) != "m" {
		t.Fatalf("the copied file holds %q", b)
	}
	// The helper's refusal is the share's.
	f.shareErr = errors.New("refused: host")
	if err := d.splitShare(ctx, stage, sharedFile{rootfsFileName, src}); err == nil || !strings.Contains(err.Error(), "refused") {
		t.Fatalf("a refused share: %v", err)
	}
	f.outErr = errors.New("refused: host")
	if err := d.splitCopyOut(ctx, root, chrootFile{rootfsFileName, filepath.Join(t.TempDir(), "x")}); err == nil {
		t.Fatal("a refused hand-out")
	}
	if err := d.splitCopyOut(ctx, "/elsewhere", chrootFile{rootfsFileName, "x"}); err == nil {
		t.Fatal("a hand-out outside a jail")
	}
}

// TestCopyFromChroot: sandboxd copies a VM's file out only through a handle
// opened with no link followed, and only a regular file within the cap that
// is its own or has one name.
func TestCopyFromChroot(t *testing.T) {
	dir, out := t.TempDir(), t.TempDir()
	at := func(n string) string { return filepath.Join(dir, n) }
	if err := os.WriteFile(at("mem"), []byte("memory"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := copyFromChroot(at("mem"), filepath.Join(out, "mem")); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(out, "mem")); string(b) != "memory" {
		t.Fatalf("copied %q", b)
	}
	// A link where the VM's memory should be, to a file sandboxd could read.
	other := filepath.Join(t.TempDir(), "other")
	if err := os.WriteFile(other, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(other, at("link")); err != nil {
		t.Fatal(err)
	}
	if err := copyFromChroot(at("link"), filepath.Join(out, "link")); err == nil {
		t.Error("copied through a link")
	}
	// A FIFO: opened without waiting, refused.
	if err := syscall.Mkfifo(at("fifo"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := copyFromChroot(at("fifo"), filepath.Join(out, "fifo")); err == nil || !strings.Contains(err.Error(), "regular") {
		t.Errorf("copied a FIFO: %v", err)
	}
	if err := copyFromChroot(dir, filepath.Join(out, "dir")); err == nil {
		t.Error("copied a folder")
	}
	// Past the cap.
	if err := os.WriteFile(at("big"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(at("big"), rootpolicy.MaxFirecrackerFileBytes+1); err == nil {
		if err := copyFromChroot(at("big"), filepath.Join(out, "big")); err == nil || !strings.Contains(err.Error(), "at most") {
			t.Errorf("copied an oversized file: %v", err)
		}
	}
	// A file of the VM's (not sandboxd's) with a second name.
	old := agentUID
	t.Cleanup(func() { agentUID = old })
	agentUID = func() int { return os.Getuid() + 1 }
	if err := os.Link(at("mem"), at("again")); err != nil {
		t.Fatal(err)
	}
	if err := copyFromChroot(at("mem"), filepath.Join(out, "two")); err == nil || !strings.Contains(err.Error(), "names") {
		t.Errorf("copied a file with two names: %v", err)
	}
	if err := copyFromChroot(at("missing"), filepath.Join(out, "missing")); err == nil {
		t.Error("copied a missing file")
	}
}

func TestCIDFromMAC(t *testing.T) {
	for _, cid := range []uint32{3, 9, 258, 1<<24 - 1} {
		if got, ok := cidFromMAC(macFromCID(cid)); !ok || got != cid {
			t.Errorf("cidFromMAC(macFromCID(%d)) = %d, %v", cid, got, ok)
		}
		// The helper works out the same MAC from the CID.
		if macFromCID(cid) != taphost.MACFromCID(cid) {
			t.Errorf("CID %d: %s here, %s in taphost", cid, macFromCID(cid), taphost.MACFromCID(cid))
		}
	}
	for _, mac := range []string{"", "02:00:00:00:00:02", "02:00:00:00:00", "aa:00:00:00:00:09", "02:00:00:0g:00:09",
		"02:00:00:00-00-09", "02:00:00:00:00:09:00", "02:00:00:00:00:0A"} {
		if cid, ok := cidFromMAC(mac); ok {
			t.Errorf("cidFromMAC(%q) = %d", mac, cid)
		}
	}
}
