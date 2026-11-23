package rootd

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/aerol-ai/microvm/internal/network/tap/taphost"
	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
	"github.com/aerol-ai/microvm/internal/rootpolicy"
)

// groupChown records each hand-over in cl and makes a group change (uid
// -1) for real, as a test can to its own group, so a repeat sees what the
// first call left.
func groupChown(cl *chownLog) func(fd, uid, gid int) error {
	return func(fd, uid, gid int) error {
		_ = cl.fchown(fd, uid, gid)
		if uid == -1 {
			return unix.Fchown(fd, -1, gid)
		}
		return nil
	}
}

// The jail of sb-1, made, with its stage folder and chroot.
func filesJail(t *testing.T, f *firecrackerHosts, id string) (stage, root string) {
	t.Helper()
	if _, err := f.prepare(id, false, &rootdpb.PrepareHostRequest{}); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(f.cfg.ChrootBase, "firecracker", id)
	return dir + "/stage", dir + "/root"
}

func modeOf(t *testing.T, p string) os.FileMode {
	t.Helper()
	fi, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Mode()
}

// TestFirecrackerShare (M1 PR 14b): the agent's snapshot files and a
// template's root disk go into the chroot as they are, the agent's, with
// the jailer's group reading them; a repeat is done already.
func TestFirecrackerShare(t *testing.T) {
	f, cl := newTestFirecracker(t)
	f.fchown = groupChown(cl)
	stage, root := filesJail(t, f, "sb-1")
	names := []string{rootpolicy.FirecrackerMemory, rootpolicy.FirecrackerState, rootpolicy.FirecrackerRootfs}
	for _, n := range names {
		stageFile(t, stage, n)
	}
	// A template's root disk has another name, the template's own: shared
	// files may.
	if err := os.Link(filepath.Join(stage, rootpolicy.FirecrackerRootfs), filepath.Join(t.TempDir(), "template.ext4")); err != nil {
		t.Fatal(err)
	}
	before := len(cl.got)
	if err := f.share("sb-1", names); err != nil {
		t.Fatal(err)
	}
	for _, n := range names {
		if m := modeOf(t, filepath.Join(root, n)); !m.IsRegular() || m.Perm() != sharedMode {
			t.Errorf("%s in the chroot: %v", n, m)
		}
		if _, err := os.Lstat(filepath.Join(stage, n)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s left in the stage folder: %v", n, err)
		}
	}
	// Each shared file gets the jailer's group and keeps its owner (uid -1);
	// the jail's own folders are set as PrepareHost sets them.
	got := slices.DeleteFunc(slices.Clone(cl.got[before:]), func(s string) bool { return strings.HasPrefix(s, "dir:") })
	if len(got) != len(names) || slices.ContainsFunc(got, func(s string) bool { return s != "file:-1:"+itoa(f.cfg.GID) }) {
		t.Fatalf("shared with %v; want each file's group, the jailer's, and no owner change", got)
	}
	// Again (a retry after a lost answer): shared already.
	if err := f.share("sb-1", names); err != nil {
		t.Fatalf("a repeat: %v", err)
	}
}

func TestFirecrackerShareRefusals(t *testing.T) {
	f, _ := newTestFirecracker(t)
	stage, root := filesJail(t, f, "sb-2")
	// Not in the stage folder.
	if err := f.share("sb-2", []string{rootpolicy.FirecrackerMemory}); status.Code(errOf(err)) != codes.InvalidArgument {
		t.Errorf("a missing file: %v", err)
	}
	// A link, even to a file of the agent's own: never followed, nothing
	// linked in.
	own := filepath.Join(t.TempDir(), "own")
	stageFile(t, filepath.Dir(own), "own")
	if err := os.Symlink(own, filepath.Join(stage, rootpolicy.FirecrackerMemory)); err != nil {
		t.Fatal(err)
	}
	if err := f.share("sb-2", []string{rootpolicy.FirecrackerMemory}); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Errorf("shared a link: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(root, rootpolicy.FirecrackerMemory)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a refused share left a name in the chroot: %v", err)
	}
	_ = os.Remove(filepath.Join(stage, rootpolicy.FirecrackerMemory))
	// A folder is no file.
	if err := os.Mkdir(filepath.Join(stage, rootpolicy.FirecrackerState), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := f.share("sb-2", []string{rootpolicy.FirecrackerState}); err == nil || !strings.Contains(err.Error(), "regular") {
		t.Errorf("shared a folder: %v", err)
	}
	// Past the cap: a file the agent would copy and hash for ever.
	big := filepath.Join(stage, rootpolicy.FirecrackerRootfs)
	stageFile(t, stage, rootpolicy.FirecrackerRootfs)
	if err := os.Truncate(big, rootpolicy.MaxFirecrackerFileBytes+1); err != nil {
		t.Skipf("no sparse file past %d bytes here: %v", rootpolicy.MaxFirecrackerFileBytes, err)
	}
	if err := f.share("sb-2", []string{rootpolicy.FirecrackerRootfs}); err == nil || !strings.Contains(err.Error(), "at most") {
		t.Errorf("shared an oversized file: %v", err)
	}
	if err := os.Truncate(big, 4); err != nil {
		t.Fatal(err)
	}
	// Not the agent's.
	f.cfg.AgentUID++
	if err := f.share("sb-2", []string{rootpolicy.FirecrackerRootfs}); err == nil || !strings.Contains(err.Error(), "not the agent") {
		t.Errorf("shared a file that is not the agent's: %v", err)
	}
	f.cfg.AgentUID--
	// An id that is not a sandbox ID.
	if err := f.share("../x", []string{rootpolicy.FirecrackerRootfs}); err == nil {
		t.Error("a jail up the tree")
	}
}

// TestFirecrackerHandOut: what firecracker wrote, and the VM's disks, are
// the agent's group's to read; the owner stays the jailer's user. A file
// the helper shared in is the agent's already.
func TestFirecrackerHandOut(t *testing.T) {
	f, cl := newTestFirecracker(t)
	f.fchown = groupChown(cl)
	_, root := filesJail(t, f, "sb-3")
	names := []string{rootpolicy.FirecrackerMemory, rootpolicy.FirecrackerState, rootpolicy.FirecrackerRootfs, rootpolicy.FirecrackerOverlay}
	for _, n := range names {
		if err := os.WriteFile(filepath.Join(root, n), []byte(n), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	before := len(cl.got)
	if err := f.handOut("sb-3", names); err != nil {
		t.Fatal(err)
	}
	for _, n := range names {
		if m := modeOf(t, filepath.Join(root, n)); m.Perm() != sharedMode {
			t.Errorf("%s: %v", n, m)
		}
	}
	got := cl.got[before:]
	if len(got) != len(names) || slices.ContainsFunc(got, func(s string) bool { return s != "file:-1:"+itoa(f.agentGID) }) {
		t.Fatalf("handed out %v; want each file's group, the agent's, and no owner change", got)
	}
	// Again: the same group and mode.
	if err := f.handOut("sb-3", names); err != nil {
		t.Fatalf("a repeat: %v", err)
	}
	// A shared file (the agent's, the jailer's group) is left as it is.
	f.cfg.UID++ // so the file is not the jailer's user's either
	if err := unix.Chown(filepath.Join(root, rootpolicy.FirecrackerMemory), -1, f.cfg.GID); err != nil {
		t.Fatal(err)
	}
	before = len(cl.got)
	if err := f.handOut("sb-3", []string{rootpolicy.FirecrackerMemory}); err != nil || len(cl.got) != before {
		t.Fatalf("a shared file: %v (calls %v)", err, cl.got[before:])
	}
}

func TestFirecrackerHandOutRefusals(t *testing.T) {
	f, _ := newTestFirecracker(t)
	// No chroot: nothing is made.
	if err := f.handOut("sb-4", []string{rootpolicy.FirecrackerMemory}); status.Code(errOf(err)) != codes.FailedPrecondition {
		t.Fatalf("no chroot: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(f.cfg.ChrootBase, "firecracker", "sb-4")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a hand-out made a jail: %v", err)
	}
	_, root := filesJail(t, f, "sb-4")
	at := func(n string) string { return filepath.Join(root, n) }
	// Missing.
	if err := f.handOut("sb-4", []string{rootpolicy.FirecrackerMemory}); status.Code(errOf(err)) != codes.InvalidArgument {
		t.Errorf("a missing file: %v", err)
	}
	// A link the VM put where its memory should be, to a file the agent
	// can read: never followed.
	other := filepath.Join(t.TempDir(), "other-vm-memory")
	if err := os.WriteFile(other, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(other, at(rootpolicy.FirecrackerMemory)); err != nil {
		t.Fatal(err)
	}
	if err := f.handOut("sb-4", []string{rootpolicy.FirecrackerMemory}); err == nil {
		t.Error("handed out a link")
	}
	if m := modeOf(t, other); m.Perm() != 0o600 {
		t.Errorf("the link's target changed: %v", m)
	}
	// A FIFO, which a reader would wait on: not a regular file.
	if err := unix.Mkfifo(at(rootpolicy.FirecrackerState), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := f.handOut("sb-4", []string{rootpolicy.FirecrackerState}); err == nil || !strings.Contains(err.Error(), "regular") {
		t.Errorf("handed out a FIFO: %v", err)
	}
	// A file with two names: the VM may have linked one file under two.
	if err := os.WriteFile(at(rootpolicy.FirecrackerRootfs), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(at(rootpolicy.FirecrackerRootfs), at("other")); err != nil {
		t.Fatal(err)
	}
	if err := f.handOut("sb-4", []string{rootpolicy.FirecrackerRootfs}); err == nil || !strings.Contains(err.Error(), "names") {
		t.Errorf("handed out a file with two names: %v", err)
	}
	// Past the cap.
	if err := os.WriteFile(at(rootpolicy.FirecrackerOverlay), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(at(rootpolicy.FirecrackerOverlay), rootpolicy.MaxFirecrackerFileBytes+1); err == nil {
		if err := f.handOut("sb-4", []string{rootpolicy.FirecrackerOverlay}); err == nil || !strings.Contains(err.Error(), "at most") {
			t.Errorf("handed out an oversized file: %v", err)
		}
		_ = os.Truncate(at(rootpolicy.FirecrackerOverlay), 4)
	}
	// Not the jailer's user's (nor a shared file).
	f.cfg.UID++
	if err := f.handOut("sb-4", []string{rootpolicy.FirecrackerOverlay}); err == nil || !strings.Contains(err.Error(), "not the jailer") {
		t.Errorf("handed out a file that is not the jailer's user's: %v", err)
	}
}

// TestFirecrackerFilesCalls: the two calls through the helper's server,
// with the rules every request meets first.
func TestFirecrackerFilesCalls(t *testing.T) {
	// Giving folders away needs root: the jail's owners are recorded, not
	// set, and the files the VM writes are the test's own.
	taps, tables := &fakeTaps{}, &fakeTables{}
	fc := testFirecrackerConfig(t)
	own := *fc
	fc.UID += 1000 // the settings' jailer: not the agent
	fh := newFirecrackerHosts(&own, filepath.Join(t.TempDir(), "vm.log"), os.Getgid())
	fh.fchown, fh.checkKernel = groupChown(&chownLog{}), func(string) error { return nil }
	r := newRig(t, func(c *Config, o *Options) {
		c.Hosts = HostsConfig{LogPath: filepath.Join(t.TempDir(), "hosts.log"), Firecracker: fc}
		o.HostKernel, o.TapDevices = newFakeHostKernel(), taps
		o.TapTables = func() (taphost.IsolationBackend, error) { return tables, nil }
		o.TapSysctls = func() error { return nil }
		o.hostLaunchers = map[rootpolicy.HostKind]hostLauncher{rootpolicy.HostFirecracker: fh}
	})
	c := hostClient(r)
	ctx := callCtx(t)
	v, err := c.Version(ctx, &rootdpb.VersionRequest{})
	if err != nil || !slices.Contains(v.GetFeatures(), rootdpb.FeatureShareFirecrackerFiles) || !slices.Contains(v.GetFeatures(), rootdpb.FeatureHandOutFirecrackerFiles) {
		t.Fatalf("Version = %v, %v", v, err)
	}
	const kind = rootdpb.HostKind_HOST_KIND_FIRECRACKER
	prep, err := c.PrepareHost(ctx, &rootdpb.PrepareHostRequest{Kind: kind, Id: "sb-5"})
	if err != nil {
		t.Fatal(err)
	}
	stageFile(t, prep.GetStageDir(), rootpolicy.FirecrackerMemory)
	// No process in the VM's group: the chroot is made again before the
	// jailer starts, so nothing is shared into it yet.
	_, err = c.ShareFirecrackerFiles(ctx, &rootdpb.FirecrackerFilesRequest{Id: "sb-5", Names: []string{rootpolicy.FirecrackerMemory}})
	wantCode(t, err, codes.FailedPrecondition)
	if err := os.WriteFile(filepath.Join(prep.GetRunDir(), rootpolicy.FirecrackerState), []byte("s"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := c.HandOutFirecrackerFiles(ctx, &rootdpb.FirecrackerFilesRequest{Id: "sb-5", Names: []string{rootpolicy.FirecrackerState}}); err != nil {
		t.Fatalf("HandOutFirecrackerFiles: %v", err)
	}
	for _, tc := range []struct {
		name string
		call func() error
	}{
		{"a VM id up the tree", func() error {
			_, err := c.HandOutFirecrackerFiles(ctx, &rootdpb.FirecrackerFilesRequest{Id: "../sb-5", Names: []string{rootpolicy.FirecrackerState}})
			return err
		}},
		{"the kernel handed out", func() error {
			_, err := c.HandOutFirecrackerFiles(ctx, &rootdpb.FirecrackerFilesRequest{Id: "sb-5", Names: []string{rootpolicy.FirecrackerKernel}})
			return err
		}},
		{"a path for a name", func() error {
			_, err := c.HandOutFirecrackerFiles(ctx, &rootdpb.FirecrackerFilesRequest{Id: "sb-5", Names: []string{"../../etc/shadow"}})
			return err
		}},
		{"the overlay shared read-only", func() error {
			_, err := c.ShareFirecrackerFiles(ctx, &rootdpb.FirecrackerFilesRequest{Id: "sb-5", Names: []string{rootpolicy.FirecrackerOverlay}})
			return err
		}},
		{"no file named", func() error {
			_, err := c.ShareFirecrackerFiles(ctx, &rootdpb.FirecrackerFilesRequest{Id: "sb-5"})
			return err
		}},
		{"a file named twice", func() error {
			_, err := c.ShareFirecrackerFiles(ctx, &rootdpb.FirecrackerFilesRequest{Id: "sb-5",
				Names: []string{rootpolicy.FirecrackerMemory, rootpolicy.FirecrackerMemory}})
			return err
		}},
	} {
		t.Run(tc.name, func(t *testing.T) { wantRefusal(t, r, tc.call(), codes.InvalidArgument, string(rootpolicy.RuleHost)) })
	}
	// A snapshot's TAP: the neighbor MAC is the helper's work, from the CID.
	if _, err := c.EnsureTap(ctx, &rootdpb.EnsureTapRequest{Name: "fctap5", GuestCid: 77}); err != nil {
		t.Fatal(err)
	}
	if got := taps.ensured[len(taps.ensured)-1]; got.GuestMAC != taphost.MACFromCID(77) || got.GuestIP != "172.16.0.22" {
		t.Fatalf("a snapshot's TAP: %+v", got)
	}
	for _, cid := range []uint32{1, 2, 1 << 24} {
		_, err := c.EnsureTap(ctx, &rootdpb.EnsureTapRequest{Name: "fctap5", GuestCid: cid})
		wantRefusal(t, r, err, codes.InvalidArgument, string(rootpolicy.RuleTap))
	}
	// A helper with no Firecracker serves neither call.
	none := rootdpb.NewRootHelperClient(newRig(t, nil).conn)
	_, err = none.ShareFirecrackerFiles(ctx, &rootdpb.FirecrackerFilesRequest{Id: "sb-5", Names: []string{rootpolicy.FirecrackerMemory}})
	wantCode(t, err, codes.Unimplemented)
	_, err = none.HandOutFirecrackerFiles(ctx, &rootdpb.FirecrackerFilesRequest{Id: "sb-5", Names: []string{rootpolicy.FirecrackerMemory}})
	wantCode(t, err, codes.Unimplemented)
}
