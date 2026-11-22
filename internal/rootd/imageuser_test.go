package rootd

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
	"github.com/aerol-ai/microvm/internal/rootpolicy"
)

// snapRoot is the test policy's snapshots folder.
var snapRoot = defaultSnapshotterRoot + "/snapshots"

// layer is snapshot n's fs folder.
func layer(n int) string { return fmt.Sprintf("%s/%d/fs", snapRoot, n) }

// activeMounts are the overlayfs snapshotter's mounts of active snapshot
// own over the image layers lower (top first).
func activeMounts(own int, lower ...int) []rootpolicy.Mount {
	var dirs []string
	for _, l := range lower {
		dirs = append(dirs, layer(l))
	}
	return []rootpolicy.Mount{{Type: "overlay", Source: "overlay", Options: []string{"index=off",
		fmt.Sprintf("workdir=%s/%d/work", snapRoot, own), "upperdir=" + layer(own), "lowerdir=" + strings.Join(dirs, ":")}}}
}

type fakeSnap struct {
	info   SnapshotInfo
	mounts []rootpolicy.Mount
	err    error
}

// fakeSnapshots is containerd's snapshot service in the helper's own
// namespace and snapshotter: only what it holds exists.
type fakeSnapshots struct {
	mu    sync.Mutex
	snaps map[string]fakeSnap
}

func newFakeSnapshots() *fakeSnapshots {
	return &fakeSnapshots{snaps: map[string]fakeSnap{
		"sb-1": {info: SnapshotInfo{Kind: "active", Parent: "sha256:aaaa"}, mounts: activeMounts(3, 2, 1)},
	}}
}

func (f *fakeSnapshots) set(key string, s fakeSnap) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.snaps[key] = s
}

func (f *fakeSnapshots) get(key string) (fakeSnap, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.snaps[key]
	if !ok {
		return s, fmt.Errorf("%w: snapshot %s: not found", errSnapshotGone, key)
	}
	return s, s.err
}

func (f *fakeSnapshots) Stat(_ context.Context, key string) (SnapshotInfo, error) {
	s, err := f.get(key)
	return s.info, err
}

func (f *fakeSnapshots) Mounts(_ context.Context, key string) ([]rootpolicy.Mount, error) {
	s, err := f.get(key)
	return s.mounts, err
}

// fakeImages is the kernel's read of an image's files: each image, by its
// layer folders, holds these files.
type fakeImages struct {
	mu    sync.Mutex
	files map[string]UserFiles // by strings.Join(layers, ":")
	reads []string
	block bool
}

func (f *fakeImages) read(ctx context.Context, snapshotsDir, mountpoint string, layers []string) (UserFiles, error) {
	f.mu.Lock()
	key := strings.Join(layers, ":")
	f.reads = append(f.reads, key)
	files, block := f.files[key], f.block
	f.mu.Unlock()
	if snapshotsDir != snapRoot || mountpoint == "" {
		return UserFiles{}, fmt.Errorf("read at %s, mounting on %q", snapshotsDir, mountpoint)
	}
	if block {
		<-ctx.Done()
		return UserFiles{}, ctx.Err()
	}
	return files, nil
}

func (f *fakeImages) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.reads)
}

func file(body string) UserFile { return UserFile{Present: true, Body: []byte(body)} }

const (
	testPasswd = "root:x:0:0:root:/root:/bin/sh\napp:x:1000:1000:app:/home/app:/bin/sh\n"
	testGroup  = "root:x:0:\napp:x:1000:\nwheel:x:10:app\naudio:x:29:app\n"
)

// snapRig is a helper with containerd's snapshots, an image's files and
// XFS quotas all faked.
func snapRig(t *testing.T) (*rig, *fakeSnapshots, *fakeImages, *fakeQuota) {
	snaps := newFakeSnapshots()
	images := &fakeImages{files: map[string]UserFiles{
		layer(2) + ":" + layer(1): {Passwd: file(testPasswd), Group: file(testGroup)},
	}}
	q := &fakeQuota{}
	r := newRig(t, func(_ *Config, o *Options) { o.Snapshots, o.ReadImageFiles, o.Quota = snaps, images.read, q })
	return r, snaps, images, q
}

func userReq(id, user string) *rootdpb.PrepareSandboxRequest {
	return &rootdpb.PrepareSandboxRequest{Parts: []string{rootdpb.PartImageUser}, ContainerId: id, ImageUser: &rootdpb.ImageUser{User: user}}
}

// TestImageUserPart (M1 PR 7): the helper resolves an image's user from
// the image's own files, as containerd would, and caches the answer by
// what it read from containerd itself.
func TestImageUserPart(t *testing.T) {
	r, snaps, images, _ := snapRig(t)
	c := helperClient(r)
	resp, err := c.PrepareSandbox(callCtx(t), userReq("sb-1", "app"))
	if err != nil {
		t.Fatal(err)
	}
	want := &rootdpb.ImageUserAnswer{Uid: 1000, Gid: 1000, AdditionalGids: []uint32{1000, 10, 29}}
	if !proto.Equal(resp.GetImageUser(), want) {
		t.Fatalf("answer %v, want %v", resp.GetImageUser(), want)
	}
	// The image's layers only: never the container's own writable one.
	if images.count() != 1 || images.reads[0] != layer(2)+":"+layer(1) {
		t.Fatalf("read %v", images.reads)
	}
	// Cached: the same image and user read nothing again, whatever the
	// container.
	snaps.set("sb-2", fakeSnap{info: SnapshotInfo{Kind: "active", Parent: "sha256:aaaa"}, mounts: activeMounts(4, 2, 1)})
	resp, err = c.PrepareSandbox(callCtx(t), userReq("sb-2", "app"))
	if err != nil || !proto.Equal(resp.GetImageUser(), want) || images.count() != 1 {
		t.Fatalf("a second container of the image: %v, %v (%d reads)", resp, err, images.count())
	}
	// Another user of the same image is read again.
	resp, err = c.PrepareSandbox(callCtx(t), userReq("sb-1", ""))
	if err != nil || !proto.Equal(resp.GetImageUser(), &rootdpb.ImageUserAnswer{AdditionalGids: []uint32{0}}) || images.count() != 2 {
		t.Fatalf("no USER: %v, %v (%d reads)", resp, err, images.count())
	}
	if len(r.refused()) != 0 {
		t.Fatalf("refusals %v", r.refused())
	}
}

// TestImageUserCacheTakesNoClaim: the cache's key is what the helper read
// from containerd, never what the agent says. A broken agent that names
// one container after asking for another image's user gets that
// container's own image's answer; a snapshot made again under the same
// parent name, with other layers, is read again; and a request that tries
// to carry a digest of its own is refused as a field this helper does not
// know.
func TestImageUserCacheTakesNoClaim(t *testing.T) {
	r, snaps, images, _ := snapRig(t)
	c := helperClient(r)
	// A second image, whose "app" is uid 4242.
	snaps.set("sb-evil", fakeSnap{info: SnapshotInfo{Kind: "active", Parent: "sha256:bbbb"}, mounts: activeMounts(8, 7, 6)})
	images.files[layer(7)+":"+layer(6)] = UserFiles{Passwd: file("app:x:4242:4242::/:/bin/sh\n")}
	if _, err := c.PrepareSandbox(callCtx(t), userReq("sb-evil", "app")); err != nil {
		t.Fatal(err)
	}
	resp, err := c.PrepareSandbox(callCtx(t), userReq("sb-1", "app"))
	if err != nil || resp.GetImageUser().GetUid() != 1000 {
		t.Fatalf("sb-1 got %v, %v: another image's answer", resp, err)
	}
	// The same parent name over other layer folders (the parent removed
	// and made again): read again, not served from the cache.
	snaps.set("sb-again", fakeSnap{info: SnapshotInfo{Kind: "active", Parent: "sha256:aaaa"}, mounts: activeMounts(12, 11, 10)})
	images.files[layer(11)+":"+layer(10)] = UserFiles{Passwd: file("app:x:7:7::/:/bin/sh\n")}
	n := images.count()
	resp, err = c.PrepareSandbox(callCtx(t), userReq("sb-again", "app"))
	if err != nil || resp.GetImageUser().GetUid() != 7 || images.count() != n+1 {
		t.Fatalf("a parent made again: %v, %v (%d reads, was %d)", resp, err, images.count(), n)
	}
	// A "digest" field from the agent: unknown to this helper, so the
	// call is Unimplemented, and nothing is cached or read.
	n = images.count()
	_, err = c.PrepareSandbox(callCtx(t), withUnknownField(userReq("sb-1", "app")))
	if status.Code(err) != codes.Unimplemented || images.count() != n {
		t.Fatalf("a claimed digest: %v", err)
	}
	_, err = c.PrepareSandbox(callCtx(t), &rootdpb.PrepareSandboxRequest{Parts: []string{rootdpb.PartImageUser}, ContainerId: "sb-1",
		ImageUser: withUnknownField(&rootdpb.ImageUser{User: "app"})})
	if status.Code(err) != codes.Unimplemented || images.count() != n {
		t.Fatalf("a claimed digest in the image user: %v", err)
	}
}

// TestImageUserBrokenAgent: a snapshot that is not the container's own
// active root filesystem, of the helper's namespace and snapshotter, is
// refused before anything is mounted or read; so is a user no image
// config holds. Every refusal is recorded (D9).
func TestImageUserBrokenAgent(t *testing.T) {
	for _, tc := range []struct {
		name   string
		snap   *fakeSnap // nil: no such snapshot here
		user   string
		code   codes.Code
		reason string
	}{
		{"a snapshot of another namespace or snapshotter", nil, "app", codes.NotFound, string(rootpolicy.RuleSnapshot)},
		{"an image's own committed layer", &fakeSnap{info: SnapshotInfo{Kind: "committed"}, mounts: activeMounts(3, 2, 1)}, "app", codes.InvalidArgument, string(rootpolicy.RuleSnapshot)},
		{"a view", &fakeSnap{info: SnapshotInfo{Kind: "view"}, mounts: activeMounts(3, 2, 1)}, "app", codes.InvalidArgument, string(rootpolicy.RuleSnapshot)},
		{"layers outside the snapshotter's root", &fakeSnap{info: SnapshotInfo{Kind: "active"},
			mounts: []rootpolicy.Mount{{Type: "overlay", Source: "overlay", Options: []string{"upperdir=" + layer(3), "workdir=" + snapRoot + "/3/work", "lowerdir=/etc:/"}}}},
			"app", codes.InvalidArgument, string(rootpolicy.RuleSnapshotMount)},
		{"a layer's subfolder", &fakeSnap{info: SnapshotInfo{Kind: "active"},
			mounts: []rootpolicy.Mount{{Type: "overlay", Source: "overlay", Options: []string{"upperdir=" + layer(3), "workdir=" + snapRoot + "/3/work", "lowerdir=" + layer(2) + "/etc"}}}},
			"app", codes.InvalidArgument, string(rootpolicy.RuleSnapshotMount)},
		{"two mounts", &fakeSnap{info: SnapshotInfo{Kind: "active"}, mounts: append(activeMounts(3, 2), activeMounts(4, 1)...)},
			"app", codes.InvalidArgument, string(rootpolicy.RuleSnapshotMount)},
		{"a user with a newline", &fakeSnap{info: SnapshotInfo{Kind: "active"}, mounts: activeMounts(3, 2, 1)}, "app\nroot", codes.InvalidArgument, string(rootpolicy.RuleImageUser)},
		{"a user past the bound", &fakeSnap{info: SnapshotInfo{Kind: "active"}, mounts: activeMounts(3, 2, 1)}, strings.Repeat("a", 257), codes.InvalidArgument, string(rootpolicy.RuleImageUser)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, snaps, images, _ := snapRig(t)
			delete(snaps.snaps, "sb-1")
			if tc.snap != nil {
				snaps.set("sb-1", *tc.snap)
			}
			_, err := helperClient(r).PrepareSandbox(callCtx(t), userReq("sb-1", tc.user))
			if status.Code(err) != tc.code {
				t.Fatalf("err %v, want %v", err, tc.code)
			}
			if ref := r.refused(); len(ref) != 1 || ref[0].Reason != tc.reason {
				t.Fatalf("refusals %v, want one %s", ref, tc.reason)
			}
			if images.count() != 0 {
				t.Fatalf("a refused request read an image: %v", images.reads)
			}
		})
	}
}

// TestImageUserImageFaults: an image's own files are the tenant's. One
// whose passwd names no such user, or that the reader would not take, or
// a read that runs past its time, fails the create, as in single mode, and
// is no refusal.
func TestImageUserImageFaults(t *testing.T) {
	r, _, images, _ := snapRig(t)
	c := helperClient(r)
	for _, tc := range []struct {
		name  string
		files UserFiles
		user  string
		want  string
	}{
		{"no such user", UserFiles{Passwd: file(testPasswd)}, "nobody", "no users found"},
		{"a passwd that is not a regular file", UserFiles{Passwd: UserFile{Present: true, Bad: "not a regular file"}}, "app", "not a regular file"},
		{"a group that is not a regular file", UserFiles{Passwd: file(testPasswd), Group: UserFile{Present: true, Bad: "not a regular file"}}, "app", "not a regular file"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			images.mu.Lock()
			images.files[layer(2)+":"+layer(1)] = tc.files
			images.mu.Unlock()
			_, err := c.PrepareSandbox(callCtx(t), userReq("sb-1", tc.user))
			if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err %v, want %q", err, tc.want)
			}
		})
	}
	// A bad file containerd never reads is no fault: a numeric user and
	// group read neither file's names, and a uid with no passwd entry
	// stops before the group file.
	images.mu.Lock()
	images.files[layer(2)+":"+layer(1)] = UserFiles{Passwd: file(testPasswd), Group: UserFile{Present: true, Bad: "not a regular file"}}
	images.mu.Unlock()
	if resp, err := c.PrepareSandbox(callCtx(t), userReq("sb-1", "4321:4321")); err != nil || resp.GetImageUser().GetUid() != 4321 {
		t.Fatalf("a numeric user over a bad Group: %v, %v", resp, err)
	}
	orig := imageUserTimeout
	imageUserTimeout = 50 * time.Millisecond
	t.Cleanup(func() { imageUserTimeout = orig })
	images.mu.Lock()
	images.block = true
	images.mu.Unlock()
	start := time.Now()
	_, err := c.PrepareSandbox(callCtx(t), userReq("sb-1", "someone-else"))
	if status.Code(err) != codes.FailedPrecondition || time.Since(start) > 5*time.Second {
		t.Fatalf("a read past its time: %v after %v", err, time.Since(start))
	}
	if len(r.refused()) != 0 {
		t.Fatalf("an image's fault counted as a refusal: %v", r.refused())
	}
}

// TestResolveImageUser: containerd's own resolution, over the files the
// helper read: every USER form, and absent files.
func TestResolveImageUser(t *testing.T) {
	both := UserFiles{Passwd: file(testPasswd), Group: file(testGroup)}
	for _, tc := range []struct {
		name  string
		files UserFiles
		user  string
		want  *rootdpb.ImageUserAnswer
		err   string
	}{
		{"no USER", both, "", &rootdpb.ImageUserAnswer{AdditionalGids: []uint32{0}}, ""},
		{"a name", both, "app", &rootdpb.ImageUserAnswer{Uid: 1000, Gid: 1000, AdditionalGids: []uint32{1000, 10, 29}}, ""},
		{"a uid", both, "1000", &rootdpb.ImageUserAnswer{Uid: 1000, Gid: 1000, AdditionalGids: []uint32{1000, 10, 29}}, ""},
		{"a uid not in passwd", both, "4242", &rootdpb.ImageUserAnswer{Uid: 4242, AdditionalGids: []uint32{0}}, ""},
		{"name:group", both, "app:wheel", &rootdpb.ImageUserAnswer{Uid: 1000, Gid: 10, AdditionalGids: []uint32{10, 29}}, ""},
		{"uid:gid", both, "5:6", &rootdpb.ImageUserAnswer{Uid: 5, Gid: 6, AdditionalGids: []uint32{6}}, ""},
		{"no files, a uid", UserFiles{}, "1000", &rootdpb.ImageUserAnswer{Uid: 1000, AdditionalGids: []uint32{0}}, ""},
		{"no files, a name", UserFiles{}, "app", nil, "no such file"},
		{"three parts", both, "a:b:c", nil, "invalid USER"},
		{"a group not there", both, "app:nogroup", nil, "no groups found"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolveImageUser(context.Background(), tc.files, tc.user)
			if tc.err != "" {
				if err == nil || !strings.Contains(err.Error(), tc.err) {
					t.Fatalf("err %v, want %q", err, tc.err)
				}
				return
			}
			if err != nil || !proto.Equal(got, tc.want) {
				t.Fatalf("%v, %v; want %v", got, err, tc.want)
			}
		})
	}
}

// fakeQuota records the XFS project quota calls.
type fakeQuota struct {
	mu          sync.Mutex
	calls       []string
	notEnforced error
	assignErr   error
}

func (q *fakeQuota) Enforced(dir string) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.calls = append(q.calls, "enforced "+dir)
	return q.notEnforced
}

func (q *fakeQuota) Assign(dir string, id uint32) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.calls = append(q.calls, fmt.Sprintf("assign %s %d", dir, id))
	return q.assignErr
}

func (q *fakeQuota) Limit(dir string, id uint32, bytes uint64) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.calls = append(q.calls, fmt.Sprintf("limit %s %d %d", dir, id, bytes))
	return nil
}

func (q *fakeQuota) seen() []string {
	q.mu.Lock()
	defer q.mu.Unlock()
	return slices.Clone(q.calls)
}

func quotaReq(id string, bytes uint64) *rootdpb.PrepareSandboxRequest {
	return &rootdpb.PrepareSandboxRequest{Parts: []string{rootdpb.PartDiskQuota}, ContainerId: id, DiskQuota: &rootdpb.DiskQuota{Bytes: bytes}}
}

// TestDiskQuotaPart (M1 PR 7): the helper limits the container's own
// snapshot folder, which it finds from containerd's answer, in a project
// of AerolVM's range; a repeat sets the same; a volume without project
// quotas fails the call without latching it.
func TestDiskQuotaPart(t *testing.T) {
	r, _, _, q := snapRig(t)
	c := helperClient(r)
	q.notEnforced = errors.New("pqnoenforce")
	if _, err := c.PrepareSandbox(callCtx(t), quotaReq("sb-1", 5<<30)); status.Code(err) != codes.FailedPrecondition || len(r.refused()) != 0 {
		t.Fatalf("not enforced: %v, refusals %v", err, r.refused())
	}
	q.notEnforced = nil
	for range 2 {
		if _, err := c.PrepareSandbox(callCtx(t), quotaReq("sb-1", 5<<30)); err != nil {
			t.Fatal(err)
		}
	}
	dir := snapRoot + "/3"
	project := rootpolicy.QuotaProjectBase + 3
	want := []string{"enforced " + dir, "enforced " + dir,
		fmt.Sprintf("assign %s %d", dir, project), fmt.Sprintf("limit %s %d %d", dir, project, uint64(5<<30)),
		fmt.Sprintf("assign %s %d", dir, project), fmt.Sprintf("limit %s %d %d", dir, project, uint64(5<<30))}
	if got := q.seen(); !slices.Equal(got, want) {
		t.Fatalf("calls %v, want %v", got, want)
	}
	q.assignErr = errors.New("EPERM")
	if _, err := c.PrepareSandbox(callCtx(t), quotaReq("sb-1", 5<<30)); status.Code(err) != codes.Internal {
		t.Fatalf("a failed assign: %v", err)
	}
}

// TestDiskQuotaBrokenAgent: a quota on anything but a container's own
// writable layer, in a project outside AerolVM's range, or of a size
// outside the bounds, is refused before any quota call.
func TestDiskQuotaBrokenAgent(t *testing.T) {
	active := func(m []rootpolicy.Mount) *fakeSnap { return &fakeSnap{info: SnapshotInfo{Kind: "active"}, mounts: m} }
	for _, tc := range []struct {
		name   string
		snap   *fakeSnap
		bytes  uint64
		code   codes.Code
		reason rootpolicy.Rule
	}{
		{"no bytes: a limit lifted", active(activeMounts(3, 2, 1)), 0, codes.InvalidArgument, rootpolicy.RuleDiskQuota},
		{"under a gigabyte", active(activeMounts(3, 2, 1)), 1 << 29, codes.InvalidArgument, rootpolicy.RuleDiskQuota},
		{"past the bound", active(activeMounts(3, 2, 1)), rootpolicy.MaxQuotaBytes + 1, codes.InvalidArgument, rootpolicy.RuleDiskQuota},
		{"a snapshot outside the project range", active(activeMounts(int(rootpolicy.QuotaProjectSpan)+1, 2, 1)), 1 << 30, codes.InvalidArgument, rootpolicy.RuleDiskQuota},
		{"a writable layer outside the snapshotter's root", active([]rootpolicy.Mount{{Type: "overlay", Source: "overlay",
			Options: []string{"upperdir=/var/lib/sandboxd/fs", "workdir=/var/lib/sandboxd/work", "lowerdir=" + layer(1)}}}), 1 << 30, codes.InvalidArgument, rootpolicy.RuleSnapshotMount},
		{"a view's read-only bind", active([]rootpolicy.Mount{{Type: "bind", Source: layer(1), Options: []string{"ro", "rbind"}}}), 1 << 30, codes.InvalidArgument, rootpolicy.RuleSnapshot},
		{"no such snapshot", nil, 1 << 30, codes.NotFound, rootpolicy.RuleSnapshot},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, snaps, _, q := snapRig(t)
			delete(snaps.snaps, "sb-1")
			if tc.snap != nil {
				snaps.set("sb-1", *tc.snap)
			}
			_, err := helperClient(r).PrepareSandbox(callCtx(t), quotaReq("sb-1", tc.bytes))
			if status.Code(err) != tc.code {
				t.Fatalf("err %v, want %v", err, tc.code)
			}
			if ref := r.refused(); len(ref) != 1 || ref[0].Reason != string(tc.reason) {
				t.Fatalf("refusals %v, want one %s", ref, tc.reason)
			}
			if got := q.seen(); len(got) != 0 {
				t.Fatalf("a refused quota reached the kernel: %v", got)
			}
		})
	}
	// A snapshot with no parent: its own folder, bound.
	r, snaps, _, q := snapRig(t)
	snaps.set("sb-1", fakeSnap{info: SnapshotInfo{Kind: "active"}, mounts: []rootpolicy.Mount{{Type: "bind", Source: layer(5), Options: []string{"rw", "rbind"}}}})
	if _, err := helperClient(r).PrepareSandbox(callCtx(t), quotaReq("sb-1", 1<<30)); err != nil {
		t.Fatal(err)
	}
	if got := q.seen(); len(got) != 3 || got[1] != fmt.Sprintf("assign %s/5 %d", snapRoot, rootpolicy.QuotaProjectBase+5) {
		t.Fatalf("calls %v", got)
	}
}

// TestContainerPartsTogether: a create's one call carries all three
// parts; the limit goes on before the image is read and the files are
// made. Parts and their values come together; a helper with no snapshot
// reader lists neither snapshot part, and a newer agent's request for one
// is version skew.
func TestContainerPartsTogether(t *testing.T) {
	r, _, images, q := snapRig(t)
	agentSocket(t, r.cfg, "sb-1", testNonce)
	req := filesReq("sb-1")
	req.Parts = append(req.Parts, rootdpb.PartImageUser, rootdpb.PartDiskQuota)
	req.ImageUser, req.DiskQuota = &rootdpb.ImageUser{User: "app"}, &rootdpb.DiskQuota{Bytes: 2 << 30}
	resp, err := helperClient(r).PrepareSandbox(callCtx(t), req)
	if err != nil || resp.GetImageUser().GetUid() != 1000 || resp.GetFiles().GetStdoutPath() == "" || len(q.seen()) != 3 || images.count() != 1 {
		t.Fatalf("all three: %v, %v (quota %v, reads %d)", resp, err, q.seen(), images.count())
	}
	for _, tc := range []struct {
		name string
		req  *rootdpb.PrepareSandboxRequest
	}{
		{"an image user with no part", &rootdpb.PrepareSandboxRequest{Parts: []string{rootdpb.PartDiskQuota}, ContainerId: "sb-1",
			DiskQuota: &rootdpb.DiskQuota{Bytes: 1 << 30}, ImageUser: &rootdpb.ImageUser{}}},
		{"a part with no values", &rootdpb.PrepareSandboxRequest{Parts: []string{rootdpb.PartDiskQuota}, ContainerId: "sb-1"}},
		{"a quota under the cgroup part", &rootdpb.PrepareSandboxRequest{Parts: []string{rootdpb.PartCgroup}, Cgroup: &rootdpb.SandboxCgroup{ContainerId: "sb-1"},
			DiskQuota: &rootdpb.DiskQuota{Bytes: 1 << 30}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := helperClient(r).PrepareSandbox(callCtx(t), tc.req); status.Code(err) != codes.InvalidArgument && status.Code(err) != codes.Unimplemented {
				t.Fatalf("err %v", err)
			}
		})
	}
	plain := newRig(t, nil)
	v, err := helperClient(plain).Version(callCtx(t), &rootdpb.VersionRequest{})
	if err != nil || slices.Contains(v.GetParts(), rootdpb.PartImageUser) || slices.Contains(v.GetParts(), rootdpb.PartDiskQuota) {
		t.Fatalf("a helper with no snapshot reader lists %v", v.GetParts())
	}
	if _, err := helperClient(plain).PrepareSandbox(callCtx(t), userReq("sb-1", "app")); status.Code(err) != codes.Unimplemented {
		t.Fatalf("image user on a helper without it: %v", err)
	}
}
