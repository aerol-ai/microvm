package containerd

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	cntr "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/containers"
	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/pkg/oci"
	"github.com/containerd/errdefs"
	"github.com/containerd/typeurl/v2"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"google.golang.org/grpc"

	runtimeoptions "github.com/containerd/containerd/api/types/runtimeoptions/v1"

	"github.com/aerol-ai/microvm/internal/egress"
	"github.com/aerol-ai/microvm/internal/rootclient"
	"github.com/aerol-ai/microvm/internal/rootd"
	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
	"github.com/aerol-ai/microvm/internal/rootpolicy"
	dockerpkg "github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
)

// memStore is a content store that only reads, for containerd's own
// oci.WithImageConfig, which reads through Image.ContentStore.
type memStore struct {
	content.Store
	p *memProvider
}

func (m memStore) ReaderAt(ctx context.Context, d ocispec.Descriptor) (content.ReaderAt, error) {
	return m.p.ReaderAt(ctx, d)
}

// storeImage is configFakeImage with a content store.
type storeImage struct {
	*configFakeImage
	store content.Store
}

func (s storeImage) ContentStore() content.Store { return s.store }

// newConfigImage is an image whose config is cfg.
func newConfigImage(t *testing.T, cfg ocispec.ImageConfig) (*memProvider, storeImage) {
	t.Helper()
	body, err := json.Marshal(ocispec.Image{Config: cfg})
	if err != nil {
		t.Fatal(err)
	}
	d := digest.FromBytes(body)
	p := &memProvider{blobs: map[digest.Digest][]byte{d: body}}
	img := &configFakeImage{configDesc: ocispec.Descriptor{MediaType: ocispec.MediaTypeImageConfig, Digest: d, Size: int64(len(body))},
		manifestDesc: ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest, Digest: digest.FromString("m" + string(body))}}
	return p, storeImage{img, memStore{p: p}}
}

// fakeSplitSnapshot stands in for the split create's snapshot prepare: it
// records each key, and each end of its lease.
type fakeSplitSnapshot struct {
	mu       sync.Mutex
	prepared []string
	ended    int
	err      error
}

type leaseMark struct{}

func (f *fakeSplitSnapshot) install(t *testing.T) {
	orig := prepareSplitSnapshotFn
	prepareSplitSnapshotFn = func(ctx context.Context, _ *Client, key string, _ cntr.Image) (context.Context, func(context.Context) error, error) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.err != nil {
			return nil, nil, f.err
		}
		f.prepared = append(f.prepared, key)
		return context.WithValue(ctx, leaseMark{}, key), func(context.Context) error {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.ended++
			return nil
		}, nil
	}
	t.Cleanup(func() { prepareSplitSnapshotFn = orig })
}

// removedSnapshots records the snapshot removals of a failed create.
type removedSnapshots struct {
	mu   sync.Mutex
	keys []string
}

func (r *removedSnapshots) Remove(_ context.Context, key string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.keys = append(r.keys, key)
	return nil
}

func (r *removedSnapshots) install(t *testing.T) {
	orig := snapshotsFn
	snapshotsFn = func(*Client) snapshotRemover { return r }
	t.Cleanup(func() { snapshotsFn = orig })
}

// splitCreateRig is a split driver whose helper answers every part, an
// image whose USER is "app", and a containerd that records the container
// a create makes.
type splitCreateRig struct {
	d       *Driver
	h       *partsHelper
	tr      *fakeTransport
	snap    *fakeSplitSnapshot
	removed *removedSnapshots
	specs   *specCapture
	made    []containers.Container
	ctxs    []context.Context
}

func newSplitCreateRig(t *testing.T) *splitCreateRig {
	t.Helper()
	stubToolboxProbe(t)
	hostIPv6(t, true)
	noHostNaming(t)
	r := &splitCreateRig{h: newPartsHelper(t), tr: newFakeTransport(), snap: &fakeSplitSnapshot{}, removed: &removedSnapshots{}, specs: &specCapture{}}
	r.snap.install(t)
	r.removed.install(t)
	r.specs.install(t)
	provider, img := newConfigImage(t, ocispec.ImageConfig{User: "app", Entrypoint: []string{"/entry"}, Cmd: []string{"serve"}})
	r.tr.provider, r.tr.image = provider, img
	r.tr.newContainerFn = func(ctx context.Context, id string, opts ...cntr.NewContainerOpts) (cntr.Container, error) {
		var c containers.Container
		for _, o := range opts {
			if err := o(ctx, nil, &c); err != nil {
				return nil, err
			}
		}
		r.made, r.ctxs = append(r.made, c), append(r.ctxs, ctx)
		fc := &fakeContainer{id: id}
		r.tr.containers[id] = fc
		return fc, nil
	}
	r.d = newTestDriver(t)
	r.d.cfg.ReadyEnabled, r.d.cfg.ReadyDir = true, shortReadyDir(t)
	r.d.SetClient(NewTestClient("aerolvm", r.tr))
	r.d.SetRootHelper(r.h)
	orig := createReadyWaitFn
	createReadyWaitFn = func(context.Context, *dockerpkg.ReadyListener) error { return nil }
	t.Cleanup(func() { createReadyWaitFn = orig })
	return r
}

func (r *splitCreateRig) create(t *testing.T, id string, req models.CreateSandboxRequest) error {
	t.Helper()
	if req.Image == "" {
		req.Image = "cfg:test"
	}
	_, err := r.d.Create(context.Background(), req, id, "tok", nil)
	return err
}

// TestSplitCreateMakesOneHelperCall (M1 PR 7): a split create makes one
// helper call before its container, with the files, the image's user (its
// first create of the image only) and the disk limit, and its container
// and spec use what the helper made: the snapshot it prepared, under its
// own lease; the helper's host files, ready socket name (read only) and
// toolbox; the user the helper resolved; the task's FIFOs.
func TestSplitCreateMakesOneHelperCall(t *testing.T) {
	r := newSplitCreateRig(t)
	if err := r.create(t, "sb-1", models.CreateSandboxRequest{}); err != nil {
		t.Fatal(err)
	}
	if len(r.h.prepares) != 1 || !slices.Equal(r.h.prepares[0].GetParts(), []string{rootdpb.PartFiles, rootdpb.PartImageUser}) ||
		r.h.prepares[0].GetImageUser().GetUser() != "app" || r.h.prepares[0].GetSetup().GetReadyNonce() == "" {
		t.Fatalf("asked %v", r.h.prepares)
	}
	if !slices.Equal(r.snap.prepared, []string{"sb-1"}) || r.snap.ended != 1 {
		t.Fatalf("snapshots %v, leases ended %d", r.snap.prepared, r.snap.ended)
	}
	c := r.made[0]
	if c.SnapshotKey != "sb-1" || c.Snapshotter != splitSnapshotter || r.ctxs[0].Value(leaseMark{}) != "sb-1" {
		t.Fatalf("container %+v made outside the snapshot's lease", c)
	}
	spec := r.specs.last(t)
	if u := spec.Process.User; u.UID != 1000 || u.GID != 1000 || !slices.Equal(u.AdditionalGids, []uint32{1000, 10}) {
		t.Fatalf("user %+v", u)
	}
	byDest := map[string]specs.Mount{}
	for _, m := range spec.Mounts {
		byDest[m.Destination] = m
	}
	if m := byDest["/etc/hosts"]; m.Source != filepath.Join(r.h.dir, "sb-1", "hosts") {
		t.Fatalf("hosts bound from %q", m.Source)
	}
	if m := byDest[dockerpkg.GuestReadySocketPath]; !strings.HasPrefix(m.Source, filepath.Join(r.h.dir, "sb-1")+"/") || !slices.Contains(m.Options, "ro") {
		t.Fatalf("ready socket bound as %+v", m)
	}
	if m := byDest[r.d.cfg.ToolboxMountPath]; m.Source != filepath.Join(r.h.dir, "toolboxd") {
		t.Fatalf("toolbox bound from %q", m.Source)
	}
	if !slices.Contains(spec.Process.Env, "SB_TOOLBOX_TOKEN=tok") || spec.Process.Cwd != "/" {
		t.Fatalf("env %v cwd %q", spec.Process.Env, spec.Process.Cwd)
	}
	if _, err := os.Stat(filepath.Join(r.d.cfg.RunDir, "hosts")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a split create wrote host files of its own: %v", err)
	}
	// The same image again: no image_user part; the agent's cache answers.
	if err := r.create(t, "sb-2", models.CreateSandboxRequest{}); err != nil {
		t.Fatal(err)
	}
	if got := r.h.prepares[1].GetParts(); !slices.Equal(got, []string{rootdpb.PartFiles}) || r.h.prepares[1].GetImageUser() != nil {
		t.Fatalf("second create asked %v", r.h.prepares[1])
	}
	if u := r.specs.last(t).Process.User; u.UID != 1000 {
		t.Fatalf("second create's user %+v", u)
	}
}

// TestSplitCreateDiskAndRunsc: with the disk limit on, the limit rides the
// same call, and nothing in the agent writes a quota; a gVisor create's
// runtime options name the helper's runsc config.
func TestSplitCreateDiskAndRunsc(t *testing.T) {
	r := newSplitCreateRig(t)
	r.d.cfg.DiskQuota = true
	q := &recordingQuota{}
	installQuota(t, q)
	if err := r.create(t, "sb-1", models.CreateSandboxRequest{DiskGB: 3, Runtime: models.RuntimeGvisor}); err != nil {
		t.Fatal(err)
	}
	p := r.h.prepares[0]
	if !slices.Contains(p.GetParts(), rootdpb.PartDiskQuota) || p.GetDiskQuota().GetBytes() != 3<<30 ||
		p.GetSetup().GetRunscConfig() != rootdpb.RunscConfig_RUNSC_CONFIG_DEFAULT {
		t.Fatalf("asked %v", p)
	}
	if len(q.calls) != 0 {
		t.Fatalf("the agent wrote a quota itself: %v", q.calls)
	}
	opts, err := typeurl.UnmarshalAny(r.made[0].Runtime.Options)
	if err != nil {
		t.Fatal(err)
	}
	if ro, ok := opts.(*runtimeoptions.Options); !ok || ro.ConfigPath != filepath.Join(r.h.dir, "config.toml") || r.made[0].Runtime.Name != runscShimName {
		t.Fatalf("runtime %+v (%v)", r.made[0].Runtime, opts)
	}
}

// recordingQuota is the agent's own quota calls, which split mode never
// makes.
type recordingQuota struct{ calls []string }

func (q *recordingQuota) Enforced(dir string) error {
	q.calls = append(q.calls, "enforced")
	return nil
}
func (q *recordingQuota) Assign(string, uint32) error {
	q.calls = append(q.calls, "assign")
	return nil
}
func (q *recordingQuota) Limit(string, uint32, uint64) error {
	q.calls = append(q.calls, "limit")
	return nil
}

func installQuota(t *testing.T, q projectQuota) {
	orig := diskQuotaOps
	diskQuotaOps = q
	t.Cleanup(func() { diskQuotaOps = orig })
}

// TestSplitCreateUndo: a split create that fails leaves nothing of its own
// behind, at any step: its snapshot, its lease, its ready socket and the
// helper's files go. A snapshot that was there already is another create's
// (a duplicate of the same ID): it stays, with everything else of that
// create, and the create answers that the sandbox exists.
func TestSplitCreateUndo(t *testing.T) {
	t.Run("the helper's call fails", func(t *testing.T) {
		r := newSplitCreateRig(t)
		r.h.prepareErr = errors.New("root helper refused the call (snapshot)")
		if err := r.create(t, "sb-1", models.CreateSandboxRequest{}); err == nil || !strings.Contains(err.Error(), "snapshot") {
			t.Fatalf("err %v", err)
		}
		if len(r.made) != 0 || !slices.Equal(r.removed.keys, []string{"sb-1"}) || r.snap.ended != 1 || !slices.Equal(r.h.released(), []string{"sb-1"}) {
			t.Fatalf("made %d, removed %v, leases ended %d, released %v", len(r.made), r.removed.keys, r.snap.ended, r.h.released())
		}
		if left, _ := filepath.Glob(filepath.Join(r.d.cfg.ReadyDir, "sb-1*")); len(left) != 0 {
			t.Fatalf("ready socket left: %v", left)
		}
	})
	t.Run("the container cannot be made", func(t *testing.T) {
		r := newSplitCreateRig(t)
		r.tr.newContainerFn = func(context.Context, string, ...cntr.NewContainerOpts) (cntr.Container, error) {
			return nil, errors.New("gate refused the call (mount)")
		}
		if err := r.create(t, "sb-1", models.CreateSandboxRequest{}); err == nil {
			t.Fatal("no error")
		}
		if !slices.Equal(r.removed.keys, []string{"sb-1"}) || r.snap.ended != 1 || !slices.Equal(r.h.released(), []string{"sb-1"}) {
			t.Fatalf("removed %v, leases ended %d, released %v", r.removed.keys, r.snap.ended, r.h.released())
		}
	})
	t.Run("the task cannot start", func(t *testing.T) {
		r := newSplitCreateRig(t)
		inner := r.tr.newContainerFn
		r.tr.newContainerFn = func(ctx context.Context, id string, opts ...cntr.NewContainerOpts) (cntr.Container, error) {
			c, err := inner(ctx, id, opts...)
			if err == nil {
				c.(*fakeContainer).newTaskErr = errors.New("runc: no such file")
			}
			return c, err
		}
		if err := r.create(t, "sb-1", models.CreateSandboxRequest{}); err == nil {
			t.Fatal("no error")
		}
		if len(r.removed.keys) != 0 || !slices.Equal(r.h.released(), []string{"sb-1"}) || r.snap.ended != 1 {
			t.Fatalf("removed %v (the container owns it), released %v, leases ended %d", r.removed.keys, r.h.released(), r.snap.ended)
		}
	})
	t.Run("another create's snapshot", func(t *testing.T) {
		r := newSplitCreateRig(t)
		r.snap.err = errdefs.ErrAlreadyExists
		err := r.create(t, "sb-1", models.CreateSandboxRequest{})
		if !errors.Is(err, dockerpkg.ErrSandboxContainerExists) {
			t.Fatalf("err %v", err)
		}
		if len(r.removed.keys) != 0 || len(r.h.prepares) != 0 || len(r.h.released()) != 0 {
			t.Fatalf("removed %v, asked %d, released %v", r.removed.keys, len(r.h.prepares), r.h.released())
		}
	})
	t.Run("no snapshot", func(t *testing.T) {
		r := newSplitCreateRig(t)
		r.snap.err = errors.New("snapshotter is down")
		if err := r.create(t, "sb-1", models.CreateSandboxRequest{}); err == nil || !strings.Contains(err.Error(), "prepare snapshot") {
			t.Fatalf("err %v", err)
		}
		if len(r.h.prepares) != 0 {
			t.Fatal("the helper was asked with no snapshot")
		}
	})
	t.Run("an answer with no user", func(t *testing.T) {
		r := newSplitCreateRig(t)
		r.h.noUser = true
		if err := r.create(t, "sb-1", models.CreateSandboxRequest{}); err == nil || !strings.Contains(err.Error(), "image's user") {
			t.Fatalf("err %v", err)
		}
		if !slices.Equal(r.removed.keys, []string{"sb-1"}) {
			t.Fatalf("removed %v", r.removed.keys)
		}
	})
	t.Run("an image config that is not one", func(t *testing.T) {
		r := newSplitCreateRig(t)
		r.tr.image.(storeImage).configFakeImage.configDesc.MediaType = ocispec.MediaTypeImageManifest
		if err := r.create(t, "sb-1", models.CreateSandboxRequest{}); err == nil || !strings.Contains(err.Error(), "media type") {
			t.Fatalf("err %v", err)
		}
		if len(r.snap.prepared) != 0 {
			t.Fatal("a snapshot was prepared for a bad config")
		}
	})
}

// TestSplitResizeDisk: a split resize sets the disk limit through the
// helper's disk_quota part, alone, by the container; single mode's own
// quota calls are never made.
func TestSplitResizeDisk(t *testing.T) {
	h := newPartsHelper(t)
	q := &recordingQuota{}
	installQuota(t, q)
	tr := newFakeTransport()
	tr.containers["sb-1"] = &fakeContainer{id: "sb-1", snapshotKey: "sb-1", taskErr: errdefs.ErrNotFound}
	tr.containers["sb-odd"] = &fakeContainer{id: "sb-odd", snapshotKey: "other", taskErr: errdefs.ErrNotFound}
	d := newTestDriver(t)
	d.cfg.DiskQuota = true
	d.SetClient(NewTestClient("aerolvm", tr))
	d.SetRootHelper(h)
	if err := d.Resize(context.Background(), "sb-1", models.ResizeSandboxRequest{DiskGB: 7}); err != nil {
		t.Fatal(err)
	}
	if len(h.prepares) != 1 || !slices.Equal(h.prepares[0].GetParts(), []string{rootdpb.PartDiskQuota}) ||
		h.prepares[0].GetDiskQuota().GetBytes() != 7<<30 || h.prepares[0].GetContainerId() != "sb-1" || len(q.calls) != 0 {
		t.Fatalf("asked %v, own quota calls %v", h.prepares, q.calls)
	}
	if err := d.Resize(context.Background(), "sb-odd", models.ResizeSandboxRequest{DiskGB: 7}); err == nil || !strings.Contains(err.Error(), "own key") {
		t.Fatalf("a snapshot under another key: %v", err)
	}
	h.prepareErr = errors.New("refused")
	if err := d.Resize(context.Background(), "sb-1", models.ResizeSandboxRequest{DiskGB: 7}); err == nil || !strings.Contains(err.Error(), "disk limit") {
		t.Fatalf("a refused limit: %v", err)
	}
	d.SetRootHelper(&fakeHelper{})
	if err := d.Resize(context.Background(), "sb-1", models.ResizeSandboxRequest{DiskGB: 7}); err == nil {
		t.Fatal("a resize with no container parts")
	}
}

// splitUserFixture is an image's root with these user files.
func splitUserFixture(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, body := range files {
		p := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		var err error
		if target, ok := strings.CutPrefix(body, "->"); ok {
			err = os.Symlink(target, p)
		} else {
			err = os.WriteFile(p, []byte(body), 0o644)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// fixtureReader is the helper's read of an image's files, from a fixture
// root: what the kernel's read returns for those layers, an absolute link
// resolved inside the root (RESOLVE_IN_ROOT).
func fixtureReader(root string) rootd.ImageFileReader {
	return func(context.Context, string, string, []string) (rootd.UserFiles, error) {
		var f rootd.UserFiles
		for name, uf := range map[string]*rootd.UserFile{"etc/passwd": &f.Passwd, "etc/group": &f.Group} {
			if target, err := os.Readlink(filepath.Join(root, name)); err == nil && filepath.IsAbs(target) {
				name = strings.TrimPrefix(target, "/")
			}
			if b, err := os.ReadFile(filepath.Join(root, name)); err == nil {
				uf.Present, uf.Body = true, b
			}
		}
		return f, nil
	}
}

// oneSnapshot is containerd's snapshot of container sb-1, for the helper.
type oneSnapshot struct{}

func (oneSnapshot) Stat(context.Context, string) (rootd.SnapshotInfo, error) {
	return rootd.SnapshotInfo{Kind: "active", Parent: "sha256:p"}, nil
}

func (oneSnapshot) Mounts(context.Context, string) ([]rootpolicy.Mount, error) {
	const snaps = "/var/lib/containerd/snap/snapshots"
	return []rootpolicy.Mount{{Type: "overlay", Source: "overlay", Options: []string{
		"workdir=" + snaps + "/3/work", "upperdir=" + snaps + "/3/fs", "lowerdir=" + snaps + "/2/fs:" + snaps + "/1/fs"}}}, nil
}

// TestSplitImageConfigMatchesContainerd: for every USER form and image
// layout, a split create's process (the image's env, command, working
// folder, and the user the real helper resolved from the image's files)
// is what containerd's own oci.WithImageConfig makes of the same image in
// single mode, field for field, and the same images fail.
func TestSplitImageConfigMatchesContainerd(t *testing.T) {
	passwd := "root:x:0:0:root:/root:/bin/sh\napp:x:1000:1000::/home/app:/bin/sh\nsvc:x:999:999::/:/sbin/nologin\n"
	group := "root:x:0:\napp:x:1000:\nwheel:x:10:app,svc\nsvc:x:999:\n"
	layouts := map[string]map[string]string{
		"passwd and group":  {"etc/passwd": passwd, "etc/group": group},
		"no group":          {"etc/passwd": passwd},
		"no etc":            {"bin/sh": "x"},
		"passwd is a link":  {"etc/passwd": "->/usr/lib/passwd", "usr/lib/passwd": passwd, "etc/group": group},
		"an empty passwd":   {"etc/passwd": "", "etc/group": group},
		"a duplicated user": {"etc/passwd": passwd + "app:x:2000:2000::/:/bin/sh\n", "etc/group": group},
	}
	users := []string{"", "app", "1000", "svc", "app:wheel", "1000:10", "4242", "4242:4242", "nobody", "app:nogroup", "a:b:c"}
	envs := [][]string{nil, {"FOO=1", "PATH=/opt/bin"}}
	for name, files := range layouts {
		root := splitUserFixture(t, files)
		client := startHelperWith(t, func(_ *rootd.Config, o *rootd.Options) {
			o.Snapshots, o.ReadImageFiles = oneSnapshot{}, fixtureReader(root)
		})
		for _, user := range users {
			for _, env := range envs {
				cfg := ocispec.ImageConfig{User: user, Env: env, Entrypoint: []string{"/e"}, Cmd: []string{"c"}, WorkingDir: map[bool]string{true: "/srv"}[env != nil]}
				_, img := newConfigImage(t, cfg)
				base := func(path string) *oci.Spec {
					return &oci.Spec{Process: &specs.Process{Env: []string{"SB_X=1", "PATH=/spec"}}, Linux: &specs.Linux{}, Root: &specs.Root{Path: path}}
				}
				single := base(root)
				singleErr := oci.WithImageConfig(img)(context.Background(), nil, &containers.Container{}, single)
				resp, splitErr := client.PrepareSandbox(context.Background(), &rootdpb.PrepareSandboxRequest{Parts: []string{rootdpb.PartImageUser},
					ContainerId: "sb-1", ImageUser: &rootdpb.ImageUser{User: user}})
				split := base("rootfs")
				if splitErr == nil {
					splitErr = withImageConfigAnswer(ocispec.Image{Config: cfg}, resp.GetImageUser())(context.Background(), nil, &containers.Container{}, split)
				}
				if (singleErr == nil) != (splitErr == nil) {
					t.Fatalf("%s, USER %q: single %v, split %v", name, user, singleErr, splitErr)
				}
				if singleErr != nil {
					continue
				}
				a, b := single.Process, split.Process
				if !slices.Equal(a.Env, b.Env) || !slices.Equal(a.Args, b.Args) || a.Cwd != b.Cwd || a.User.UID != b.User.UID ||
					a.User.GID != b.User.GID || !slices.Equal(a.User.AdditionalGids, b.User.AdditionalGids) {
					t.Fatalf("%s, USER %q, env %v:\nsingle %+v\nsplit  %+v", name, user, env, a, b)
				}
			}
		}
	}
}

// startHelperWith is startHelper with the helper's config and options
// changed: a toolbox and an image folder, and what the test gives it.
func startHelperWith(t *testing.T, mutate func(*rootd.Config, *rootd.Options)) *rootclient.Client {
	t.Helper()
	dir, err := os.MkdirTemp("", "dh")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if dir, err = filepath.EvalSymlinks(dir); err != nil {
		t.Fatal(err)
	}
	files := rootd.FileDirs{
		Hosts: filepath.Join(dir, "state", "hosts"), Ready: filepath.Join(dir, "run", "ready"),
		Runsc: filepath.Join(dir, "state", "runsc"), AgentReady: filepath.Join(dir, "agent", "ready"),
		Toolbox: filepath.Join(dir, "opt", "toolboxd"), ImageRoot: filepath.Join(dir, "state", "imageroot"),
	}
	cfg := rootd.Config{
		Socket: filepath.Join(dir, "sock", "root.sock"), SocketGID: os.Getgid(), AgentUID: uint32(os.Getuid()), Files: files,
		Policy: rootpolicy.Policy{
			Namespace: "aerolvm", Snapshotter: "overlayfs", SnapshotterRoot: "/var/lib/containerd/snap",
			NetnsDir: "/run/netns", MovesDir: filepath.Join(dir, "state", "moves"), FIFODir: filepath.Join(dir, "run", "fifo"),
			BindFiles:        []string{files.Toolbox},
			HelperFileRoots:  []string{files.Hosts, files.Ready},
			RunscConfigPaths: []string{filepath.Join(files.Runsc, "config.toml"), filepath.Join(files.Runsc, "restore.toml")},
			Limits:           rootpolicy.Limits{MemoryBytes: 1 << 30, Pids: 4096, CPUs: 2},
		},
	}
	opts := rootd.Options{
		Containerd: func(any, grpc.ServerStream) error { return nil },
		Peer:       egress.UnixPeerCheck([]uint32{uint32(os.Getuid())}, ""),
	}
	if mutate != nil {
		mutate(&cfg, &opts)
	}
	srv, err := rootd.New(cfg, opts, nil)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve() }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 1e9)
		defer cancel()
		srv.Shutdown(ctx)
	})
	c := rootclient.New(rootclient.Config{Socket: cfg.Socket, HelperUID: uint32(os.Getuid())})
	t.Cleanup(func() { _ = c.Close() })
	return c
}
