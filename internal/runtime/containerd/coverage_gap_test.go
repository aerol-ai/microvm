package containerd

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	cntr "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/leases"
	"github.com/containerd/errdefs"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/aerol-ai/microvm/internal/pool/containerdpool"
	dockerpkg "github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/docker/netrules"
	"github.com/aerol-ai/microvm/pkg/models"
)

func TestLoadContainerForRefBySandboxLabel(t *testing.T) {
	tr := newFakeTransport()
	tr.containers["park-abc"] = &fakeContainer{
		id:     "park-abc",
		labels: map[string]string{sandboxIDLabelKey: "sb-warm"},
	}
	d := newTestDriver(t)
	d.SetClient(NewTestClient("aerolvm", tr))
	c, err := d.loadContainerForRef(context.Background(), d.client, "sb-warm")
	if err != nil || c.ID() != "park-abc" {
		t.Fatalf("c=%v err=%v", c, err)
	}
}

func TestLoadContainerForRefDirect(t *testing.T) {
	tr := newFakeTransport()
	tr.containers["sb-1"] = &fakeContainer{id: "sb-1"}
	d := newTestDriver(t)
	d.SetClient(NewTestClient("aerolvm", tr))
	c, err := d.loadContainerForRef(context.Background(), d.client, "sb-1")
	if err != nil || c.ID() != "sb-1" {
		t.Fatalf("c=%v err=%v", c, err)
	}
}

func TestLoadContainerForRefNotFound(t *testing.T) {
	d := newTestDriver(t)
	_, err := d.loadContainerForRef(context.Background(), d.client, "ghost")
	if !errors.Is(err, errdefs.ErrNotFound) {
		t.Fatalf("err=%v", err)
	}
}

func TestSandboxIDFromContainerLabel(t *testing.T) {
	d := newTestDriver(t)
	c := &fakeContainer{id: "park-x", labels: map[string]string{sandboxIDLabelKey: "sb-real"}}
	if got := d.sandboxIDFromContainer(context.Background(), c); got != "sb-real" {
		t.Fatalf("got %q", got)
	}
}

func TestInspectUsesSandboxLabel(t *testing.T) {
	stubToolboxProbe(t)
	tr := newFakeTransport()
	tr.containers["park-x"] = &fakeContainer{
		id:     "park-x",
		task:   &fakeTask{status: cntr.Running},
		labels: map[string]string{sandboxIDLabelKey: "sb-labeled"},
	}
	d := newTestDriver(t)
	d.SetClient(NewTestClient("aerolvm", tr))
	state, err := d.Inspect(context.Background(), "park-x")
	if err != nil || state.SandboxID != "sb-labeled" {
		t.Fatalf("state=%+v err=%v", state, err)
	}
}

func TestListManagedSkipsParkInventory(t *testing.T) {
	stubToolboxProbe(t)
	tr := newFakeTransport()
	tr.containers["park-1"] = &fakeContainer{
		id:     "park-1",
		labels: map[string]string{poolParkLabelKey: poolParkLabelValue, managedLabelKey: "true"},
		task:   &fakeTask{status: cntr.Running},
	}
	tr.containers["sb-live"] = &fakeContainer{
		id:     "sb-live",
		task:   &fakeTask{status: cntr.Running},
		labels: map[string]string{sandboxIDLabelKey: "sb-live"},
	}
	d := newTestDriver(t)
	d.SetClient(NewTestClient("aerolvm", tr))
	managed, err := d.ListManaged(context.Background())
	if err != nil || len(managed) != 1 || managed["sb-live"] == nil {
		t.Fatalf("managed=%v err=%v", managed, err)
	}
}

func TestPurgeParkedContainers(t *testing.T) {
	stubToolboxProbe(t)
	tr := newFakeTransport()
	tr.containers["park-1"] = &fakeContainer{
		id:     "park-1",
		task:   &fakeTask{status: cntr.Running},
		labels: map[string]string{poolParkLabelKey: poolParkLabelValue},
	}
	d := newTestDriver(t)
	d.SetClient(NewTestClient("aerolvm", tr))
	n, err := d.PurgeParkedContainers(context.Background())
	if err != nil || n != 1 {
		t.Fatalf("purged=%d err=%v", n, err)
	}
}

func TestParkContainerRequiresReadySocket(t *testing.T) {
	d := newTestDriver(t)
	d.cfg.ReadyEnabled = false
	_, err := d.parkContainer(context.Background(), "park-1", containerdpoolKey())
	if err == nil || !strings.Contains(err.Error(), "ready socket") {
		t.Fatalf("err=%v", err)
	}
}

func TestParkContainerInvalidSlotID(t *testing.T) {
	d := newTestDriver(t)
	d.cfg.ReadyEnabled = true
	_, err := d.parkContainer(context.Background(), "../evil", containerdpoolKey())
	if err == nil {
		t.Fatal("want validation error")
	}
}

func TestPoolSpawnerNilSafe(t *testing.T) {
	var sp *PoolSpawner
	if _, err := sp.Park(context.Background(), "park-1", containerdpoolKey()); err == nil {
		t.Fatal("want error")
	}
	if err := sp.DestroyParked(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
}

func TestPoolSpawnerDelegates(t *testing.T) {
	d := newTestDriver(t)
	d.cfg.ReadyEnabled = false
	sp := &PoolSpawner{Driver: d}
	if _, err := sp.Park(context.Background(), "park-1", containerdpoolKey()); err == nil {
		t.Fatal("want ready socket error")
	}
	if err := sp.DestroyParked(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
}

func TestApplyAdoptNetworkPolicyBranches(t *testing.T) {
	be := &netrulesMemBackend{}
	d := New(Config{}, netrules.NewWithBackend(be), nil)
	ip := "10.88.0.42"
	if err := d.applyAdoptNetworkPolicy(ip, models.CreateSandboxRequest{NetworkBlockAll: true}); err != nil {
		t.Fatal(err)
	}
	if err := d.applyAdoptNetworkPolicy(ip, models.CreateSandboxRequest{
		NetworkAllowOut: []string{"0.0.0.0/0"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := d.applyAdoptNetworkPolicy(ip, models.CreateSandboxRequest{}); err != nil {
		t.Fatal(err)
	}
}

func TestAssertSandboxNotExistsDuplicate(t *testing.T) {
	tr := newFakeTransport()
	tr.containers["sb-dup"] = &fakeContainer{id: "sb-dup", labels: map[string]string{managedLabelKey: "true"}}
	d := newTestDriver(t)
	d.SetClient(NewTestClient("aerolvm", tr))
	err := d.assertSandboxNotExists(context.Background(), d.client, "sb-dup", "park-other")
	if !errors.Is(err, dockerpkg.ErrSandboxContainerExists) {
		t.Fatalf("err=%v", err)
	}
}

func TestAssertSandboxNotExistsParkedNameOK(t *testing.T) {
	tr := newFakeTransport()
	// Fake ListContainers ignores filters, so the adopt container ID must
	// match the parked object ID when we allow the parked name collision.
	tr.containers["sb-dup"] = &fakeContainer{
		id:     "sb-dup",
		labels: map[string]string{poolParkLabelKey: poolParkLabelValue},
	}
	d := newTestDriver(t)
	d.SetClient(NewTestClient("aerolvm", tr))
	if err := d.assertSandboxNotExists(context.Background(), d.client, "sb-dup", "sb-dup"); err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeContainerOptDocker(t *testing.T) {
	d := newTestDriver(t)
	opt, err := d.runtimeContainerOpt(models.RuntimeDocker)
	if err != nil || opt == nil {
		t.Fatalf("opt=%v err=%v", opt, err)
	}
}

func TestRuntimeContainerOptEmpty(t *testing.T) {
	d := newTestDriver(t)
	opt, err := d.runtimeContainerOpt("")
	if err != nil || opt != nil {
		t.Fatalf("opt=%v err=%v", opt, err)
	}
}

func TestReleaseImageLeaseNoOp(t *testing.T) {
	d := newTestDriver(t)
	d.releaseImageLease(context.Background(), d.client, map[string]string{imageLeaseLabelKey: "lease-1"})
	d.releaseImageLease(context.Background(), nil, nil)
	d.releaseImageLease(context.Background(), d.client, map[string]string{})
}

func TestRandomLeaseID(t *testing.T) {
	id, err := randomLeaseID("aerolvm-img-")
	if err != nil || !strings.HasPrefix(id, "aerolvm-img-") || len(id) < 20 {
		t.Fatalf("id=%q err=%v", id, err)
	}
}

func TestDestroyParkedClearsNetworkRules(t *testing.T) {
	be := &netrulesMemBackend{}
	d := New(Config{}, netrules.NewWithBackend(be), nil)
	tr := newFakeTransport()
	tr.containers["park-1"] = &fakeContainer{id: "park-1", task: &fakeTask{status: cntr.Running}}
	d.SetClient(NewTestClient("aerolvm", tr))
	if err := d.destroyParked(context.Background(), &containerdpool.ParkedSlot{
		ContainerID: "park-1",
		ContainerIP: "10.88.0.9",
	}); err != nil {
		t.Fatal(err)
	}
}

func TestDestroyParkedNil(t *testing.T) {
	d := newTestDriver(t)
	if err := d.destroyParked(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
}

func TestFindContainerBySandboxIDMiss(t *testing.T) {
	d := newTestDriver(t)
	c, err := d.findContainerBySandboxID(context.Background(), d.client, "missing")
	if err != nil || c != nil {
		t.Fatalf("c=%v err=%v", c, err)
	}
}

func TestImageDigestStringAndID(t *testing.T) {
	if _, err := imageDigestString(nil); err == nil {
		t.Fatal("want nil image error")
	}
	img := &fakeImage{name: "alpine:3.20"}
	got, err := imageDigestString(img)
	if err != nil || got != "alpine:3.20" {
		t.Fatalf("got=%q err=%v", got, err)
	}
	img.target = ocispec.Descriptor{Digest: digest.Digest("sha256:" + strings.Repeat("a", 64))}
	got, err = imageDigestString(img)
	if err != nil || !strings.HasPrefix(got, "sha256:") {
		t.Fatalf("got=%q err=%v", got, err)
	}
	if id := imageDigestID(img.target); id == "" {
		t.Fatal("empty digest id")
	}
}

func TestParkDefaultCreateRequest(t *testing.T) {
	req := parkDefaultCreateRequest()
	if req.CPU != models.DefaultCPU || req.MemoryMB != models.DefaultMemoryMB {
		t.Fatalf("req=%+v", req)
	}
}

func TestMintBootstrapToken(t *testing.T) {
	tok, err := mintBootstrapToken()
	if err != nil || len(tok) < 32 {
		t.Fatalf("tok=%q err=%v", tok, err)
	}
}

func TestIsParkedHelpers(t *testing.T) {
	if !IsParkedSandboxID("park-abc") || IsParkedSandboxID("sb-1") {
		t.Fatal("IsParkedSandboxID")
	}
	if !IsParkedContainerLabels(map[string]string{poolParkLabelKey: poolParkLabelValue}) {
		t.Fatal("IsParkedContainerLabels")
	}
}

func TestPublishEngineTag(t *testing.T) {
	PublishEngineTag(models.ContainerEngineContainerd)
	if got := containerEngineExpvar.Value(); got != models.ContainerEngineContainerd {
		t.Fatalf("got %q", got)
	}
	PublishEngineTag("")
	if got := containerEngineExpvar.Value(); got != "docker" {
		t.Fatalf("got %q", got)
	}
}

type fakeLeaseManager struct {
	created   []string
	deleted   []string
	added     []leases.Resource
	createErr error
	addErr    error
}

func (f *fakeLeaseManager) Create(_ context.Context, opts ...leases.Opt) (leases.Lease, error) {
	if f.createErr != nil {
		return leases.Lease{}, f.createErr
	}
	l := leases.Lease{ID: "lease-test"}
	for _, opt := range opts {
		_ = opt(&l)
	}
	f.created = append(f.created, l.ID)
	return l, nil
}

func (f *fakeLeaseManager) Delete(_ context.Context, lease leases.Lease, _ ...leases.DeleteOpt) error {
	f.deleted = append(f.deleted, lease.ID)
	return nil
}

func (f *fakeLeaseManager) AddResource(_ context.Context, _ leases.Lease, resource leases.Resource) error {
	if f.addErr != nil {
		return f.addErr
	}
	f.added = append(f.added, resource)
	return nil
}

func TestPinAndReleaseImageLeaseFake(t *testing.T) {
	lm := &fakeLeaseManager{}
	orig := leasesServiceFn
	leasesServiceFn = func(*Client) leaseManager { return lm }
	t.Cleanup(func() { leasesServiceFn = orig })

	d := newTestDriver(t)
	img := &fakeImage{
		name:   "alpine:3.20",
		target: ocispec.Descriptor{Digest: digest.Digest("sha256:" + strings.Repeat("b", 64))},
	}
	id, err := d.pinImageLease(context.Background(), d.client, img)
	if err != nil || id == "" {
		t.Fatalf("id=%q err=%v", id, err)
	}
	if len(lm.added) != 1 || lm.added[0].Type != leaseContentType {
		t.Fatalf("added=%v", lm.added)
	}
	d.releaseImageLease(context.Background(), d.client, map[string]string{imageLeaseLabelKey: id})
	if len(lm.deleted) != 1 {
		t.Fatalf("deleted=%v", lm.deleted)
	}
}

func TestPinImageLeaseNoDigest(t *testing.T) {
	lm := &fakeLeaseManager{}
	orig := leasesServiceFn
	leasesServiceFn = func(*Client) leaseManager { return lm }
	t.Cleanup(func() { leasesServiceFn = orig })

	d := newTestDriver(t)
	_, err := d.pinImageLease(context.Background(), d.client, &fakeImage{name: "alpine:3.20"})
	if err == nil || !strings.Contains(err.Error(), "digest") {
		t.Fatalf("err=%v", err)
	}
	if len(lm.deleted) != 1 {
		t.Fatalf("lease should be deleted on digest failure: %v", lm.deleted)
	}
}

func shortReadyDir(t *testing.T) string {
	t.Helper()
	// macOS sun_path is 104 bytes; /tmp/r* keeps room for sandboxID.nonce.sock.
	dir, err := os.MkdirTemp("/tmp", "r")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func TestParkContainerSuccessFake(t *testing.T) {
	stubToolboxProbe(t)
	origWait := parkReadyWaitFn
	parkReadyWaitFn = func(context.Context, *dockerpkg.ParkedListener) error { return nil }
	t.Cleanup(func() { parkReadyWaitFn = origWait })

	provider, img := newTestImageProvider(t)
	tr := newFakeTransport()
	tr.provider = provider
	tr.image = img

	tmp := t.TempDir()
	toolbox := filepath.Join(tmp, "toolboxd")
	if err := os.WriteFile(toolbox, []byte{0}, 0o755); err != nil {
		t.Fatal(err)
	}
	be := &netrulesMemBackend{}
	d := New(Config{
		ToolboxBinaryPath:  toolbox,
		ToolboxMountPath:   "/.aerol/toolboxd",
		ToolboxPort:        2280,
		ToolboxWaitTimeout: 2 * time.Second,
		LogDir:             filepath.Join(tmp, "logs"),
		RunDir:             filepath.Join(tmp, "run"),
		ReadyEnabled:       true,
		ReadyDir:           shortReadyDir(t),
		NativeNetnsPool:    true,
	}, netrules.NewWithBackend(be), nil)
	d.SetClient(NewTestClient("aerolvm", tr))
	d.SetNetnsHandoff(&harnessNetns{path: "/run/netns/park", ip: "10.88.0.77"})

	slot, err := d.parkContainer(context.Background(), "park-ok1", containerdpool.Key{
		Image:   "cfg:test",
		Runtime: models.RuntimeDocker,
	})
	if err != nil {
		t.Fatal(err)
	}
	if slot == nil || slot.ContainerID != "park-ok1" || slot.ContainerIP != "10.88.0.77" {
		t.Fatalf("slot=%+v", slot)
	}
	if err := d.destroyParked(context.Background(), slot); err != nil {
		t.Fatal(err)
	}
}

func TestParkContainerRunscSuccessFake(t *testing.T) {
	stubToolboxProbe(t)
	origWait := parkReadyWaitFn
	parkReadyWaitFn = func(context.Context, *dockerpkg.ParkedListener) error { return nil }
	t.Cleanup(func() { parkReadyWaitFn = origWait })

	provider, img := newTestImageProvider(t)
	tr := newFakeTransport()
	tr.provider = provider
	tr.image = img

	tmp := t.TempDir()
	toolbox := filepath.Join(tmp, "toolboxd")
	if err := os.WriteFile(toolbox, []byte{0}, 0o755); err != nil {
		t.Fatal(err)
	}
	d := New(Config{
		ToolboxBinaryPath:  toolbox,
		ToolboxMountPath:   "/.aerol/toolboxd",
		ToolboxPort:        2280,
		ToolboxWaitTimeout: 2 * time.Second,
		LogDir:             filepath.Join(tmp, "logs"),
		RunDir:             filepath.Join(tmp, "run"),
		ReadyEnabled:       true,
		ReadyDir:           shortReadyDir(t),
		NativeNetnsPool:    true,
	}, nil, nil)
	d.SetClient(NewTestClient("aerolvm", tr))
	d.SetNetnsHandoff(&harnessNetns{path: "/run/netns/park-g", ip: "10.88.0.78"})

	slot, err := d.parkContainer(context.Background(), "park-gv1", containerdpool.Key{
		Image:   "cfg:test",
		Runtime: models.RuntimeGvisor,
	})
	if err != nil {
		t.Fatal(err)
	}
	if slot.Key.Runtime != models.RuntimeGvisor {
		t.Fatalf("runtime=%q", slot.Key.Runtime)
	}
}

func TestClientContentStoreAndProvider(t *testing.T) {
	tr := newFakeTransport()
	provider, _ := newTestImageProvider(t)
	tr.provider = provider
	c := NewTestClient("aerolvm", tr)
	if c.ContentStore() == nil && c.contentProvider() == nil {
		t.Fatal("want provider")
	}
	if c.contentProvider() == nil {
		t.Fatal("contentProvider")
	}
	// memProvider may not implement content.Store — ContentStore can be nil.
	_ = c.ContentStore()
}

func TestParkContainerImagePullError(t *testing.T) {
	origWait := parkReadyWaitFn
	parkReadyWaitFn = func(context.Context, *dockerpkg.ParkedListener) error { return nil }
	t.Cleanup(func() { parkReadyWaitFn = origWait })

	tr := newFakeTransport()
	tr.getImageFn = func(context.Context, string) (cntr.Image, error) {
		return nil, errors.New("missing")
	}
	tr.pullImageFn = func(context.Context, string, ...cntr.RemoteOpt) (cntr.Image, error) {
		return nil, errors.New("pull failed")
	}
	tmp := t.TempDir()
	toolbox := filepath.Join(tmp, "toolboxd")
	_ = os.WriteFile(toolbox, []byte{0}, 0o755)
	d := New(Config{
		ToolboxBinaryPath:  toolbox,
		ToolboxMountPath:   "/.aerol/toolboxd",
		ToolboxPort:        2280,
		ToolboxWaitTimeout: time.Second,
		LogDir:             filepath.Join(tmp, "logs"),
		RunDir:             filepath.Join(tmp, "run"),
		ReadyEnabled:       true,
		ReadyDir:           shortReadyDir(t),
	}, nil, nil)
	d.SetClient(NewTestClient("aerolvm", tr))
	_, err := d.parkContainer(context.Background(), "park-fail", containerdpool.Key{Image: "missing:latest"})
	if err == nil || !strings.Contains(err.Error(), "park image") {
		t.Fatalf("err=%v", err)
	}
}

func TestParkContainerReadyWaitError(t *testing.T) {
	stubToolboxProbe(t)
	origWait := parkReadyWaitFn
	parkReadyWaitFn = func(context.Context, *dockerpkg.ParkedListener) error {
		return errors.New("ready timeout")
	}
	t.Cleanup(func() { parkReadyWaitFn = origWait })

	provider, img := newTestImageProvider(t)
	tr := newFakeTransport()
	tr.provider = provider
	tr.image = img
	tmp := t.TempDir()
	toolbox := filepath.Join(tmp, "toolboxd")
	_ = os.WriteFile(toolbox, []byte{0}, 0o755)
	d := New(Config{
		ToolboxBinaryPath:  toolbox,
		ToolboxMountPath:   "/.aerol/toolboxd",
		ToolboxPort:        2280,
		ToolboxWaitTimeout: time.Second,
		LogDir:             filepath.Join(tmp, "logs"),
		RunDir:             filepath.Join(tmp, "run"),
		ReadyEnabled:       true,
		ReadyDir:           shortReadyDir(t),
		NativeNetnsPool:    true,
	}, nil, nil)
	d.SetClient(NewTestClient("aerolvm", tr))
	d.SetNetnsHandoff(&harnessNetns{path: "/run/netns/x", ip: "10.88.0.1"})
	_, err := d.parkContainer(context.Background(), "park-rdy", containerdpool.Key{Image: "cfg:test"})
	if err == nil || !strings.Contains(err.Error(), "park ready") {
		t.Fatalf("err=%v", err)
	}
}

func containerdpoolKey() containerdpool.Key {
	return containerdpool.Key{Image: "alpine:3.20", Runtime: models.RuntimeDocker}
}
