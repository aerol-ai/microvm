package service

import (
	"context"
	"errors"
	"maps"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
)

// snapHomeStub captures the snapshot-home index writes the service makes.
type snapHomeStub struct {
	*cluster.Noop
	registered map[string]string
	forgotten  []string
}

func (c *snapHomeStub) RegisterSnapshotNode(_ context.Context, name, node string) error {
	c.registered[name] = node
	return nil
}
func (c *snapHomeStub) ForgetSnapshotNode(_ context.Context, name string) error {
	c.forgotten = append(c.forgotten, name)
	return nil
}

// Creating a snapshot registers this node as its home; deleting it forgets the
// entry — so a snapshot-by-id GET/DELETE can be routed to the holding node (B6).
func TestSnapshotCreateRegistersAndDeleteForgetsHome(t *testing.T) {
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	stub := &snapHomeStub{Noop: cluster.NewNoop("node-1", "", ""), registered: map[string]string{}}
	svc.AttachCluster(stub)
	ctx := context.Background()

	// RegisterSnapshot (name == image: no chain resolution, no sandbox needed).
	if _, err := svc.RegisterSnapshot(ctx, &models.SandboxSnapshot{Name: "img:reg", Image: "img:reg"}); err != nil {
		t.Fatalf("RegisterSnapshot: %v", err)
	}
	if got := stub.registered["img:reg"]; got != "node-1" {
		t.Fatalf("home registered = %q, want node-1", got)
	}

	if err := svc.DeleteSnapshot(ctx, "img:reg"); err != nil {
		t.Fatalf("DeleteSnapshot: %v", err)
	}
	if !slices.Contains(stub.forgotten, "img:reg") {
		t.Fatalf("home not forgotten on delete: %v", stub.forgotten)
	}
}

// A node with no self id (not yet joined) skips the register, and an index
// write that errors is logged, not fatal — the snapshot create/delete still
// succeeds.
func TestSnapshotHomeBestEffort(t *testing.T) {
	// Empty self id → register is skipped (the node is not placeable yet).
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	noSelf := &emptySelfSnapStub{Noop: cluster.NewNoop("node-1", "", "")}
	svc.AttachCluster(noSelf)
	if _, err := svc.RegisterSnapshot(context.Background(), &models.SandboxSnapshot{Name: "img:a", Image: "img:a"}); err != nil {
		t.Fatalf("RegisterSnapshot: %v", err)
	}
	if noSelf.registerCalls != 0 {
		t.Fatalf("registered %d times with an empty self id, want 0", noSelf.registerCalls)
	}

	// An erroring index write must not fail the create or the delete.
	svc2, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	errStub := &errSnapHomeStub{Noop: cluster.NewNoop("node-1", "", "")}
	svc2.AttachCluster(errStub)
	if _, err := svc2.RegisterSnapshot(context.Background(), &models.SandboxSnapshot{Name: "img:b", Image: "img:b"}); err != nil {
		t.Fatalf("RegisterSnapshot with an erroring index: %v", err)
	}
	if err := svc2.DeleteSnapshot(context.Background(), "img:b"); err != nil {
		t.Fatalf("DeleteSnapshot with an erroring index: %v", err)
	}
}

type emptySelfSnapStub struct {
	*cluster.Noop
	registerCalls int
}

func (c *emptySelfSnapStub) SelfNodeID() string { return "" }
func (c *emptySelfSnapStub) RegisterSnapshotNode(context.Context, string, string) error {
	c.registerCalls++
	return nil
}

type errSnapHomeStub struct{ *cluster.Noop }

func (c *errSnapHomeStub) RegisterSnapshotNode(context.Context, string, string) error {
	return errors.New("register boom")
}
func (c *errSnapHomeStub) ForgetSnapshotNode(context.Context, string) error {
	return errors.New("forget boom")
}

// A committed snapshot's home is also keyed by its committed tag, so a create
// that names the tag (the SDK hands callers snap.Image) can be routed to this
// node from any other, and, while its image is only here, by the local-only
// key, so a create by its name is too; deleting the snapshot forgets all
// three. A snapshot registered over some other image owns no tag and gets only
// its name key.
func TestSnapshotHomeKeysIncludeCommittedTag(t *testing.T) {
	for _, tc := range []struct {
		name  string
		owner string
		ctx   context.Context
	}{
		{name: "snap-op", owner: "", ctx: context.Background()},
		{name: "snap-tenant", owner: "tenant-a", ctx: ownerScopedCtx("tenant-a")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt := &recordingRuntime{}
			svc, st, _ := newServiceRuntimeHarness(t, rt)
			svc.docker = resizeSnapRuntime{rt}
			stub := &snapHomeStub{Noop: cluster.NewNoop("node-1", "", ""), registered: map[string]string{}}
			svc.AttachCluster(stub)
			now := time.Now().UTC()
			if err := st.Create(context.Background(), &models.Sandbox{
				ID: "sb-src", Image: "alpine:3.20", Status: models.SandboxStatusStarted, Runtime: models.RuntimeDocker,
				ContainerID: "ctr-sb-src", OwnerRef: tc.owner, CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
			}); err != nil {
				t.Fatalf("seed sandbox: %v", err)
			}

			snap, _, err := svc.CreateSnapshotWithOwnership(tc.ctx, "sb-src", models.CreateSandboxSnapshotRequest{Name: tc.name})
			if err != nil {
				t.Fatalf("CreateSnapshotWithOwnership: %v", err)
			}
			nameKey := cluster.SnapshotHomeKey(tc.owner, tc.name)
			tagKey := docker.SnapshotImageTagForOwner(tc.owner, tc.name)
			if snap.Image != tagKey {
				t.Fatalf("committed image = %q, want %q", snap.Image, tagKey)
			}
			localKey := cluster.SnapshotLocalOnlyKey(tc.owner, tc.name)
			want := map[string]string{nameKey: "node-1", tagKey: "node-1", localKey: "node-1"}
			if !maps.Equal(stub.registered, want) {
				t.Fatalf("registered = %q, want %q", stub.registered, want)
			}

			if err := svc.DeleteSnapshot(tc.ctx, tc.name); err != nil {
				t.Fatalf("DeleteSnapshot: %v", err)
			}
			slices.Sort(stub.forgotten)
			wantForgotten := []string{nameKey, tagKey, localKey}
			slices.Sort(wantForgotten)
			if !slices.Equal(stub.forgotten, wantForgotten) {
				t.Fatalf("forgotten = %q, want %q", stub.forgotten, wantForgotten)
			}
		})
	}

	t.Run("registered_over_another_image_has_no_tag_key", func(t *testing.T) {
		svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
		stub := &snapHomeStub{Noop: cluster.NewNoop("node-1", "", ""), registered: map[string]string{}}
		svc.AttachCluster(stub)
		if _, err := svc.RegisterSnapshot(context.Background(), &models.SandboxSnapshot{Name: "img:reg", Image: "img:reg"}); err != nil {
			t.Fatalf("RegisterSnapshot: %v", err)
		}
		if want := map[string]string{"img:reg": "node-1"}; !maps.Equal(stub.registered, want) {
			t.Fatalf("registered = %q, want only the name key %q", stub.registered, want)
		}
	})
}

// The cluster create router asks whether this node holds a snapshot's
// committed tag before it consults the cluster index. It answers for the node
// (any owner's committed row counts, every spelling of the tag counts) and
// says no for anything that is not a committed snapshot tag here.
func TestHoldsCommittedSnapshotImage(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarnessAllowStoreClose(t, &recordingRuntime{})
	tag := docker.SnapshotImageTagForOwner("tenant-a", "demo")
	if err := st.CreateSnapshot(ctx, &models.SandboxSnapshot{
		Name: "demo", Image: tag, SourceSandboxID: "sb-src", OwnerRef: "tenant-a", CreatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}
	if err := st.CreateSnapshot(ctx, &models.SandboxSnapshot{
		Name: "alias", Image: docker.SnapshotImageTagForOwner("", "elsewhere"), CreatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("CreateSnapshot alias: %v", err)
	}
	for _, tc := range []struct {
		image string
		want  bool
	}{
		{image: tag, want: true},
		{image: "docker.io/" + tag, want: true},
		{image: strings.TrimSuffix(tag, ":latest"), want: true},
		// An alias row naming a tag does not own it: the tag's snapshot is
		// committed elsewhere.
		{image: docker.SnapshotImageTagForOwner("", "elsewhere"), want: false},
		{image: docker.SnapshotImageTagForOwner("tenant-b", "demo"), want: false},
		{image: "demo", want: false},
		{image: "alpine:3.20", want: false},
	} {
		got, err := svc.HoldsCommittedSnapshotImage(ctx, tc.image)
		if err != nil || got != tc.want {
			t.Errorf("HoldsCommittedSnapshotImage(%q) = %v,%v, want %v,nil", tc.image, got, err, tc.want)
		}
	}

	// No catalogue (a service without a store) holds nothing.
	var nilSvc *Service
	if got, err := nilSvc.HoldsCommittedSnapshotImage(ctx, tag); got || err != nil {
		t.Fatalf("nil service = %v,%v, want false,nil", got, err)
	}

	// A catalogue that cannot be read is an error, never "held".
	if err := st.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}
	if got, err := svc.HoldsCommittedSnapshotImage(ctx, tag); got || err == nil {
		t.Fatalf("closed store = %v,%v, want false and an error", got, err)
	}
}

// The local-only key lives exactly while the snapshot's image is only on this
// node. A landed push drops it, so creates by the snapshot's name spread over
// the registry copy again; a failed push keeps it, so those creates keep
// running here, where the snapshot still works. A node with no cluster has no
// key to drop.
func TestSnapshotPushLandingForgetsLocalOnlyKey(t *testing.T) {
	for _, tc := range []struct {
		name       string
		owner      string
		pushErr    error
		wantForget bool
	}{
		{name: "operator_push_lands", wantForget: true},
		{name: "tenant_push_lands", owner: "tenant-a", wantForget: true},
		{name: "push_fails", pushErr: errors.New("registry 500")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
			stub := &snapHomeStub{Noop: cluster.NewNoop("node-1", "", ""), registered: map[string]string{}}
			svc.AttachCluster(stub)
			ps := newFakePushStore()
			row := pendingLocal("snap")
			row.OwnerRef = tc.owner
			ps.seed(row)
			rec := newTestReconciler(t, ps, &fakeSnapshotPushDocker{digest: "sha256:pushed", err: tc.pushErr})
			svc.AttachSnapshotPusher(rec.pusher, rec)

			if _, err := rec.RunOnce(context.Background()); err != nil {
				t.Fatalf("RunOnce: %v", err)
			}
			key := cluster.SnapshotLocalOnlyKey(tc.owner, "snap")
			if got := slices.Contains(stub.forgotten, key); got != tc.wantForget {
				t.Fatalf("forgot %q = %v (forgotten %q), want %v", key, got, stub.forgotten, tc.wantForget)
			}
		})
	}

	t.Run("no_cluster_is_a_no_op", func(t *testing.T) {
		svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
		svc.forgetSnapshotLocalOnly(context.Background(), pendingLocal("snap"))
		svc.AttachCluster(&errSnapHomeStub{Noop: cluster.NewNoop("node-1", "", "")})
		svc.forgetSnapshotLocalOnly(context.Background(), nil)
		// A failed forget is logged, never fatal.
		svc.forgetSnapshotLocalOnly(context.Background(), pendingLocal("snap"))
	})
}

// A snapshot whose image is already in a registry never gets the local-only
// key: a create by its name can run anywhere.
func TestRegisteredRegistrySnapshotHasNoLocalOnlyKey(t *testing.T) {
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	stub := &snapHomeStub{Noop: cluster.NewNoop("node-1", "", ""), registered: map[string]string{}}
	svc.AttachCluster(stub)
	if _, err := svc.RegisterSnapshot(context.Background(), &models.SandboxSnapshot{Name: "py", Image: "ghcr.io/org/py:3.12"}); err != nil {
		t.Fatalf("RegisterSnapshot: %v", err)
	}
	if _, ok := stub.registered[cluster.SnapshotLocalOnlyKey("", "py")]; ok {
		t.Fatalf("registered = %q, want no local-only key for a registry image", stub.registered)
	}
	if err := svc.DeleteSnapshot(context.Background(), "py"); err != nil {
		t.Fatalf("DeleteSnapshot: %v", err)
	}
	// Forgotten on delete anyway: a push whose own forget failed may have
	// left it behind.
	if !slices.Contains(stub.forgotten, cluster.SnapshotLocalOnlyKey("", "py")) {
		t.Fatalf("forgotten = %q, want the local-only key too", stub.forgotten)
	}
}

// The cluster create router and the snapshot's home both ask whether this
// node has a snapshot of a name in the caller's namespace. Every spelling of
// the name counts; another owner's same-named snapshot does not; a catalogue
// that cannot be read is an error, never "held".
func TestHoldsSnapshotNamed(t *testing.T) {
	svc, st, _ := newServiceRuntimeHarnessAllowStoreClose(t, &recordingRuntime{})
	ctx := context.Background()
	for _, row := range []*models.SandboxSnapshot{
		{Name: "gym", Image: docker.SnapshotImageTagForOwner("tenant-a", "gym"), SourceSandboxID: "sb-1", OwnerRef: "tenant-a", CreatedAt: time.Now()},
		{Name: "ops", Image: docker.SnapshotImageTagForOwner("", "ops"), SourceSandboxID: "sb-2", CreatedAt: time.Now()},
	} {
		if err := st.CreateSnapshot(ctx, row); err != nil {
			t.Fatalf("CreateSnapshot %s: %v", row.Name, err)
		}
	}
	for _, tc := range []struct {
		ctx  context.Context
		name string
		want bool
	}{
		{ctx: ownerScopedCtx("tenant-a"), name: "gym", want: true},
		{ctx: ownerScopedCtx("tenant-a"), name: "gym:latest", want: true},
		{ctx: ownerScopedCtx("tenant-b"), name: "gym", want: false},
		{ctx: ctx, name: "gym", want: false},
		{ctx: ctx, name: "ops", want: true},
		{ctx: ctx, name: "  ", want: false},
		{ctx: ctx, name: "alpine", want: false},
	} {
		got, err := svc.HoldsSnapshotNamed(tc.ctx, tc.name)
		if err != nil || got != tc.want {
			t.Errorf("HoldsSnapshotNamed(%q) = %v,%v, want %v,nil", tc.name, got, err, tc.want)
		}
	}
	var nilSvc *Service
	if got, err := nilSvc.HoldsSnapshotNamed(ctx, "ops"); got || err != nil {
		t.Fatalf("nil service = %v,%v, want false,nil", got, err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}
	if got, err := svc.HoldsSnapshotNamed(ctx, "ops"); got || err == nil {
		t.Fatalf("closed store = %v,%v, want false and an error", got, err)
	}
}

// Only a bare name can be a snapshot a node without its row resolves across
// the cluster; registry refs, tagged images, builds and committed tags each
// have their own path.
func TestIsBareSnapshotName(t *testing.T) {
	for _, tc := range []struct {
		image string
		want  bool
	}{
		{image: "gym-start", want: true},
		{image: " gym-start ", want: true},
		{image: "team/gym", want: true},
		{image: "", want: false},
		{image: "alpine:3.20", want: false},
		{image: "alpine@sha256:" + strings.Repeat("a", 64), want: false},
		{image: "ghcr.io/org/gym", want: false},
		{image: "localhost:5000/gym", want: false},
		{image: docker.SnapshotImageTagForOwner("", "gym"), want: false},
		{image: docker.BuiltImageNamespace + "/abc", want: false},
	} {
		if got := IsBareSnapshotName(tc.image); got != tc.want {
			t.Errorf("IsBareSnapshotName(%q) = %v, want %v", tc.image, got, tc.want)
		}
	}
}
