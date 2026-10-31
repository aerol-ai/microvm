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
// node from any other; deleting the snapshot forgets both keys. A snapshot
// registered over some other image owns no tag and gets only its name key.
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
			want := map[string]string{nameKey: "node-1", tagKey: "node-1"}
			if !maps.Equal(stub.registered, want) {
				t.Fatalf("registered = %q, want %q", stub.registered, want)
			}

			if err := svc.DeleteSnapshot(tc.ctx, tc.name); err != nil {
				t.Fatalf("DeleteSnapshot: %v", err)
			}
			slices.Sort(stub.forgotten)
			wantForgotten := []string{nameKey, tagKey}
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
