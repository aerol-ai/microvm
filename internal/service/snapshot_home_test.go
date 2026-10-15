package service

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
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
