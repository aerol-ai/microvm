package netns

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/network/cni"
)

func TestHostRealizeRunnerErrorCleansUp(t *testing.T) {
	runner := cni.NewFakeRunner()
	runner.SetAddError(errors.New("cni add boom"))
	h := &Host{
		Runner:    runner,
		NetnsRoot: t.TempDir(),
		addNetns:  func(context.Context, string) error { return nil },
		delNetns:  func(context.Context, string) error { return nil },
	}
	if _, _, err := h.Realize(context.Background(), Slot{SandboxID: "sb-x"}); err == nil {
		t.Fatal("want realize error when CNI ADD fails")
	}
}

func TestHostRemoveSurfacesDelError(t *testing.T) {
	runner := cni.NewFakeRunner()
	runner.SetDelError(errors.New("cni del boom"))
	h := &Host{
		Runner:   runner,
		delNetns: func(context.Context, string) error { return nil },
	}
	// Del error must surface (errors.Join), not be swallowed.
	if err := h.Remove(context.Background(), Slot{SandboxID: "sb-x", NetnsPath: "/run/netns/sb-x", ContainerIP: "10.88.0.5"}); err == nil {
		t.Fatal("want surfaced CNI DEL error")
	}
}

func TestHostRealizeCreatesRealNetns(t *testing.T) {
	// Realize must create a real netns (addNetns), not just mkdir a directory —
	// the live regression that made CNI ADD fail with a bare "exit status 1".
	var created, deleted string
	runner := cni.NewFakeRunner()
	h := &Host{
		Runner:    runner,
		NetnsRoot: t.TempDir(),
		addNetns:  func(_ context.Context, name string) error { created = name; return nil },
		delNetns:  func(_ context.Context, name string) error { deleted = name; return nil },
	}
	path, ip, err := h.Realize(context.Background(), Slot{SandboxID: "sb-real"})
	if err != nil {
		t.Fatalf("Realize: %v", err)
	}
	if created != "sb-real" {
		t.Fatalf("expected a real netns to be created for sb-real, got %q", created)
	}
	if path == "" || ip == "" {
		t.Fatalf("Realize returned path=%q ip=%q", path, ip)
	}
	if deleted != "" {
		t.Fatalf("netns should not be deleted on success, deleted=%q", deleted)
	}
}

func TestHostRemoveNilRunnerNoOp(t *testing.T) {
	if err := (&Host{}).Remove(context.Background(), Slot{SandboxID: "x"}); err != nil {
		t.Fatalf("nil-runner Remove should be a no-op: %v", err)
	}
}

// TestProvisionFallsThroughOnUnrealizedSlot exercises the B3 fix: a claim that
// resolves to an owned-but-not-yet-realized slot (empty netns path/IP) must NOT
// be treated as a ready hit — Provision falls through to Build, which realizes
// it.
func TestProvisionFallsThroughOnUnrealizedSlot(t *testing.T) {
	p := testPool(t, 2)
	ctx := context.Background()
	now := time.Unix(1, 0).UTC()
	// Reserve leaves the slot reserved with empty path/IP.
	if _, err := p.Reserve(ctx, "sb-x", now); err != nil {
		t.Fatal(err)
	}
	h := NewRuntimeHandoff(p, NewFakeHost())
	path, ip, err := h.Provision(ctx, "sb-x")
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if path == "" || ip == "" {
		t.Fatalf("Provision should realize via Build, got path=%q ip=%q", path, ip)
	}
}
