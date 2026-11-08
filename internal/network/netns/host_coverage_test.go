package netns

import (
	"context"
	"testing"

	"github.com/aerol-ai/microvm/internal/network/cni"
)

func TestHostRemoveEmptyPathUsesRoot(t *testing.T) {
	removed := ""
	h := &Host{
		Runner:    cni.NewFakeRunner(),
		NetnsRoot: "/tmp/netns-root",
		delNetns: func(_ context.Context, name string) error {
			removed = name
			return nil
		},
	}
	if err := h.Remove(context.Background(), Slot{SandboxID: "sb-empty-path"}); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if removed != "sb-empty-path" {
		t.Fatalf("removed = %q", removed)
	}
}

func TestBuilderBuildPoolExhaustion(t *testing.T) {
	p := testPool(t, 1)
	host := NewFakeHost()
	b := NewBuilder(p, host)
	if _, err := b.Build(context.Background(), "sb-1"); err != nil {
		t.Fatalf("build1: %v", err)
	}
	if _, err := b.Build(context.Background(), "sb-2"); err == nil {
		t.Fatal("want pool exhaustion error")
	}
}
