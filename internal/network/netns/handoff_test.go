package netns

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestRuntimeHandoffProvisionRelease(t *testing.T) {
	p := testPool(t, 2)
	host := NewFakeHost()
	h := NewRuntimeHandoff(p, host)

	path, ip, err := h.Provision(context.Background(), "sb-1")
	if err != nil || path == "" || ip == "" {
		t.Fatalf("provision: path=%s ip=%s err=%v", path, ip, err)
	}
	stats, _ := p.Stats(context.Background())
	if stats.Adopted != 1 {
		t.Fatalf("stats=%+v", stats)
	}
	if err := h.Release(context.Background(), "sb-1"); err != nil {
		t.Fatal(err)
	}
	stats, _ = p.Stats(context.Background())
	if stats.Free != 2 {
		t.Fatalf("after release free=%d", stats.Free)
	}
	if len(host.removed) != 1 {
		t.Fatalf("host removes=%v", host.removed)
	}
}

func TestRuntimeHandoffReleaseIdempotent(t *testing.T) {
	h := NewRuntimeHandoff(testPool(t, 1), NewFakeHost())
	ctx := context.Background()
	_, _, _ = h.Provision(ctx, "sb-x")
	if err := h.Release(ctx, "sb-x"); err != nil {
		t.Fatal(err)
	}
	if err := h.Release(ctx, "sb-x"); err != nil {
		t.Fatal("double release")
	}
}

func TestRuntimeHandoffNilSafe(t *testing.T) {
	var h *RuntimeHandoff
	if err := h.Release(context.Background(), "x"); err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeHandoffProvisionFailureNoLeak(t *testing.T) {
	p := testPool(t, 1)
	host := NewFakeHost()
	host.SetRealizeError(errors.New("cni boom"))
	h := NewRuntimeHandoff(p, host)
	if _, _, err := h.Provision(context.Background(), "sb-f"); err == nil {
		t.Fatal("want error")
	}
	stats, _ := p.Stats(context.Background())
	if stats.Free != 1 {
		t.Fatalf("leaked slot: %+v", stats)
	}
	_ = time.Now()
}

// Address names the address of the slot a sandbox holds, and "" once it
// holds none: the containerd driver frees a failed claim's slot only while
// the sandbox still holds the address it remembered.
func TestRuntimeHandoffAddress(t *testing.T) {
	ctx := context.Background()
	if ip, err := (*RuntimeHandoff)(nil).Address(ctx, "sb-1"); ip != "" || err != nil {
		t.Fatalf("nil handoff: %q %v", ip, err)
	}
	h := NewRuntimeHandoff(testPool(t, 2), NewFakeHost())
	if ip, err := h.Address(ctx, "sb-1"); ip != "" || err != nil {
		t.Fatalf("before provision: %q %v", ip, err)
	}
	_, want, err := h.Provision(ctx, "sb-1")
	if err != nil {
		t.Fatal(err)
	}
	if ip, err := h.Address(ctx, "sb-1"); ip != want || err != nil {
		t.Fatalf("held: %q %v, want %q", ip, err, want)
	}
	if err := h.Release(ctx, "sb-1"); err != nil {
		t.Fatal(err)
	}
	if ip, err := h.Address(ctx, "sb-1"); ip != "" || err != nil {
		t.Fatalf("after release: %q %v", ip, err)
	}
	if _, err := h.Address(ctx, " "); err == nil {
		t.Fatal("an empty sandbox id was not refused")
	}
}
