package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestContainerNetnsSlotValidationErrors(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	if err := st.SeedContainerNetnsSlot(ctx, "", now); err == nil {
		t.Fatal("empty slot_id")
	}
	if _, err := st.ReserveContainerNetnsSlot(ctx, "", now); err == nil {
		t.Fatal("empty sandbox reserve")
	}
	if _, err := st.MarkContainerNetnsSlotRealized(ctx, "", "/n", "10.0.0.1", now); err == nil {
		t.Fatal("empty sandbox realize")
	}
	if _, err := st.AdoptContainerNetnsSlot(ctx, "", now); err == nil {
		t.Fatal("empty sandbox adopt")
	}
	if err := st.ReleaseContainerNetnsSlot(ctx, "", now); err == nil {
		t.Fatal("empty sandbox release")
	}
}

func TestContainerNetnsListByState(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Unix(5, 0).UTC()
	for i := 0; i < 3; i++ {
		_ = st.SeedContainerNetnsSlot(ctx, "aerol-netns-"+iToStr(i), now)
	}
	free, err := st.ListContainerNetnsSlotsByState(ctx, NetnsSlotStateFree)
	if err != nil || len(free) != 3 {
		t.Fatalf("free slots = %d err=%v", len(free), err)
	}
	_, _ = st.ReserveContainerNetnsSlot(ctx, "sb-l", now)
	reserved, err := st.ListContainerNetnsSlotsByState(ctx, NetnsSlotStateReserved)
	if err != nil || len(reserved) != 1 {
		t.Fatalf("reserved = %d err=%v", len(reserved), err)
	}
}

func TestContainerNetnsMarkRealizedWrongState(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	_ = st.SeedContainerNetnsSlot(ctx, "aerol-netns-0", now)
	if _, err := st.MarkContainerNetnsSlotRealized(ctx, "ghost", "/n", "10.0.0.2", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want not found, got %v", err)
	}
}

func TestContainerNetnsReleaseIdempotent(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	_ = st.SeedContainerNetnsSlot(ctx, "aerol-netns-0", now)
	if err := st.ReleaseContainerNetnsSlot(ctx, "nobody", now); err != nil {
		t.Fatal(err)
	}
	if err := st.ReleaseContainerNetnsSlot(ctx, "nobody", now); err != nil {
		t.Fatal("double release should be no-op")
	}
}

func TestContainerNetnsStatsEmpty(t *testing.T) {
	st := newTestStore(t)
	stats, err := st.GetContainerNetnsPoolStats(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if stats.Total != 0 {
		t.Fatalf("stats=%+v", stats)
	}
}

func TestContainerNetnsReassignSandbox(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	_ = st.SeedContainerNetnsSlot(ctx, "aerol-netns-0", now)
	_, _ = st.ReserveContainerNetnsSlot(ctx, "park-1", now)
	_, _ = st.MarkContainerNetnsSlotRealized(ctx, "park-1", "/n", "10.0.0.4", now)
	_, _ = st.AdoptContainerNetnsSlot(ctx, "park-1", now)
	if err := st.ReassignContainerNetnsSandbox(ctx, "park-1", "sb-warm", now); err != nil {
		t.Fatal(err)
	}
	slot, err := st.GetContainerNetnsSlotBySandbox(ctx, "sb-warm")
	if err != nil || slot == nil || slot.SandboxID != "sb-warm" {
		t.Fatalf("slot=%+v err=%v", slot, err)
	}
}

func TestContainerNetnsAdoptIdempotent(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	_ = st.SeedContainerNetnsSlot(ctx, "aerol-netns-0", now)
	_, _ = st.ReserveContainerNetnsSlot(ctx, "sb-a", now)
	_, _ = st.MarkContainerNetnsSlotRealized(ctx, "sb-a", "/n", "10.0.0.3", now)
	a, err := st.AdoptContainerNetnsSlot(ctx, "sb-a", now)
	if err != nil {
		t.Fatal(err)
	}
	b, err := st.AdoptContainerNetnsSlot(ctx, "sb-a", now)
	if err != nil || a.SlotID != b.SlotID {
		t.Fatalf("idempotent adopt failed: %+v %+v", a, b)
	}
}
