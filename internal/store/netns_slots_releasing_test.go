package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

// A slot whose host teardown failed is parked as releasing: no owner (so no
// sandbox can find or claim it), identity kept (so the retry deletes what
// CNI ADD created), and invisible to Reserve / BeginPrewarm / ClaimPooled.
func TestMarkContainerNetnsSlotReleasing(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(10, 0).UTC()
	st, err := Open(t.TempDir() + "/releasing.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.SeedContainerNetnsSlot(ctx, "aerol-netns-0", now); err != nil {
		t.Fatal(err)
	}

	// A free row cannot be parked.
	if err := st.MarkContainerNetnsSlotReleasing(ctx, "aerol-netns-0", "", "/run/netns/x", "10.88.0.2", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("free row: err=%v, want ErrNotFound", err)
	}
	if err := st.MarkContainerNetnsSlotReleasing(ctx, " ", "", "", "", now); err == nil {
		t.Fatal("want slot_id required")
	}

	if _, err := st.BeginPrewarmContainerNetnsSlot(ctx, now); err != nil {
		t.Fatal(err)
	}
	if err := st.FinishPrewarmContainerNetnsSlot(ctx, "aerol-netns-0", "/run/netns/aerol-netns-0", "10.88.0.2", now); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ClaimPooledContainerNetnsSlot(ctx, "sb-a", now); err != nil {
		t.Fatal(err)
	}
	// Wrong owner: the row is left alone.
	if err := st.MarkContainerNetnsSlotReleasing(ctx, "aerol-netns-0", "sb-other", "/run/netns/aerol-netns-0", "10.88.0.2", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("owner mismatch: err=%v, want ErrNotFound", err)
	}
	if err := st.MarkContainerNetnsSlotReleasing(ctx, "aerol-netns-0", "sb-a", "/run/netns/aerol-netns-0", "10.88.0.2", now); err != nil {
		t.Fatal(err)
	}
	if got, err := st.GetContainerNetnsSlotBySandbox(ctx, "sb-a"); err != nil || got != nil {
		t.Fatalf("parked slot still found by its old owner: %+v err=%v", got, err)
	}
	rows, err := st.ListContainerNetnsSlotsByState(ctx, NetnsSlotStateReleasing)
	if err != nil || len(rows) != 1 {
		t.Fatalf("rows=%+v err=%v", rows, err)
	}
	if r := rows[0]; r.NetnsPath != "/run/netns/aerol-netns-0" || r.ContainerIP != "10.88.0.2" || r.SandboxID != "" {
		t.Fatalf("parked row=%+v", r)
	}
	stats, err := st.GetContainerNetnsPoolStats(ctx)
	if err != nil || stats.Releasing != 1 || stats.Free != 0 || stats.Total != 1 {
		t.Fatalf("stats=%+v err=%v", stats, err)
	}
	if _, err := st.ReserveContainerNetnsSlot(ctx, "sb-b", now); !errors.Is(err, ErrNoFreeContainerNetnsSlot) {
		t.Fatalf("reserve took a releasing slot: err=%v", err)
	}
	if _, err := st.BeginPrewarmContainerNetnsSlot(ctx, now); !errors.Is(err, ErrNoFreeContainerNetnsSlot) {
		t.Fatalf("prewarm took a releasing slot: err=%v", err)
	}
	if _, err := st.ClaimPooledContainerNetnsSlot(ctx, "sb-c", now); !errors.Is(err, ErrNoPooledContainerNetnsSlot) {
		t.Fatalf("claim took a releasing slot: err=%v", err)
	}
	// Re-parking a releasing row (retry failed again) is allowed.
	if err := st.MarkContainerNetnsSlotReleasing(ctx, "aerol-netns-0", "", "/run/netns/aerol-netns-0", "10.88.0.2", now.Add(time.Second)); err != nil {
		t.Fatalf("re-park: %v", err)
	}
}

func TestFreeReleasingContainerNetnsSlot(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(10, 0).UTC()
	st, err := Open(t.TempDir() + "/free-releasing.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	for _, id := range []string{"aerol-netns-0", "aerol-netns-1"} {
		if err := st.SeedContainerNetnsSlot(ctx, id, now); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := st.ReserveContainerNetnsSlot(ctx, "sb-a", now); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ReserveContainerNetnsSlot(ctx, "sb-keep", now); err != nil {
		t.Fatal(err)
	}
	if err := st.MarkContainerNetnsSlotReleasing(ctx, "aerol-netns-0", "sb-a", "/run/netns/sb-a", "", now); err != nil {
		t.Fatal(err)
	}
	if err := st.FreeReleasingContainerNetnsSlot(ctx, "aerol-netns-0", now); err != nil {
		t.Fatal(err)
	}
	// Only releasing rows are freed: sb-keep's reserved row is untouched.
	if err := st.FreeReleasingContainerNetnsSlot(ctx, "aerol-netns-1", now); err != nil {
		t.Fatal(err)
	}
	if got, _ := st.GetContainerNetnsSlotBySandbox(ctx, "sb-keep"); got == nil {
		t.Fatal("a reserved row was freed")
	}
	stats, _ := st.GetContainerNetnsPoolStats(ctx)
	if stats.Free != 1 || stats.Releasing != 0 {
		t.Fatalf("stats=%+v", stats)
	}
	if err := st.FreeReleasingContainerNetnsSlot(ctx, "", now); err == nil {
		t.Fatal("want slot_id required")
	}
	_ = st.Close()
	if err := st.FreeReleasingContainerNetnsSlot(ctx, "aerol-netns-0", now); err == nil {
		t.Fatal("want closed-store error")
	}
	if err := st.MarkContainerNetnsSlotReleasing(ctx, "aerol-netns-0", "", "", "", now); err == nil {
		t.Fatal("want closed-store error")
	}
}
