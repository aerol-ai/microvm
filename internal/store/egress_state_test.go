package store

import (
	"context"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

func TestEgressHoldLifecycle(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	now := time.Now().UTC().Truncate(time.Second)
	if err := st.Upsert(ctx, &models.Sandbox{ID: "sb", Image: "img", Status: models.SandboxStatusStarted, CreatedAt: now, UpdatedAt: now, LastActiveAt: now}); err != nil {
		t.Fatal(err)
	}
	if s, err := st.GetEgressState(ctx, "sb"); err != nil || s.HoldReason != "" {
		t.Fatalf("fresh state = %+v, %v", s, err)
	}
	if err := st.SetEgressHold(ctx, "sb", "", now); err == nil {
		t.Fatal("a hold needs a reason")
	}
	if err := st.SetEgressHold(ctx, "sb", "attach_failed", now); err != nil {
		t.Fatal(err)
	}
	later := now.Add(time.Minute)
	if err := st.SetEgressHold(ctx, "sb", "gateway_unavailable", later); err != nil {
		t.Fatal(err)
	}
	s, err := st.GetEgressState(ctx, "sb")
	if err != nil || s.HoldReason != "gateway_unavailable" || !s.HoldSince.Equal(now) {
		t.Fatalf("state = %+v, %v (hold_since must keep the first hold)", s, err)
	}
	holds, err := st.ListEgressHolds(ctx)
	if err != nil || holds["sb"] != "gateway_unavailable" {
		t.Fatalf("holds = %v, %v", holds, err)
	}
	if err := st.ClearEgressHold(ctx, "sb", later); err != nil {
		t.Fatal(err)
	}
	if holds, _ := st.ListEgressHolds(ctx); len(holds) != 0 {
		t.Fatalf("holds after clear = %v", holds)
	}
	if err := st.SetEgressHold(ctx, "sb", "attach_failed", later); err != nil {
		t.Fatal(err)
	}
	if err := st.Delete(ctx, "sb"); err != nil {
		t.Fatal(err)
	}
	if holds, _ := st.ListEgressHolds(ctx); len(holds) != 0 {
		t.Fatal("egress state must go with its sandbox (ON DELETE CASCADE)")
	}
	_ = st.Close()
	if _, err := st.GetEgressState(ctx, "sb"); err == nil {
		t.Fatal("closed store must error")
	}
	if _, err := st.ListEgressHolds(ctx); err == nil {
		t.Fatal("closed store must error")
	}
	if err := st.SetEgressHold(ctx, "sb", "x", now); err == nil {
		t.Fatal("closed store must error")
	}
	if err := st.ClearEgressHold(ctx, "sb", now); err == nil {
		t.Fatal("closed store must error")
	}
}
