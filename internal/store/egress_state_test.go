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

// TestEgressHoldRankedAndAppliedPolicy (PR #622 review 2): a ranked hold
// write never replaces a stronger reason, and the applied policy record
// round-trips (nil until written).
func TestEgressHoldRankedAndAppliedPolicy(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	if err := st.Upsert(ctx, &models.Sandbox{ID: "sb", Image: "img", Status: models.SandboxStatusStarted, CreatedAt: now, UpdatedAt: now, LastActiveAt: now}); err != nil {
		t.Fatal(err)
	}
	rank := map[string]int{"weak": 1, "strong": 2}
	for _, step := range []struct{ reason, want string }{{"weak", "weak"}, {"strong", "strong"}, {"weak", "strong"}, {"strong", "strong"}} {
		if err := st.SetEgressHoldRanked(ctx, "sb", step.reason, rank, now); err != nil {
			t.Fatal(err)
		}
		if got, _ := st.GetEgressState(ctx, "sb"); got.HoldReason != step.want {
			t.Fatalf("after %s: hold = %q, want %q", step.reason, got.HoldReason, step.want)
		}
	}
	if err := st.SetEgressHoldRanked(ctx, "sb", "", rank, now); err == nil {
		t.Fatal("an empty reason must be refused")
	}
	got, _ := st.GetEgressState(ctx, "sb")
	if got.Applied != nil {
		t.Fatal("no applied policy before one is written")
	}
	p := AppliedPolicy{AllowOut: []string{"pypi.org"}, Mode: "learn"}
	if err := st.SetAppliedEgressPolicy(ctx, "sb", p, now); err != nil {
		t.Fatal(err)
	}
	if got, _ := st.GetEgressState(ctx, "sb"); got.Applied == nil || got.Applied.AllowOut[0] != "pypi.org" || got.Applied.Mode != "learn" {
		t.Fatalf("applied = %+v", got.Applied)
	}
}
