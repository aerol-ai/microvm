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

// TestEgressHoldRankedAndInstalled (PR #622 reviews 2 and 3): a ranked hold
// write never replaces a stronger reason; a conditional clear lifts only the
// reason it names; the installed record round-trips (nil until written).
func TestEgressHoldRankedAndInstalled(t *testing.T) {
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
	if cleared, err := st.ClearEgressHoldIf(ctx, "sb", "weak", now); err != nil || cleared {
		t.Fatalf("a clear naming another reason must leave the hold: %v %v", cleared, err)
	}
	if cleared, err := st.ClearEgressHoldIf(ctx, "sb", "strong", now); err != nil || !cleared {
		t.Fatalf("a clear naming the reason must lift it: %v %v", cleared, err)
	}
	if cleared, _ := st.ClearEgressHoldIf(ctx, "sb", "", now); cleared {
		t.Fatal("an empty reason clears nothing")
	}
	got, _ := st.GetEgressState(ctx, "sb")
	if got.HoldReason != "" || got.Installed != nil {
		t.Fatalf("state = %+v", got)
	}
	inst := InstalledEgress{Gateway: true, CIDR: []CIDRRules{{Allow: []string{"8.8.8.0/24"}}}}
	if err := st.SetInstalledEgress(ctx, "sb", inst, now); err != nil {
		t.Fatal(err)
	}
	if got, _ := st.GetEgressState(ctx, "sb"); got.Installed == nil || !got.Installed.Gateway || len(got.Installed.CIDR) != 1 || got.Installed.CIDR[0].Allow[0] != "8.8.8.0/24" {
		t.Fatalf("installed = %+v", got.Installed)
	}
	_ = st.Close()
	if err := st.SetInstalledEgress(ctx, "sb", inst, now); err == nil {
		t.Fatal("closed store must error")
	}
	if _, err := st.ClearEgressHoldIf(ctx, "sb", "x", now); err == nil {
		t.Fatal("closed store must error")
	}
}

// TestInstalledRecordLifecycle (review 5 finding 3): ListInstalledEgress
// names exactly the sandboxes with a record, and a cleared one is gone.
func TestInstalledRecordLifecycle(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	for _, id := range []string{"a", "b"} {
		if err := st.Upsert(ctx, &models.Sandbox{ID: id, Image: "img", Status: models.SandboxStatusStarted, CreatedAt: now, UpdatedAt: now, LastActiveAt: now}); err != nil {
			t.Fatal(err)
		}
	}
	if ids, err := st.ListInstalledEgress(ctx); err != nil || len(ids) != 0 {
		t.Fatalf("no records yet: %v %v", ids, err)
	}
	for _, id := range []string{"a", "b"} {
		if err := st.SetInstalledEgress(ctx, id, InstalledEgress{Gateway: true}, now); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.ClearInstalledEgress(ctx, "a", now); err != nil {
		t.Fatal(err)
	}
	ids, err := st.ListInstalledEgress(ctx)
	if err != nil || len(ids) != 1 || ids[0] != "b" {
		t.Fatalf("records = %v %v", ids, err)
	}
	if got, _ := st.GetEgressState(ctx, "a"); got.Installed != nil {
		t.Fatalf("a cleared record must read as none: %+v", got.Installed)
	}
	_ = st.Close()
	if _, err := st.ListInstalledEgress(ctx); err == nil {
		t.Fatal("closed store must error")
	}
	if err := st.ClearInstalledEgress(ctx, "b", now); err == nil {
		t.Fatal("closed store must error")
	}
}

// TestPendingEgressRuleClearLedger (review 6 findings 3 and 4): entries are
// keyed by where the rules live, merge rather than replace, move a
// sandbox's installed record into the ledger in the same transaction, and
// outlive the sandbox row.
func TestPendingEgressRuleClearLedger(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	if err := st.Upsert(ctx, &models.Sandbox{ID: "sb", Image: "img", Status: models.SandboxStatusStarted, CreatedAt: now, UpdatedAt: now, LastActiveAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := st.SetInstalledEgress(ctx, "sb", InstalledEgress{CIDR: []CIDRRules{{Allow: []string{"8.8.8.0/24"}}}}, now); err != nil {
		t.Fatal(err)
	}
	a := PendingEgressRuleClear{Scope: "docker", IP: "10.0.0.20", SandboxID: "sb", Rules: []CIDRRules{{Allow: []string{"8.8.8.0/24"}}}, Hold: true}
	got, err := st.AddPendingEgressRuleClear(ctx, a, "sb", now)
	if err != nil || len(got.Rules) != 1 || !got.Hold {
		t.Fatalf("add = %+v %v", got, err)
	}
	if es, _ := st.GetEgressState(ctx, "sb"); es.Installed != nil {
		t.Fatalf("the record moves into the ledger: %+v", es.Installed)
	}
	b := PendingEgressRuleClear{Scope: "docker", IP: "10.0.0.20", SandboxID: "next", Rules: []CIDRRules{{Allow: []string{"8.8.8.0/24"}}, {Deny: []string{"9.9.9.0/24"}}}}
	got, err = st.AddPendingEgressRuleClear(ctx, b, "", now.Add(time.Minute))
	if err != nil || len(got.Rules) != 2 || !got.Hold || got.SandboxID != "next" || !got.CreatedAt.Equal(now) {
		t.Fatalf("a second add merges: %+v %v", got, err)
	}
	other := PendingEgressRuleClear{Scope: "containerd", IP: "10.0.0.20", SandboxID: "c", Rules: []CIDRRules{{Allow: []string{"1.1.1.0/24"}}}}
	if _, err := st.AddPendingEgressRuleClear(ctx, other, "", now); err != nil {
		t.Fatal(err)
	}
	if err := st.Delete(ctx, "sb"); err != nil {
		t.Fatal(err)
	}
	list, err := st.ListPendingEgressRuleClears(ctx)
	if err != nil || len(list) != 2 || list[0].Scope != "containerd" || list[1].Scope != "docker" || len(list[1].Rules) != 2 {
		t.Fatalf("entries outlive the row, one per scope and address: %+v %v", list, err)
	}

	left := list[1]
	left.Rules, left.Hold = left.Rules[1:], false
	if err := st.SetPendingEgressRuleClear(ctx, left, now); err != nil {
		t.Fatal(err)
	}
	list, _ = st.ListPendingEgressRuleClears(ctx)
	if len(list[1].Rules) != 1 || list[1].Hold || list[1].Rules[0].Deny[0] != "9.9.9.0/24" {
		t.Fatalf("set replaces what is left: %+v", list[1])
	}
	left.Rules = nil
	if err := st.SetPendingEgressRuleClear(ctx, left, now); err != nil {
		t.Fatal(err)
	}
	fresh := PendingEgressRuleClear{Scope: "firecracker", IP: "10.1.0.2", Rules: []CIDRRules{{Allow: []string{"7.7.7.0/24"}}}}
	if err := st.SetPendingEgressRuleClear(ctx, fresh, now); err != nil {
		t.Fatal(err)
	}
	list, _ = st.ListPendingEgressRuleClears(ctx)
	if len(list) != 2 || list[0].Scope != "containerd" || list[1].Scope != "firecracker" {
		t.Fatalf("an empty set deletes, a new one inserts: %+v", list)
	}

	_ = st.Close()
	if _, err := st.AddPendingEgressRuleClear(ctx, a, "", now); err == nil {
		t.Fatal("closed store must error")
	}
	if err := st.SetPendingEgressRuleClear(ctx, fresh, now); err == nil {
		t.Fatal("closed store must error")
	}
	if err := st.SetPendingEgressRuleClear(ctx, PendingEgressRuleClear{Scope: "x", IP: "y"}, now); err == nil {
		t.Fatal("closed store must error")
	}
	if _, err := st.ListPendingEgressRuleClears(ctx); err == nil {
		t.Fatal("closed store must error")
	}
}
