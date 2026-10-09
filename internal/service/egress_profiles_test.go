package service

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/egresspolicy"
	"github.com/aerol-ai/microvm/pkg/models"
)

func ownerCtx(owner string) context.Context {
	return controlplane.ContextWithAccess(context.Background(), controlplane.Access{Identity: controlplane.Identity{OwnerRef: owner}})
}

func putProfile(t *testing.T, svc *Service, ctx context.Context, name string, allow ...string) *models.EgressProfile {
	t.Helper()
	p, err := svc.PutEgressProfile(ctx, name, models.EgressProfileRequest{AllowOut: allow})
	if err != nil {
		t.Fatalf("put %s: %v", name, err)
	}
	return p
}

func TestEgressProfileCRUDService(t *testing.T) {
	svc, _, _ := newPolicyHarness(t)
	a, b := ownerCtx("acct-a"), ownerCtx("acct-b")
	p := putProfile(t, svc, a, "python", "PyPI.org", "pypi.org", "*.pythonhosted.org")
	if p.Generation != 1 || !slices.Equal(p.AllowOut, []string{"pypi.org", "*.pythonhosted.org"}) {
		t.Fatalf("stored canonical and deduped: %+v", p)
	}
	if again := putProfile(t, svc, a, "python", "pypi.org", "*.pythonhosted.org"); again.Generation != 1 {
		t.Fatal("the same body must be a no-op")
	}
	if _, err := svc.GetEgressProfile(b, "python"); !errors.Is(err, ErrEgressProfileNotFound) {
		t.Fatalf("owners are separate namespaces: %v", err)
	}
	var big []string
	for i := 0; i <= egresspolicy.MaxProfileHostnames; i++ {
		big = append(big, fmt.Sprintf("h%d.example.com", i))
	}
	for _, tc := range []struct {
		name string
		req  models.EgressProfileRequest
	}{
		{"Bad_Name", models.EgressProfileRequest{}},
		{"builtin:pypi", models.EgressProfileRequest{}},
		{"ok", models.EgressProfileRequest{AllowOut: []string{"bad host!"}}},
		{"ok", models.EgressProfileRequest{AllowOut: big}},
		{"ok", models.EgressProfileRequest{Description: strings.Repeat("x", maxProfileDescription+1)}},
	} {
		if _, err := svc.PutEgressProfile(a, tc.name, tc.req); !errors.Is(err, egresspolicy.ErrInvalid) {
			t.Fatalf("%s: err = %v", tc.name, err)
		}
	}
	for _, n := range []string{"b1", "b2", "b3"} {
		putProfile(t, svc, a, n)
	}
	page, err := svc.ListEgressProfiles(a, "", 2)
	if err != nil || len(page.Profiles) != 2 || page.Profiles[0].Name != "b1" || page.NextCursor != "b2" {
		t.Fatalf("page 1 = %+v %v", page, err)
	}
	page, _ = svc.ListEgressProfiles(a, page.NextCursor, 0)
	if len(page.Profiles) != 2 || page.Profiles[1].Name != "python" || page.NextCursor != "" {
		t.Fatalf("page 2 = %+v", page)
	}
	if page, _ := svc.ListEgressProfiles(a, "", 10_000); len(page.Profiles) != 4 {
		t.Fatalf("limit is capped, not refused: %d", len(page.Profiles))
	}
	if err := svc.DeleteEgressProfile(a, "b1"); err != nil {
		t.Fatal(err)
	}
	if err := svc.DeleteEgressProfile(a, "b1"); err != nil {
		t.Fatalf("deleting a gone profile succeeds: %v", err)
	}
	if err := svc.DeleteEgressProfile(a, "Bad"); !errors.Is(err, egresspolicy.ErrInvalid) {
		t.Fatalf("bad name: %v", err)
	}

	svc.SetEgressOperator(operatorWatcher(t, "version: 1\nceiling: {allow_out: [\"*.corp.example\"]}\ndefault_policy: {mode: block_all}\n"))
	if _, err := svc.PutEgressProfile(a, "outside", models.EgressProfileRequest{AllowOut: []string{"evil.example"}}); !errors.Is(err, egresspolicy.ErrInvalid) {
		t.Fatalf("outside the ceiling: %v", err)
	}
}

// TestCreateWithEgressProfiles: the row and the driver get the effective
// list; GET shows the inline list, the references and their generations.
func TestCreateWithEgressProfiles(t *testing.T) {
	svc, gw, _ := newPolicyHarness(t)
	ctx := ownerCtx("acct")
	putProfile(t, svc, ctx, "python", "pypi.org")
	resp, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{Image: "alpine", NetworkAllowOut: []string{"10.0.0.0/8"}, EgressProfiles: []string{"python"}})
	if err != nil {
		t.Fatal(err)
	}
	row, _ := svc.store.Get(ctx, resp.ID)
	if !slices.Equal(row.NetworkAllowOut, []string{"10.0.0.0/8", "pypi.org"}) {
		t.Fatalf("row holds the effective list: %v", row.NetworkAllowOut)
	}
	if spec := gw.attached[resp.ID]; !slices.Contains(spec.AllowOut, "pypi.org") {
		t.Fatalf("a profile's hostname puts the sandbox in gateway mode: %+v", spec)
	}
	if !slices.Equal(resp.NetworkAllowOut, []string{"10.0.0.0/8"}) || !slices.Equal(resp.EgressProfiles, []string{"python"}) {
		t.Fatalf("create response = %v %v", resp.NetworkAllowOut, resp.EgressProfiles)
	}
	got, err := svc.GetSandbox(ctx, resp.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got.NetworkAllowOut, []string{"10.0.0.0/8"}) || len(got.EgressProfilesApplied) != 1 || got.EgressProfilesApplied[0].Generation != 1 {
		t.Fatalf("GET = %v %+v", got.NetworkAllowOut, got.EgressProfilesApplied)
	}
	list, err := svc.ListSandboxes(ctx, nil)
	if err != nil || len(list) != 1 || !slices.Equal(list[0].EgressProfiles, []string{"python"}) {
		t.Fatalf("list = %+v %v", list, err)
	}
	spec, err := svc.specFromSandbox(ctx, row)
	if err != nil || !slices.Equal(spec.NetworkAllowOut, []string{"10.0.0.0/8"}) || !slices.Equal(spec.EgressProfiles, []string{"python"}) {
		t.Fatalf("a replay keeps the inline list and references: %+v %v", spec, err)
	}

	for _, tc := range []struct {
		name string
		req  models.CreateSandboxRequest
	}{
		{"unknown profile", models.CreateSandboxRequest{Image: "alpine", EgressProfiles: []string{"nope"}}},
		{"unknown built-in", models.CreateSandboxRequest{Image: "alpine", EgressProfiles: []string{"builtin:nope"}}},
		{"block-all", models.CreateSandboxRequest{Image: "alpine", NetworkBlockAll: true, EgressProfiles: []string{"python"}}},
		{"firecracker", models.CreateSandboxRequest{Image: "alpine", Runtime: models.RuntimeFirecracker, EgressProfiles: []string{"python"}}},
	} {
		if _, err := svc.CreateSandbox(ctx, tc.req); err == nil {
			t.Fatalf("%s: create must fail", tc.name)
		}
	}
	// The owner's namespace: another account's profile of the same name
	// isn't visible.
	if _, err := svc.CreateSandbox(ownerCtx("other"), models.CreateSandboxRequest{Image: "alpine", EgressProfiles: []string{"python"}}); !errors.Is(err, egresspolicy.ErrInvalid) {
		t.Fatalf("another owner's profile: %v", err)
	}
	if err := svc.DeleteEgressProfile(ctx, "python"); !errors.Is(err, ErrEgressProfileInUse) {
		t.Fatalf("delete in use: %v", err)
	}
}

func TestEgressProfileUnionCap(t *testing.T) {
	svc, _, _ := newPolicyHarness(t)
	ctx := ownerCtx("acct")
	half := func(prefix string) []string {
		var out []string
		for i := 0; i < egresspolicy.MaxProfileHostnames; i++ {
			out = append(out, fmt.Sprintf("%s%d.example.com", prefix, i))
		}
		return out
	}
	putProfile(t, svc, ctx, "one", half("a")...)
	putProfile(t, svc, ctx, "two", half("b")[:egresspolicy.MaxProfileHostnames-1]...)
	resp, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{Image: "alpine", EgressProfiles: []string{"one", "two"}, NetworkAllowOut: []string{"x.example.com"}})
	if err != nil {
		t.Fatalf("exactly at the cap: %v", err)
	}
	if _, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{Image: "alpine", EgressProfiles: []string{"one", "two"}, NetworkAllowOut: []string{"x.example.com", "y.example.com"}}); !errors.Is(err, egresspolicy.ErrInvalid) {
		t.Fatalf("over the cap: %v", err)
	}
	// Growing a referenced profile past the cap names the sandbox.
	_, err = svc.PutEgressProfile(ctx, "two", models.EgressProfileRequest{AllowOut: half("c")})
	if !errors.Is(err, ErrEgressProfileCapExceeded) || !strings.Contains(err.Error(), resp.ID) {
		t.Fatalf("cap check: %v", err)
	}
}

// TestUpdateNetworkPolicyWithProfiles: references change live like any other
// policy change, and an unchanged body is a no-op.
func TestUpdateNetworkPolicyWithProfiles(t *testing.T) {
	svc, gw, rt := newPolicyHarness(t)
	ctx := ownerCtx("acct")
	putProfile(t, svc, ctx, "python", "pypi.org")
	putProfile(t, svc, ctx, "cidrs", "1.1.1.0/24")
	seedPolicySandbox(t, svc, models.Sandbox{OwnerRef: "acct"})
	req := models.NetworkPolicyRequest{NetworkAllowOut: []string{"10.0.0.0/8"}, EgressProfiles: []string{"python"}}
	got, err := svc.UpdateNetworkPolicy(ctx, "sb-pol", req)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got.NetworkAllowOut, []string{"10.0.0.0/8"}) || !slices.Equal(got.EgressProfiles, []string{"python"}) || got.EffectiveHostnameCount != 1 || got.EgressStatus != EgressStatusActive {
		t.Fatalf("response = %+v", got)
	}
	if spec := gw.attached["sb-pol"]; !slices.Equal(spec.AllowOut, []string{"10.0.0.0/8", "pypi.org"}) {
		t.Fatalf("gateway gets the effective list: %v", spec.AllowOut)
	}
	before := rt.blockCalls
	if _, err := svc.UpdateNetworkPolicy(ctx, "sb-pol", req); err != nil || rt.blockCalls != before {
		t.Fatalf("a repeat must be a no-op: %v %d→%d", err, before, rt.blockCalls)
	}
	// Swap the reference for a CIDR-only profile: out of gateway mode.
	got, err = svc.UpdateNetworkPolicy(ctx, "sb-pol", models.NetworkPolicyRequest{EgressProfiles: []string{"cidrs"}})
	if err != nil || got.EgressStatus != "" || !slices.Contains(gw.detached, "sb-pol") || len(rt.applied) == 0 || !slices.Equal(rt.applied[len(rt.applied)-1], []string{"1.1.1.0/24"}) {
		t.Fatalf("CIDR profile: %+v %v applied=%v", got, err, rt.applied)
	}
	if _, err := svc.UpdateNetworkPolicy(ctx, "sb-pol", models.NetworkPolicyRequest{EgressProfiles: []string{"missing"}}); !errors.Is(err, egresspolicy.ErrInvalid) {
		t.Fatalf("unknown profile: %v", err)
	}
	// Dropping every reference clears them.
	if got, err := svc.UpdateNetworkPolicy(ctx, "sb-pol", models.NetworkPolicyRequest{}); err != nil || len(got.EgressProfiles) != 0 {
		t.Fatalf("clear: %+v %v", got, err)
	}
	if state, _ := svc.store.GetSandboxEgressProfiles(ctx, "sb-pol"); len(state.Refs) != 0 {
		t.Fatalf("references left: %+v", state)
	}
}

// TestReapplyEgressProfiles: a profile change reaches a running sandbox
// (row, gateway, applied generation) and a stopped one (row only).
func TestReapplyEgressProfiles(t *testing.T) {
	svc, gw, _ := newPolicyHarness(t)
	ctx := ownerCtx("acct")
	putProfile(t, svc, ctx, "python", "pypi.org")
	seedPolicySandbox(t, svc, models.Sandbox{OwnerRef: "acct"})
	seedPolicySandbox(t, svc, models.Sandbox{ID: "sb-stopped", OwnerRef: "acct", Status: models.SandboxStatusStopped})
	for _, id := range []string{"sb-pol", "sb-stopped"} {
		if _, err := svc.UpdateNetworkPolicy(ctx, id, models.NetworkPolicyRequest{EgressProfiles: []string{"python"}}); err != nil {
			t.Fatal(err)
		}
	}
	putProfile(t, svc, ctx, "python", "pypi.org", "*.pythonhosted.org")
	select {
	case <-svc.profileKick():
	default:
		t.Fatal("a profile change must wake the re-apply pass")
	}
	svc.reapplyEgressProfiles(ctx)
	for _, id := range []string{"sb-pol", "sb-stopped"} {
		row, _ := svc.store.Get(ctx, id)
		if !slices.Equal(row.NetworkAllowOut, []string{"pypi.org", "*.pythonhosted.org"}) {
			t.Fatalf("%s row = %v", id, row.NetworkAllowOut)
		}
		state, _ := svc.store.GetSandboxEgressProfiles(ctx, id)
		if state.Refs[0].Generation != 2 {
			t.Fatalf("%s applied = %+v", id, state.Refs)
		}
	}
	if spec := gw.attached["sb-pol"]; !slices.Contains(spec.AllowOut, "*.pythonhosted.org") {
		t.Fatalf("running sandbox's gateway policy = %v", spec.AllowOut)
	}
	if _, ok := gw.attached["sb-stopped"]; ok {
		t.Fatal("a stopped sandbox must not be attached")
	}
	// Nothing stale: a second pass changes nothing.
	n := len(gw.attached)
	svc.reapplyEgressProfiles(ctx)
	if len(gw.attached) != n {
		t.Fatal("an idle pass must not re-apply")
	}
}

// vanishedProfiles reads every profile as gone, as a cluster race could
// leave it.
type vanishedProfiles struct{ *store.Store }

func (vanishedProfiles) GetEgressProfile(context.Context, string, string) (models.EgressProfile, error) {
	return models.EgressProfile{}, ErrEgressProfileNotFound
}

func TestReapplyHoldsWhenProfilesUnreadable(t *testing.T) {
	svc, gw, rt := newPolicyHarness(t)
	ctx := ownerCtx("acct")
	putProfile(t, svc, ctx, "python", "pypi.org")
	seedPolicySandbox(t, svc, models.Sandbox{OwnerRef: "acct"})
	if _, err := svc.UpdateNetworkPolicy(ctx, "sb-pol", models.NetworkPolicyRequest{EgressProfiles: []string{"python"}}); err != nil {
		t.Fatal(err)
	}
	// The profile vanishes underneath (a cluster race); the sandbox is held,
	// and the hold-retry loop leaves it alone.
	svc.egressProfiles = vanishedProfiles{svc.store}
	before := egressProfileApplyFailedTotal.Value()
	svc.reapplyEgressProfiles(ctx)
	if st, _ := svc.store.GetEgressState(ctx, "sb-pol"); st.HoldReason != egressHoldProfileUnavailable || len(rt.holds) == 0 {
		t.Fatalf("hold = %+v", st)
	}
	if egressProfileApplyFailedTotal.Value() != before+1 {
		t.Fatal("the failure must be counted")
	}
	svc.retryEgressHolds(ctx)
	if st, _ := svc.store.GetEgressState(ctx, "sb-pol"); st.HoldReason != egressHoldProfileUnavailable {
		t.Fatal("the hold retry must not lift a profile hold")
	}
	// The profile comes back at the same generation: the re-apply lifts it.
	svc.egressProfiles = nil
	svc.reapplyEgressProfiles(ctx)
	if st, _ := svc.store.GetEgressState(ctx, "sb-pol"); st.HoldReason != "" || !gw.isAttached("sb-pol") {
		t.Fatalf("hold after the profile returned = %+v", st)
	}
}

func TestSuperviseEgressProfilesStopsOnCancel(t *testing.T) {
	svc, _, _ := newPolicyHarness(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		svc.SuperviseEgressProfiles(ctx)
		close(done)
	}()
	svc.kickEgressProfileReapply()
	svc.kickEgressProfileReapply() // coalesces, never blocks
	cancel()
	<-done
}

// TestUpdateNetworkListsKeepsProfiles: a facade update that can't express
// profiles replaces the lists and keeps the references (D19).
func TestUpdateNetworkListsKeepsProfiles(t *testing.T) {
	svc, _, _ := newPolicyHarness(t)
	ctx := ownerCtx("acct")
	putProfile(t, svc, ctx, "cidrs", "1.1.1.0/24")
	seedPolicySandbox(t, svc, models.Sandbox{OwnerRef: "acct"})
	if _, err := svc.UpdateNetworkPolicy(ctx, "sb-pol", models.NetworkPolicyRequest{EgressProfiles: []string{"cidrs"}}); err != nil {
		t.Fatal(err)
	}
	got, err := svc.UpdateNetworkLists(ctx, "sb-pol", false, []string{"8.8.8.0/24"}, nil)
	if err != nil || !slices.Equal(got.EgressProfiles, []string{"cidrs"}) || !slices.Equal(got.NetworkAllowOut, []string{"8.8.8.0/24"}) {
		t.Fatalf("lists update = %+v %v", got, err)
	}
	if row, _ := svc.store.Get(ctx, "sb-pol"); !slices.Equal(row.NetworkAllowOut, []string{"8.8.8.0/24", "1.1.1.0/24"}) {
		t.Fatalf("effective = %v", row.NetworkAllowOut)
	}
	if _, err := svc.UpdateNetworkLists(ctx, "sb-pol", true, nil, nil); !errors.Is(err, ErrEgressProfilesConflict) {
		t.Fatalf("block-all over profiles: %v", err)
	}
}

// TestEgressProfilesNeedReplicatedStoreInCluster: a cluster node never falls
// back to its own store, which would give each node its own profiles.
func TestEgressProfilesNeedReplicatedStoreInCluster(t *testing.T) {
	svc, _, _ := newPolicyHarness(t)
	svc.cfg.EnableCluster = true
	ctx := ownerCtx("acct")
	if _, err := svc.PutEgressProfile(ctx, "p", models.EgressProfileRequest{}); !errors.Is(err, ErrEgressProfileUnavailable) {
		t.Fatalf("put: %v", err)
	}
	if _, err := svc.GetEgressProfile(ctx, "p"); !errors.Is(err, ErrEgressProfileUnavailable) {
		t.Fatalf("get: %v", err)
	}
	if _, err := svc.ListEgressProfiles(ctx, "", 0); !errors.Is(err, ErrEgressProfileUnavailable) {
		t.Fatalf("list: %v", err)
	}
	if err := svc.DeleteEgressProfile(ctx, "p"); !errors.Is(err, ErrEgressProfileUnavailable) {
		t.Fatalf("delete: %v", err)
	}
	if _, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{Image: "alpine", EgressProfiles: []string{"p"}}); !errors.Is(err, ErrEgressProfileUnavailable) {
		t.Fatalf("create: %v", err)
	}
}
