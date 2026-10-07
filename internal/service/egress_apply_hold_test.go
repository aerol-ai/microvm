package service

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
)

// TestPolicyFailureRetryMustApply (review finding 2): a PUT whose apply
// fails holds the sandbox, so the identical retry applies the stored policy
// instead of answering "already in place" while the old one is enforced.
func TestPolicyFailureRetryMustApply(t *testing.T) {
	ctx := context.Background()
	svc, gw, rt := newPolicyHarness(t)
	sb := seedPolicySandbox(t, svc, models.Sandbox{NetworkAllowOut: []string{"pypi.org"}})
	if err := svc.attachSandboxEgress(ctx, sb, rt); err != nil {
		t.Fatal(err)
	}
	rt.blockErr = errors.New("iptables busy")
	req := models.NetworkPolicyRequest{NetworkAllowOut: []string{"github.com"}}
	if _, err := svc.UpdateNetworkPolicy(ctx, sb.ID, req); !errors.Is(err, ErrEgressApplyFailedHeld) {
		t.Fatalf("err = %v", err)
	}
	if st, _ := svc.store.GetEgressState(ctx, sb.ID); st.HoldReason != egressHoldApplyFailed {
		t.Fatalf("hold = %q: apply_failed_held must mean held", st.HoldReason)
	}
	if row, _ := svc.store.Get(ctx, sb.ID); svc.EgressStatus(ctx, row) != EgressStatusHeld {
		t.Fatal("egress_status must say held")
	}
	rt.blockErr = nil
	if _, err := svc.UpdateNetworkPolicy(ctx, sb.ID, req); err != nil {
		t.Fatal(err)
	}
	gw.mu.Lock()
	allow := gw.attached[sb.ID].AllowOut
	gw.mu.Unlock()
	if !slices.Equal(allow, []string{"github.com"}) {
		t.Fatalf("the retry must apply the stored policy; gateway has %v", allow)
	}
	if st, _ := svc.store.GetEgressState(ctx, sb.ID); st.HoldReason != "" {
		t.Fatalf("a successful apply must release the hold, got %q", st.HoldReason)
	}
}

// TestHeldPolicyIsRetriedBySupervisor: an apply_failed hold converges
// without the user retrying: the supervisor's hold pass re-applies the
// stored policy, here a CIDR list whose rules failed to go in.
func TestHeldPolicyIsRetriedBySupervisor(t *testing.T) {
	ctx := context.Background()
	svc, gw, rt := newPolicyHarness(t)
	sb := seedPolicySandbox(t, svc, models.Sandbox{NetworkAllowOut: []string{"1.1.1.0/24"}})
	gw.events = nil
	rt.applyErr = errors.New("iptables busy")
	if _, err := svc.UpdateNetworkPolicy(ctx, sb.ID, models.NetworkPolicyRequest{NetworkAllowOut: []string{"8.8.8.0/24"}}); !errors.Is(err, ErrEgressApplyFailedHeld) {
		t.Fatalf("err = %v", err)
	}
	if !slices.Contains(rt.holds, policyIP) {
		t.Fatal("a held CIDR sandbox gets the host-firewall hold")
	}
	if rt.lifted(policyIP) {
		t.Fatal("the swap block must stay while the rules are missing")
	}
	rt.applyErr = nil
	svc.retryEgressHolds(ctx)
	if st, _ := svc.store.GetEgressState(ctx, sb.ID); st.HoldReason != "" {
		t.Fatalf("the hold pass must apply the stored policy, hold = %q", st.HoldReason)
	}
	if last := rt.applied[len(rt.applied)-1]; !slices.Equal(last, []string{"8.8.8.0/24"}) {
		t.Fatalf("applied %v", rt.applied)
	}
	if !slices.Contains(rt.unhold, policyIP) || !rt.lifted(policyIP) {
		t.Fatal("success lifts the hold and the swap block")
	}
}

// TestMediatedApplyFailureHolds: WASM and isolate sandboxes are held the
// same way, by block-all in their mediators, and released by the next
// successful apply.
func TestMediatedApplyFailureHolds(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newPolicyHarness(t)
	wasm, iso := newMediator(), newMediator()
	svc.wasm, svc.isolate = wasm, iso
	seedPolicySandbox(t, svc, models.Sandbox{ID: "sb-wasm", Runtime: models.RuntimeWasm, NetworkAllowOut: []string{"1.1.1.0/24"}})
	seedPolicySandbox(t, svc, models.Sandbox{ID: "sb-iso", Runtime: models.RuntimeIsolate, NetworkAllowOut: []string{"1.1.1.0/24"}})
	wasm.err, iso.err = errors.New("worker gone"), errors.New("host gone")
	req := models.NetworkPolicyRequest{NetworkAllowOut: []string{"8.8.8.0/24"}}
	for _, id := range []string{"sb-wasm", "sb-iso"} {
		if _, err := svc.UpdateNetworkPolicy(ctx, id, req); !errors.Is(err, ErrEgressApplyFailedHeld) {
			t.Fatalf("%s: err = %v", id, err)
		}
		if st, _ := svc.store.GetEgressState(ctx, id); st.HoldReason != egressHoldApplyFailed {
			t.Fatalf("%s: hold = %q", id, st.HoldReason)
		}
	}
	if !wasm.blocked["sb-wasm"] || !iso.blocked["sb-iso"] {
		t.Fatalf("held mediators must run block-all: wasm=%v iso=%v", wasm.blocked, iso.blocked)
	}
	wasm.err, iso.err = nil, nil
	for _, id := range []string{"sb-wasm", "sb-iso"} {
		if _, err := svc.UpdateNetworkPolicy(ctx, id, req); err != nil {
			t.Fatalf("%s retry: %v", id, err)
		}
		if st, _ := svc.store.GetEgressState(ctx, id); st.HoldReason != "" {
			t.Fatalf("%s: the retry must release the hold", id)
		}
	}
	if wasm.blocked["sb-wasm"] || iso.blocked["sb-iso"] {
		t.Fatal("the applied policy replaces block-all")
	}
}

// TestDestroyFailureKeepsEnforcement (review finding 3): the gateway entry
// goes only after the runtime is gone, so a destroy that fails leaves the
// still-running sandbox filtered for the retry.
func TestDestroyFailureKeepsEnforcement(t *testing.T) {
	ctx := context.Background()
	svc, gw, rt := newPolicyHarness(t)
	resp, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{Image: "alpine", NetworkAllowOut: []string{"pypi.org"}})
	if err != nil {
		t.Fatal(err)
	}
	rt.destroyErr = errors.New("docker timeout")
	if err := svc.DestroySandbox(ctx, resp.ID); err == nil {
		t.Fatal("destroy must report the runtime failure")
	}
	if !gw.isAttached(resp.ID) {
		t.Fatal("a sandbox whose destroy failed must stay under the gateway")
	}
	rt.destroyErr = nil
	if err := svc.DestroySandbox(ctx, resp.ID); err != nil {
		t.Fatal(err)
	}
	if gw.isAttached(resp.ID) {
		t.Fatal("a completed destroy detaches")
	}
}

// TestStaleProfilesHoldEveryRuntime (review finding 6): a profile this
// worker can't read past the staleness bound holds its sandboxes until it
// can be read, WASM and isolate included.
func TestStaleProfilesHoldEveryRuntime(t *testing.T) {
	ctx := context.Background()
	svc, _, rt := newPolicyHarness(t)
	wasm, iso := newMediator(), newMediator()
	svc.wasm, svc.isolate = wasm, iso
	putProfile(t, svc, ctx, "web", "pypi.org")
	var ids []string
	for _, c := range []struct{ id, runtime string }{{"sb-ctr", models.RuntimeDocker}, {"sb-wasm", models.RuntimeWasm}, {"sb-iso", models.RuntimeIsolate}} {
		seedPolicySandbox(t, svc, models.Sandbox{ID: c.id, Runtime: c.runtime})
		if _, err := svc.UpdateNetworkPolicy(ctx, c.id, models.NetworkPolicyRequest{EgressProfiles: []string{"web"}}); err != nil {
			t.Fatalf("%s: %v", c.id, err)
		}
		ids = append(ids, c.id)
	}
	// The worker's cache has gone past its staleness bound.
	svc.egressProfiles = noClusterProfiles{}
	svc.reapplyEgressProfiles(ctx)
	for _, id := range ids {
		if st, _ := svc.store.GetEgressState(ctx, id); st.HoldReason != egressHoldProfileUnavailable {
			t.Fatalf("%s: hold = %q, want profile_unavailable", id, st.HoldReason)
		}
	}
	if !slices.Contains(rt.holds, policyIP) || !wasm.blocked["sb-wasm"] || !iso.blocked["sb-iso"] {
		t.Fatalf("every runtime must be shut: holds=%v wasm=%v iso=%v", rt.holds, wasm.blocked, iso.blocked)
	}
	// Readable again: the pass re-applies and releases them.
	svc.egressProfiles = nil
	svc.reapplyEgressProfiles(ctx)
	for _, id := range ids {
		if st, _ := svc.store.GetEgressState(ctx, id); st.HoldReason != "" {
			t.Fatalf("%s: hold = %q after the profile came back", id, st.HoldReason)
		}
	}
}

// TestEgressProcidAuthorize (review finding 16): sandboxd answers the
// gateway's executable lookups for a started gateway-mode sandbox with
// per-binary rules, with its own record of the sandbox's init pid (renewed
// when the container changes) and only the paths those rules list.
func TestEgressProcidAuthorize(t *testing.T) {
	ctx := context.Background()
	svc, _, rt := newPolicyHarness(t)
	rt.pid = 4242
	rules := []models.EgressRule{{Host: "pypi.org", Ports: []uint16{443}, Binaries: []string{"/usr/local/bin/pip", "/usr/bin/git"}},
		{Host: "github.com", Ports: []uint16{443}, Binaries: []string{"/usr/bin/git"}}}
	sb := seedPolicySandbox(t, svc, models.Sandbox{NetworkAllowOut: []string{"pypi.org", "github.com"}})
	withRules := func(id string) {
		t.Helper()
		if err := svc.store.WriteNetworkPolicy(ctx, id, store.NetworkPolicyWrite{AllowOut: []string{"pypi.org", "github.com"}, Rules: rules}); err != nil {
			t.Fatal(err)
		}
	}
	withRules(sb.ID)
	pid, paths, err := svc.EgressProcidAuthorize(ctx, sb.ID)
	if err != nil || pid != 4242 || !slices.Equal(paths, []string{"/usr/local/bin/pip", "/usr/bin/git"}) {
		t.Fatalf("authorize = %d %v %v", pid, paths, err)
	}
	rt.pid = 9999 // cached for the same container
	if pid, _, _ := svc.EgressProcidAuthorize(ctx, sb.ID); pid != 4242 {
		t.Fatalf("pid = %d, want the cached 4242", pid)
	}
	row, _ := svc.store.Get(ctx, sb.ID)
	row.ContainerID = "ctr-restarted"
	if err := svc.store.Upsert(ctx, row); err != nil {
		t.Fatal(err)
	}
	if pid, _, _ := svc.EgressProcidAuthorize(ctx, sb.ID); pid != 9999 {
		t.Fatalf("a new container must not get the old pid, got %d", pid)
	}

	plain := seedPolicySandbox(t, svc, models.Sandbox{ID: "sb-plain", NetworkAllowOut: []string{"pypi.org"}})
	stopped := seedPolicySandbox(t, svc, models.Sandbox{ID: "sb-stopped", Status: models.SandboxStatusStopped, NetworkAllowOut: []string{"pypi.org"}})
	withRules(stopped.ID)
	for _, id := range []string{plain.ID, stopped.ID, "sb-missing"} {
		if _, _, err := svc.EgressProcidAuthorize(ctx, id); err == nil {
			t.Fatalf("%s: a sandbox without traceable per-binary rules must be refused", id)
		}
	}
	rt.pid, rt.pidErr = 0, errors.New("no such container")
	row.ContainerID = "ctr-gone"
	_ = svc.store.Upsert(ctx, row)
	if _, _, err := svc.EgressProcidAuthorize(ctx, sb.ID); !errors.Is(err, ErrEgressProcidRefused) {
		t.Fatalf("an unknown process must be refused: %v", err)
	}
}
