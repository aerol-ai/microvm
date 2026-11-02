package service

// Regression tests for a fail-open found by the bank-readiness campaign on
// the local-mode scenario: with the host firewall off (install.sh --local
// writes SB_ENABLE_NETWORK_RULES=false; macOS has no firewall to program at
// all) a docker or containerd sandbox accepted network_block_all, address
// lists and byte caps, stored them, showed them on GET, and ran with nothing
// enforcing them (UC-332 block-all exfiltrated over DNS and HTTP, UC-98 a
// denied 1.1.1.1 was reached, UC-179 an allowlist dropped nothing).
//
// The runtime below sends every rule through a real netrules.Manager, built
// the way the daemon builds it: disabled, as SB_ENABLE_NETWORK_RULES=false or
// a non-Linux host leaves it, or enabled over an in-memory rule table. It
// reports NetRulesEnabled the way the docker client does. These tests use
// only identifiers that exist on main, so they run against it unchanged.

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/pkg/docker/netrules"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts"
)

type netRulesRuntime struct {
	*recordingRuntime
	rules *netrules.Manager
}

func (r *netRulesRuntime) NetRulesEnabled() bool { return r.rules.Enabled() }

// Create installs the create-time rules after the container is up, as
// pkg/docker's Client.Create does.
func (r *netRulesRuntime) Create(ctx context.Context, req models.CreateSandboxRequest, id, token string, binds []mounts.ContainerBind) (*models.SandboxRuntimeState, error) {
	st, err := r.recordingRuntime.Create(ctx, req, id, token, binds)
	if err != nil {
		return nil, err
	}
	if req.NetworkBlockAll {
		if err := r.rules.BlockAllEgress(st.ContainerIP); err != nil {
			return nil, err
		}
	}
	if len(req.NetworkAllowOut) > 0 || len(req.NetworkDenyOut) > 0 {
		if err := r.rules.ApplyEgressPolicy(st.ContainerIP, req.NetworkAllowOut, req.NetworkDenyOut); err != nil {
			return nil, err
		}
	}
	return st, nil
}
func (r *netRulesRuntime) ApplyNetworkBlockAll(ip string) error { return r.rules.BlockAllEgress(ip) }
func (r *netRulesRuntime) ClearNetworkBlockEgress(ip string) error {
	return r.rules.ClearBlockAllEgress(ip)
}
func (r *netRulesRuntime) ApplyNetworkBlockIngress(ip string) error {
	return r.rules.BlockAllIngress(ip)
}
func (r *netRulesRuntime) ClearNetworkBlockIngress(ip string) error {
	return r.rules.ClearBlockAllIngress(ip)
}
func (r *netRulesRuntime) ApplyEgressPolicy(ip string, allow, deny []string) error {
	return r.rules.ApplyEgressPolicy(ip, allow, deny)
}
func (r *netRulesRuntime) ClearEgressPolicy(ip string, allow, deny []string) error {
	return r.rules.ClearEgressPolicy(ip, allow, deny)
}
func (r *netRulesRuntime) ApplyEgressHold(ip string) error { return r.rules.HoldEgress(ip) }
func (r *netRulesRuntime) ClearEgressHold(ip string) error { return r.rules.ClearHoldEgress(ip) }

// newNetRulesHarness returns a docker-runtime service whose firewall is on
// (rules land in the returned table) or off (a disabled manager: every rule
// call returns nil and installs nothing).
func newNetRulesHarness(t *testing.T, firewallOn bool) (*Service, *netRulesRuntime, orderedRules) {
	t.Helper()
	table := orderedRules{}
	rules := netrules.NewWithBackend(table)
	if !firewallOn {
		var err error
		if rules, err = netrules.NewWithOptions(false, netrules.BackendExec, ""); err != nil {
			t.Fatal(err)
		}
	}
	rt := &netRulesRuntime{recordingRuntime: &recordingRuntime{}, rules: rules}
	svc, _, _ := newServiceRuntimeHarnessAtPath(t, filepath.Join(t.TempDir(), "state.db"), rt)
	return svc, rt, table
}

// firewallPolicyCreates are the container creates the host firewall
// enforces, each the shape of a live finding or a byte cap.
var firewallPolicyCreates = []struct {
	name  string
	field string
	req   models.CreateSandboxRequest
}{
	{"block-all (UC-332)", "network_block_all", models.CreateSandboxRequest{NetworkBlockAll: true}},
	{"deny list (UC-98)", "network_deny_out", models.CreateSandboxRequest{NetworkDenyOut: []string{"1.1.1.1/32"}}},
	{"CIDR allowlist (UC-179)", "network_allow_out", models.CreateSandboxRequest{NetworkAllowOut: []string{"10.0.0.0/8"}}},
	{"deny everything", "network_deny_out", models.CreateSandboxRequest{NetworkDenyOut: []string{"0.0.0.0/0"}}},
	{"egress byte cap", "network_bytes_out_limit", models.CreateSandboxRequest{NetworkBytesOutLimit: 1 << 20}},
	{"ingress byte cap", "network_bytes_in_limit", models.CreateSandboxRequest{NetworkBytesInLimit: 1 << 20}},
}

// TestCreateRefusesNetworkPolicyWithFirewallOff: every firewall policy is
// refused with a 501-class error naming the field and SB_ENABLE_NETWORK_RULES,
// before the runtime, the store or the capacity budget is touched.
func TestCreateRefusesNetworkPolicyWithFirewallOff(t *testing.T) {
	for _, tc := range firewallPolicyCreates {
		t.Run(tc.name, func(t *testing.T) {
			svc, rt, _ := newNetRulesHarness(t, false)
			req := tc.req
			req.Image = "alpine:3.20"
			_, err := svc.CreateSandbox(context.Background(), req)
			if !errors.Is(err, models.ErrRuntimeNotImplemented) {
				t.Fatalf("create err = %v; want a 501 refusal: the host firewall is off, so nothing would enforce %s", err, tc.field)
			}
			for _, want := range []string{tc.field, "SB_ENABLE_NETWORK_RULES"} {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("err %q does not name %q", err, want)
				}
			}
			if rt.createCalls != 0 {
				t.Fatalf("runtime Create called %d times; the refusal must come before any work", rt.createCalls)
			}
			if got, _ := svc.store.List(context.Background()); len(got) != 0 {
				t.Fatalf("%d sandbox rows stored for a refused create", len(got))
			}
			if snap := svc.admitter.Snapshot(); snap.SandboxesActive != 0 {
				t.Fatalf("refused create left %d capacity reservations", snap.SandboxesActive)
			}
		})
	}
}

// TestCreateEnforcesNetworkPolicyWithFirewallOn: the same creates on a node
// with the firewall are accepted and the rules are really in the table.
func TestCreateEnforcesNetworkPolicyWithFirewallOn(t *testing.T) {
	for _, tc := range firewallPolicyCreates {
		t.Run(tc.name, func(t *testing.T) {
			svc, rt, table := newNetRulesHarness(t, true)
			req := tc.req
			req.Image = "alpine:3.20"
			if _, err := svc.CreateSandbox(context.Background(), req); err != nil {
				t.Fatalf("create on a node with the firewall: %v", err)
			}
			if rt.createCalls != 1 {
				t.Fatalf("runtime Create calls = %d, want 1", rt.createCalls)
			}
			ip := "10.0.0.2"
			switch {
			case req.NetworkBlockAll, len(req.NetworkDenyOut) > 0 && req.NetworkDenyOut[0] == "0.0.0.0/0":
				if table.permits(ip, "8.8.8.8") {
					t.Fatal("block-all sandbox may still reach 8.8.8.8")
				}
			case len(req.NetworkDenyOut) > 0:
				if table.permits(ip, "1.1.1.1") || !table.permits(ip, "8.8.8.8") {
					t.Fatal("deny 1.1.1.1/32 not enforced, or over-blocks")
				}
			case len(req.NetworkAllowOut) > 0:
				if table.permits(ip, "8.8.8.8") || !table.permits(ip, "10.1.2.3") {
					t.Fatal("allowlist 10.0.0.0/8 not enforced")
				}
			}
		})
	}
}

// TestCreateRefusesHostnamePolicyWithFirewallOff: hostname mode is filtered
// by the egress gateway's own table once attached, but the sandbox boots
// behind a firewall block-all until then, and a failed attach holds it with
// a firewall DROP. Without the firewall both are no-ops, so it is refused
// even with a healthy gateway.
func TestCreateRefusesHostnamePolicyWithFirewallOff(t *testing.T) {
	svc, rt, _ := newNetRulesHarness(t, false)
	svc.cfg.EgressFQDNEnabled = true
	svc.SetEgressGateway(newFakeGateway(), nil)
	_, err := svc.CreateSandbox(context.Background(), models.CreateSandboxRequest{Image: "alpine", NetworkAllowOut: []string{"pypi.org"}})
	if !errors.Is(err, models.ErrRuntimeNotImplemented) || !strings.Contains(err.Error(), "SB_ENABLE_NETWORK_RULES") {
		t.Fatalf("hostname create with the firewall off: err = %v, want the firewall refusal", err)
	}
	if rt.createCalls != 0 {
		t.Fatal("runtime must not be called")
	}
}

// TestUpdateNetworkPolicyRefusedWithFirewallOff: a live PUT that would add
// a firewall policy is refused and changes nothing; one that clears the
// policy needs no firewall and still works.
func TestUpdateNetworkPolicyRefusedWithFirewallOff(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newNetRulesHarness(t, false)
	seedPolicySandbox(t, svc, models.Sandbox{ID: "sb-open"})
	for _, req := range []models.NetworkPolicyRequest{
		{NetworkBlockAll: true},
		{NetworkDenyOut: []string{"1.1.1.1/32"}},
		{NetworkAllowOut: []string{"10.0.0.0/8"}},
	} {
		if _, err := svc.UpdateNetworkPolicy(ctx, "sb-open", req); !errors.Is(err, models.ErrRuntimeNotImplemented) {
			t.Fatalf("PUT %+v with the firewall off: err = %v, want the firewall refusal", req, err)
		}
		if _, err := svc.UpdateNetworkLists(ctx, "sb-open", req.NetworkBlockAll, req.NetworkAllowOut, req.NetworkDenyOut); !errors.Is(err, models.ErrRuntimeNotImplemented) {
			t.Fatalf("facade lists %+v with the firewall off: err = %v, want the firewall refusal", req, err)
		}
	}
	got, err := svc.store.Get(ctx, "sb-open")
	if err != nil {
		t.Fatal(err)
	}
	if got.NetworkBlockAll || len(got.NetworkAllowOut) > 0 || len(got.NetworkDenyOut) > 0 {
		t.Fatalf("a refused PUT stored a policy: %+v", got)
	}

	// A sandbox stored with a policy before the firewall went off can
	// always be loosened.
	seedPolicySandbox(t, svc, models.Sandbox{ID: "sb-legacy", NetworkDenyOut: []string{"1.1.1.1/32"}})
	if _, err := svc.UpdateNetworkPolicy(ctx, "sb-legacy", models.NetworkPolicyRequest{}); err != nil {
		t.Fatalf("clearing a policy must not need the firewall: %v", err)
	}
}

// TestSetNetworkLimitsRefusedWithFirewallOff: a byte cap is a firewall DROP
// when crossed, so setting one is refused; lifting caps (0) is not.
func TestSetNetworkLimitsRefusedWithFirewallOff(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newNetRulesHarness(t, false)
	seedPolicySandbox(t, svc, models.Sandbox{ID: "sb-cap"})
	if _, err := svc.SetNetworkLimits(ctx, "sb-cap", 0, 1<<20); !errors.Is(err, models.ErrRuntimeNotImplemented) {
		t.Fatalf("byte cap with the firewall off: err = %v, want the firewall refusal", err)
	}
	if got, _ := svc.store.Get(ctx, "sb-cap"); got.NetworkBytesOutLimit != 0 {
		t.Fatalf("refused cap was stored: %d", got.NetworkBytesOutLimit)
	}
	if _, err := svc.SetNetworkLimits(ctx, "sb-cap", 0, 0); err != nil {
		t.Fatalf("lifting caps must not need the firewall: %v", err)
	}
}

// TestStartRefusesStoredPolicyWithFirewallOff: a sandbox created while the
// firewall was on and stopped, then started after it was turned off, stays
// stopped instead of running open under a policy GET still shows.
func TestStartRefusesStoredPolicyWithFirewallOff(t *testing.T) {
	ctx := context.Background()
	svc, rt, _ := newNetRulesHarness(t, false)
	seedPolicySandbox(t, svc, models.Sandbox{ID: "sb-stopped", Status: models.SandboxStatusStopped, NetworkBlockAll: true})
	if _, err := svc.StartSandbox(ctx, "sb-stopped"); !errors.Is(err, models.ErrRuntimeNotImplemented) {
		t.Fatalf("start with the firewall off: err = %v, want the firewall refusal", err)
	}
	if len(rt.startRefs) != 0 {
		t.Fatalf("container started %v; the refusal must come first", rt.startRefs)
	}
}

// TestMediatedRuntimesKeepPolicyWithFirewallOff: WASM and isolate filter
// egress in their own host-side mediators, so a node without the firewall
// still takes their policies.
func TestMediatedRuntimesKeepPolicyWithFirewallOff(t *testing.T) {
	ctx := context.Background()
	svc, rt, _ := newNetRulesHarness(t, false)
	wasm, iso := newMediator(), newMediator()
	svc.wasm, svc.isolate = wasm, iso
	seedPolicySandbox(t, svc, models.Sandbox{ID: "sb-wasm", Runtime: models.RuntimeWasm, Status: models.SandboxStatusStopped})
	seedPolicySandbox(t, svc, models.Sandbox{ID: "sb-iso", Runtime: models.RuntimeIsolate})
	if _, err := svc.UpdateNetworkPolicy(ctx, "sb-wasm", models.NetworkPolicyRequest{NetworkBlockAll: true}); err != nil || !wasm.blocked["sb-wasm"] {
		t.Fatalf("wasm block-all: err=%v blocked=%v", err, wasm.blocked)
	}
	if _, err := svc.UpdateNetworkPolicy(ctx, "sb-iso", models.NetworkPolicyRequest{NetworkDenyOut: []string{"1.1.1.1/32"}}); err != nil {
		t.Fatalf("isolate deny list: %v", err)
	}
	if _, err := svc.SetNetworkLimits(ctx, "sb-wasm", 0, 1<<20); err != nil {
		t.Fatalf("wasm byte cap: %v", err)
	}

	wrt := &recordingRuntime{}
	svc.cfg.EnableWasm = true
	svc.admitter = nil
	svc.SetWasmRuntime(wrt)
	resp, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{Runtime: models.RuntimeWasm, ModuleRef: "m.wasm",
		NetworkBlockAll: true, NetworkBytesOutLimit: 1 << 20})
	if err != nil {
		t.Fatalf("wasm create with block-all on a node without the firewall: %v", err)
	}
	if !resp.NetworkBlockAll || wrt.createCalls != 1 || rt.createCalls != 0 {
		t.Fatalf("wasm create: block_all=%v wasm calls=%d docker calls=%d", resp.NetworkBlockAll, wrt.createCalls, rt.createCalls)
	}
}
