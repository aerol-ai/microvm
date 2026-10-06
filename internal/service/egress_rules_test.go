package service

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/aerol-ai/microvm/pkg/egresspolicy"
	"github.com/aerol-ai/microvm/pkg/models"
)

// Method and path rules (plans/egress-domain-filtering.md §5.9, P3-1).

var getOnly = []models.EgressRule{{Host: "plain.example.org", Methods: []string{"GET"}, Paths: []string{"/v1/**"}}}

func TestCreateWithEgressRules(t *testing.T) {
	svc, gw, _ := newPolicyHarness(t)
	ctx := ownerCtx("acct")
	resp, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{Image: "alpine", NetworkAllowOut: []string{"plain.example.org"}, NetworkEgressRules: getOnly})
	if err != nil {
		t.Fatal(err)
	}
	if rules := gw.attached[resp.ID].Rules; len(rules) != 1 || rules[0].Host != "plain.example.org" || rules[0].Methods[0] != "GET" {
		t.Fatalf("gateway rules = %+v", rules)
	}
	got, err := svc.GetSandbox(ctx, resp.ID)
	if err != nil || len(got.NetworkEgressRules) != 1 || len(resp.NetworkEgressRules) != 1 {
		t.Fatalf("GET rules = %+v, create = %+v, %v", got.NetworkEgressRules, resp.NetworkEgressRules, err)
	}
	row, _ := svc.store.Get(ctx, resp.ID)
	if spec, err := svc.specFromSandbox(ctx, row); err != nil || len(spec.NetworkEgressRules) != 1 {
		t.Fatalf("a replay keeps the rules: %+v %v", spec, err)
	}
	if es, _ := svc.store.GetEgressState(ctx, resp.ID); es.InspectCA {
		t.Fatal("no inspect rule, no CA")
	}

	for name, tc := range map[string]struct {
		req  models.CreateSandboxRequest
		want error
	}{
		"rule for a host not allowed": {models.CreateSandboxRequest{Image: "alpine", NetworkAllowOut: []string{"plain.example.org"},
			NetworkEgressRules: []models.EgressRule{{Host: "evil.example.net"}}}, egresspolicy.ErrInvalid},
		"firecracker": {models.CreateSandboxRequest{Image: "alpine", Runtime: models.RuntimeFirecracker, NetworkAllowOut: []string{"plain.example.org"},
			NetworkEgressRules: getOnly}, models.ErrRuntimeNotImplemented},
	} {
		if _, err := svc.CreateSandbox(ctx, tc.req); !errors.Is(err, tc.want) {
			t.Fatalf("%s: err = %v, want %v", name, err, tc.want)
		}
	}
}

func TestUpdateNetworkPolicyRules(t *testing.T) {
	svc, gw, _ := newPolicyHarness(t)
	ctx := ownerCtx("acct")
	seedPolicySandbox(t, svc, models.Sandbox{OwnerRef: "acct"})
	req := models.NetworkPolicyRequest{NetworkAllowOut: []string{"plain.example.org"}, NetworkEgressRules: getOnly}
	got, err := svc.UpdateNetworkPolicy(ctx, "sb-pol", req)
	if err != nil || len(got.NetworkEgressRules) != 1 || len(gw.attached["sb-pol"].Rules) != 1 {
		t.Fatalf("policy = %+v %v, gateway %+v", got, err, gw.attached["sb-pol"])
	}
	n := len(gw.attached)
	if _, err := svc.UpdateNetworkPolicy(ctx, "sb-pol", req); err != nil || len(gw.attached) != n {
		t.Fatalf("the same rules again must be a no-op: %v", err)
	}
	// A facade list update keeps the rules it can't see.
	if _, err := svc.UpdateNetworkLists(ctx, "sb-pol", false, []string{"plain.example.org", "pypi.org"}, nil); err != nil {
		t.Fatal(err)
	}
	if sb, _ := svc.store.Get(ctx, "sb-pol"); len(sb.NetworkEgressRules) != 1 {
		t.Fatalf("facade update dropped the rules: %+v", sb.NetworkEgressRules)
	}
	// The facade can't drop the host a rule refines.
	if _, err := svc.UpdateNetworkLists(ctx, "sb-pol", false, []string{"pypi.org"}, nil); !errors.Is(err, egresspolicy.ErrInvalid) {
		t.Fatalf("facade update orphaning a rule: %v", err)
	}
	// Trusting the CA is set up at create: adding inspection later is 409.
	inspect := []models.EgressRule{{Host: "plain.example.org", Inspect: true}}
	if _, err := svc.UpdateNetworkPolicy(ctx, "sb-pol", models.NetworkPolicyRequest{NetworkAllowOut: []string{"plain.example.org"}, NetworkEgressRules: inspect}); !errors.Is(err, ErrEgressInspectRecreate) {
		t.Fatalf("inspect on a sandbox created without it: %v", err)
	}
	// Clearing them.
	if got, err := svc.UpdateNetworkPolicy(ctx, "sb-pol", models.NetworkPolicyRequest{NetworkAllowOut: []string{"plain.example.org"}}); err != nil || len(got.NetworkEgressRules) != 0 {
		t.Fatalf("clear = %+v %v", got, err)
	}
}

// TestEgressRulesMediatedRuntimes: isolate proxies plaintext requests, so
// it takes every rule, inspect included; WASM sees no requests and refuses
// them.
func TestEgressRulesMediatedRuntimes(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newPolicyHarness(t)
	wasm, iso := newMediator(), newMediator()
	svc.wasm, svc.isolate = wasm, iso
	seedPolicySandbox(t, svc, models.Sandbox{ID: "sb-wasm", Runtime: models.RuntimeWasm, Status: models.SandboxStatusStopped})
	seedPolicySandbox(t, svc, models.Sandbox{ID: "sb-iso", Runtime: models.RuntimeIsolate})
	svc.cfg.EgressFQDNEnabled = false
	inspect := []models.EgressRule{{Host: "api.example.org", Inspect: true, Methods: []string{"GET"}}}
	if _, err := svc.UpdateNetworkPolicy(ctx, "sb-iso", models.NetworkPolicyRequest{NetworkAllowOut: []string{"api.example.org"}, NetworkEgressRules: inspect}); err != nil {
		t.Fatal(err)
	}
	if r := iso.rules["sb-iso"]; len(r) != 1 || !r[0].Inspect {
		t.Fatalf("isolate rules = %+v", r)
	}
	if _, err := svc.UpdateNetworkPolicy(ctx, "sb-wasm", models.NetworkPolicyRequest{NetworkAllowOut: []string{"plain.example.org"}, NetworkEgressRules: getOnly}); !errors.Is(err, models.ErrRuntimeNotImplemented) {
		t.Fatalf("wasm rules: %v", err)
	}
	wrt := &recordingRuntime{}
	svc.cfg.EnableWasm = true
	svc.admitter = nil
	svc.SetWasmRuntime(wrt)
	if _, err := svc.createWasmSandbox(ctx, models.CreateSandboxRequest{Runtime: models.RuntimeWasm, ModuleRef: "m.wasm",
		NetworkAllowOut: []string{"plain.example.org"}, NetworkEgressRules: getOnly}, ""); !errors.Is(err, models.ErrRuntimeNotImplemented) {
		t.Fatalf("wasm create with rules: %v", err)
	}
}

// TestReapplyKeepsEgressRules: a profile change re-applies the effective
// list and keeps the rules.
func TestReapplyKeepsEgressRules(t *testing.T) {
	svc, gw, _ := newPolicyHarness(t)
	ctx := ownerCtx("acct")
	putProfile(t, svc, ctx, "plain", "plain.example.org")
	seedPolicySandbox(t, svc, models.Sandbox{OwnerRef: "acct"})
	if _, err := svc.UpdateNetworkPolicy(ctx, "sb-pol", models.NetworkPolicyRequest{EgressProfiles: []string{"plain"}, NetworkEgressRules: getOnly}); err != nil {
		t.Fatal(err)
	}
	putProfile(t, svc, ctx, "plain", "plain.example.org", "pypi.org")
	svc.reapplyEgressProfiles(ctx)
	spec := gw.attached["sb-pol"]
	if !slices.Contains(spec.AllowOut, "pypi.org") || len(spec.Rules) != 1 {
		t.Fatalf("re-applied spec = %+v", spec)
	}
}

var gitOnly = []models.EgressRule{{Host: "github.com", Ports: []uint16{22}, Binaries: []string{"/usr/bin/git"}}}

// TestEgressRulesBinaries (P3-3): a runc sandbox's gateway spec carries the
// init pid to trace from; gVisor and isolate refuse binaries.
func TestEgressRulesBinaries(t *testing.T) {
	svc, gw, rt := newPolicyHarness(t)
	rt.pid = 4242
	ctx := ownerCtx("acct")
	resp, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{Image: "alpine", NetworkAllowOut: []string{"github.com:22"}, NetworkEgressRules: gitOnly})
	if err != nil {
		t.Fatal(err)
	}
	if spec := gw.attached[resp.ID]; spec.Pid != 4242 || len(spec.Rules) != 1 || spec.Rules[0].Binaries[0] != "/usr/bin/git" {
		t.Fatalf("gateway spec = %+v", spec)
	}
	specs, err := svc.localEgressSpecs(context.Background())
	if err != nil || len(specs) != 1 || specs[0].Pid != 4242 {
		t.Fatalf("resync specs = %+v %v", specs, err)
	}
	// No pid: traced flows are refused at the gateway, never guessed.
	rt.pidErr = errors.New("not running")
	if specs, _ := svc.localEgressSpecs(context.Background()); specs[0].Pid != 0 {
		t.Fatalf("pid without a running task = %d", specs[0].Pid)
	}
	if svc.egressPid(ctx, &models.Sandbox{ID: "x"}) != 0 {
		t.Fatal("no rules, no pid")
	}

	if _, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{Image: "alpine", Runtime: models.RuntimeGvisor, NetworkAllowOut: []string{"github.com:22"},
		NetworkEgressRules: gitOnly}); !errors.Is(err, models.ErrRuntimeNotImplemented) {
		t.Fatalf("gVisor: %v", err)
	}
	if _, err := svc.createIsolateSandbox(ctx, models.CreateSandboxRequest{Runtime: models.RuntimeIsolate, ModuleRef: "b", NetworkAllowOut: []string{"github.com:22"},
		NetworkEgressRules: gitOnly}, ""); !errors.Is(err, models.ErrRuntimeNotImplemented) {
		t.Fatalf("isolate create: %v", err)
	}
	seedPolicySandbox(t, svc, models.Sandbox{ID: "sb-iso", Runtime: models.RuntimeIsolate})
	seedPolicySandbox(t, svc, models.Sandbox{ID: "sb-gv", Runtime: models.RuntimeGvisor})
	svc.isolate = newMediator()
	for _, id := range []string{"sb-iso", "sb-gv"} {
		if _, err := svc.UpdateNetworkPolicy(context.Background(), id, models.NetworkPolicyRequest{NetworkAllowOut: []string{"github.com:22"}, NetworkEgressRules: gitOnly}); !errors.Is(err, models.ErrRuntimeNotImplemented) {
			t.Fatalf("%s PUT: %v", id, err)
		}
	}
}
