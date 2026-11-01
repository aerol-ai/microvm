package service

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
)

// npLogBuffer is a log sink safe for the service's concurrent loggers.
type npLogBuffer struct {
	mu sync.Mutex
	b  strings.Builder
}

func (l *npLogBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *npLogBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func captureServiceLogs(svc *Service) *npLogBuffer {
	logs := &npLogBuffer{}
	svc.logger = slog.New(slog.NewTextHandler(logs, nil))
	return logs
}

// TestUnenforcedPolicyErrorShape: the refusal carries its own sentinel (for
// the network_policy_unenforced code) and ErrRuntimeNotImplemented (501 on
// every facade), names each refused field once, and both flags.
func TestUnenforcedPolicyErrorShape(t *testing.T) {
	svc, _, _ := newNetRulesHarness(t, false)
	_, err := svc.CreateSandbox(context.Background(), models.CreateSandboxRequest{
		Image: "alpine", NetworkBlockAll: true, NetworkBytesInLimit: 1, NetworkBytesOutLimit: 1,
	})
	if !errors.Is(err, ErrNetworkPolicyUnenforced) || !errors.Is(err, models.ErrRuntimeNotImplemented) {
		t.Fatalf("err = %v, want ErrNetworkPolicyUnenforced and ErrRuntimeNotImplemented", err)
	}
	msg := err.Error()
	for _, want := range []string{"network_block_all, network_bytes_in_limit, network_bytes_out_limit refused", `runtime "docker"`, "SB_ENABLE_NETWORK_RULES", "SB_ALLOW_UNENFORCED_NETWORK_POLICY=true"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("message %q lacks %q", msg, want)
		}
	}
}

// TestFirewallPolicyFieldsCoversEveryPolicy lists each field a container
// enforces with the firewall, by wire name, and nothing for a create that
// asks for none.
func TestFirewallPolicyFieldsCoversEveryPolicy(t *testing.T) {
	if got := firewallPolicyFields(&models.CreateSandboxRequest{Image: "alpine", Env: map[string]string{"A": "b"}}); len(got) != 0 {
		t.Fatalf("plain create fields = %v, want none", got)
	}
	all := &models.Sandbox{
		NetworkBlockAll: true, NetworkAllowOut: []string{"pypi.org"}, NetworkDenyOut: []string{"1.1.1.1/32"},
		EgressProfiles: []string{"builtin:pypi"}, NetworkEgressMode: models.NetworkEgressModeLearn,
		NetworkEgressRules:  []models.EgressRule{{Host: "pypi.org", Methods: []string{"GET"}}},
		NetworkBytesInLimit: 1, NetworkBytesOutLimit: 1,
	}
	want := "network_block_all,network_allow_out,network_deny_out,egress_profiles,network_egress_mode,network_egress_rules,network_bytes_in_limit,network_bytes_out_limit"
	if got := strings.Join(sandboxFirewallFields(all), ","); got != want {
		t.Fatalf("fields = %s\nwant     %s", got, want)
	}
}

// TestAllowUnenforcedOptInAcceptsAndWarns: with the operator's local-dev
// opt-in every refused path accepts again, each logs a per-sandbox warning,
// and GET says the policy is unenforced.
func TestAllowUnenforcedOptInAcceptsAndWarns(t *testing.T) {
	ctx := context.Background()
	svc, rt, _ := newNetRulesHarness(t, false)
	svc.cfg.AllowUnenforcedNetworkPolicy = true
	logs := captureServiceLogs(svc)

	resp, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{Image: "alpine", NetworkDenyOut: []string{"1.1.1.1/32"}})
	if err != nil {
		t.Fatalf("create under the opt-in: %v", err)
	}
	if rt.createCalls != 1 {
		t.Fatalf("runtime Create calls = %d, want 1", rt.createCalls)
	}
	if out := logs.String(); !strings.Contains(out, "NOT enforced") || !strings.Contains(out, "sandbox_id="+resp.ID) || !strings.Contains(out, "op=create") || !strings.Contains(out, "fields=network_deny_out") {
		t.Fatalf("no per-create warning naming the sandbox:\n%s", out)
	}
	got, err := svc.GetSandbox(ctx, resp.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.EgressStatus != EgressStatusUnenforced {
		t.Fatalf("egress_status = %q, want %q", got.EgressStatus, EgressStatusUnenforced)
	}

	pol, err := svc.UpdateNetworkPolicy(ctx, resp.ID, models.NetworkPolicyRequest{NetworkBlockAll: true})
	if err != nil {
		t.Fatalf("policy PUT under the opt-in: %v", err)
	}
	if pol.EgressStatus != EgressStatusUnenforced {
		t.Fatalf("PUT egress_status = %q, want %q", pol.EgressStatus, EgressStatusUnenforced)
	}
	if _, err := svc.SetNetworkLimits(ctx, resp.ID, 0, 1<<20); err != nil {
		t.Fatalf("byte cap under the opt-in: %v", err)
	}
	seedPolicySandbox(t, svc, models.Sandbox{ID: "sb-stopped-optin", Status: models.SandboxStatusStopped, NetworkBlockAll: true})
	if _, err := svc.StartSandbox(ctx, "sb-stopped-optin"); err != nil {
		t.Fatalf("start under the opt-in: %v", err)
	}
	out := logs.String()
	for _, op := range []string{"op=update_network_policy", "op=set_network_limits", "op=start"} {
		if !strings.Contains(out, op) {
			t.Fatalf("no %s warning:\n%s", op, out)
		}
	}
}

// TestEgressStatusUnenforcedOnlyWithoutFirewall: a CIDR sandbox shows no
// status where the firewall enforces it, "unenforced" where it doesn't, and
// a WASM sandbox, filtered by its own mediator, never does.
func TestEgressStatusUnenforcedOnlyWithoutFirewall(t *testing.T) {
	ctx := context.Background()
	on, _, _ := newNetRulesHarness(t, true)
	seedPolicySandbox(t, on, models.Sandbox{ID: "sb-cidr", NetworkDenyOut: []string{"1.1.1.1/32"}})
	if got, _ := on.GetSandbox(ctx, "sb-cidr"); got.EgressStatus != "" {
		t.Fatalf("firewall on: egress_status = %q, want empty", got.EgressStatus)
	}

	off, _, _ := newNetRulesHarness(t, false)
	seedPolicySandbox(t, off, models.Sandbox{ID: "sb-cidr", NetworkDenyOut: []string{"1.1.1.1/32"}})
	seedPolicySandbox(t, off, models.Sandbox{ID: "sb-open"})
	off.wasm = newMediator()
	seedPolicySandbox(t, off, models.Sandbox{ID: "sb-wasm", Runtime: models.RuntimeWasm, NetworkBlockAll: true})
	for id, want := range map[string]string{"sb-cidr": EgressStatusUnenforced, "sb-open": "", "sb-wasm": ""} {
		got, err := off.GetSandbox(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if got.EgressStatus != want {
			t.Fatalf("%s: egress_status = %q, want %q", id, got.EgressStatus, want)
		}
	}
}

// TestNetRulesChecksTrustWhatTheyCannotResolve: a runtime that doesn't
// report (a test double, never a production driver) is trusted, and a
// sandbox whose runtime isn't wired here is left to the caller, which fails
// on it with its own error.
func TestNetRulesChecksTrustWhatTheyCannotResolve(t *testing.T) {
	if !netRulesEnabled(&recordingRuntime{}) {
		t.Fatal("a runtime without NetRulesEnabled is a double that enforces; it must be trusted")
	}
	svc, _, _ := newNetRulesHarness(t, false)
	svc.cfg.ContainerEngine = models.ContainerEngineContainerd
	orphan := &models.Sandbox{ID: "sb-ctd", Runtime: models.RuntimeDocker, Engine: models.ContainerEngineContainerd, NetworkBlockAll: true}
	if err := svc.checkSandboxNetRules(orphan, "start", sandboxFirewallFields(orphan)); err != nil {
		t.Fatalf("unresolvable runtime: err = %v, want nil (the caller reports it)", err)
	}
	if svc.sandboxNetRulesOff(orphan) {
		t.Fatal("unresolvable runtime must not read as unenforced")
	}
	// The create path skips the check when the host engine isn't wired and
	// fails on the engine instead.
	if _, err := svc.CreateSandbox(context.Background(), models.CreateSandboxRequest{Image: "alpine", NetworkBlockAll: true}); !errors.Is(err, models.ErrContainerEngineNotRegistered) {
		t.Fatalf("create with no containerd driver: err = %v, want ErrContainerEngineNotRegistered", err)
	}
}

// TestDefaultsAndReplaysHeldToTheFirewall: the check sees the effective
// request, so an operator's block-all default, which the caller never
// wrote, and a failover replay of a stored spec are refused on a node
// without the firewall, not started open.
func TestDefaultsAndReplaysHeldToTheFirewall(t *testing.T) {
	ctx := context.Background()
	svc, rt, _ := newNetRulesHarness(t, false)
	svc.SetEgressOperator(operatorWatcher(t, "version: 1\ndefault_policy: {mode: block_all}\n"))
	if _, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{Image: "alpine"}); !errors.Is(err, ErrNetworkPolicyUnenforced) || !strings.Contains(err.Error(), "network_block_all") {
		t.Fatalf("operator default on a node without the firewall: err = %v", err)
	}
	svc.SetEgressOperator(operatorWatcher(t, "version: 1\n"))
	if _, err := svc.CreateSandboxWithID(contextWithStoredSpecReplay(ctx), models.CreateSandboxRequest{Image: "alpine", NetworkDenyOut: []string{"1.1.1.1/32"}}, "sb-replay"); !errors.Is(err, ErrNetworkPolicyUnenforced) {
		t.Fatalf("failover replay on a node without the firewall: err = %v", err)
	}
	if rt.createCalls != 0 {
		t.Fatalf("runtime Create calls = %d, want 0", rt.createCalls)
	}
}
