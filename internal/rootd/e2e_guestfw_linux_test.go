//go:build linux

package rootd

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
	"github.com/aerol-ai/microvm/pkg/docker/netrules"
)

// The Firecracker guests' firewall on a live helper (M1 PR 14), in the PR
// 14 box: the helper runs as root, these calls come as the agent's uid over
// its socket, and the box sends packets between network namespaces that
// stand in for guests (a veth named as a TAP, its far end the guest's
// address). AEROL_E2E_GUEST_PHASE names one step; the box runs them in
// turn and probes between them.

// guestPhase is the step a live run asks for, or "" (skip).
func guestPhase(t *testing.T) (rootdpb.RootHelperClient, context.Context, string) {
	t.Helper()
	sock, phase := os.Getenv("AEROL_E2E_HELPER_SOCKET"), os.Getenv("AEROL_E2E_GUEST_PHASE")
	if sock == "" || phase == "" {
		t.Skip("a live run: set AEROL_E2E_HELPER_SOCKET and AEROL_E2E_GUEST_PHASE")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	t.Cleanup(cancel)
	return rootdpb.NewRootHelperClient(dialSocket(t, sock)), ctx, phase
}

const (
	e2eGuest      = "172.16.0.10" // fctap2's guest
	e2eOtherGuest = "172.16.0.14" // fctap3's guest
)

func TestE2EGuestFirewall(t *testing.T) {
	c, ctx, phase := guestPhase(t)
	op := func(o rootdpb.SandboxRulesOp, ip string, allow, deny []string) {
		t.Helper()
		if _, err := c.GuestRules(ctx, &rootdpb.GuestRulesRequest{GuestIp: ip, Op: o, AllowCidrs: allow, DenyCidrs: deny}); err != nil {
			t.Fatalf("%v on %s: %v", o, ip, err)
		}
	}
	switch phase {
	case "setup":
		if _, err := c.EnsureGuestFirewall(ctx, &rootdpb.EnsureGuestFirewallRequest{}); err != nil {
			t.Fatalf("EnsureGuestFirewall: %v", err)
		}
		if _, err := c.SetGuestEgressFloor(ctx, &rootdpb.SetEgressFloorRequest{Cidrs: []string{"10.251.0.0/24"}}); err != nil {
			t.Fatalf("SetGuestEgressFloor: %v", err)
		}
		if _, err := c.SetGuestNodeGuard(ctx, &rootdpb.SetNodeGuardRequest{Allow: []*rootdpb.NodePort{{Proto: "tcp", Port: 15080}}}); err != nil {
			t.Fatalf("SetGuestNodeGuard: %v", err)
		}
		t.Log("the guests' firewall: set up, floor 10.251.0.0/24 and the metadata endpoints, node port tcp/15080")
	case "policy":
		op(rootdpb.SandboxRulesOp_SANDBOX_RULES_OP_APPLY_EGRESS_POLICY, e2eGuest, nil, []string{"10.250.0.2/32"})
		t.Logf("%s: egress policy deny 10.250.0.2/32", e2eGuest)
	case "block":
		op(rootdpb.SandboxRulesOp_SANDBOX_RULES_OP_CLEAR_EGRESS_POLICY, e2eGuest, nil, nil)
		op(rootdpb.SandboxRulesOp_SANDBOX_RULES_OP_BLOCK_EGRESS, e2eGuest, nil, nil)
		t.Logf("%s: policy cleared, egress blocked", e2eGuest)
	case "clear":
		for _, o := range []rootdpb.SandboxRulesOp{rootdpb.SandboxRulesOp_SANDBOX_RULES_OP_CLEAR_BLOCK_EGRESS,
			rootdpb.SandboxRulesOp_SANDBOX_RULES_OP_CLEAR_BLOCK_INGRESS, rootdpb.SandboxRulesOp_SANDBOX_RULES_OP_CLEAR_HOLD_EGRESS,
			rootdpb.SandboxRulesOp_SANDBOX_RULES_OP_CLEAR_EGRESS_POLICY} {
			op(o, e2eGuest, nil, nil)
		}
		t.Logf("%s: every rule cleared, as a destroy clears them", e2eGuest)
	case "refuse":
		e2eGuestRefusals(t, c, ctx)
	case "fence":
		// The containerd network first: the fence is the sandboxes'
		// firewall's, which opens on the helper's CNI config.
		if _, err := c.EnsureHostNetwork(ctx, &rootdpb.EnsureHostNetworkRequest{}); err != nil {
			t.Fatalf("EnsureHostNetwork: %v", err)
		}
		resp, err := c.EnsureHost(ctx, &rootdpb.EnsureHostRequest{})
		if err != nil {
			t.Fatalf("EnsureHost: %v", err)
		}
		t.Logf("fence: bridge %q, covers the TAPs %v, TAPs %q", resp.GetIpv6FenceError(), resp.GetFencesFirecracker(), resp.GetFirecrackerIpv6FenceError())
		if !resp.GetFencesFirecracker() || resp.GetFirecrackerIpv6FenceError() != "" {
			t.Fatalf("the fence does not cover the TAPs: %v", resp)
		}
	case "timing":
		e2eGuestTiming(t, c, ctx)
	default:
		t.Fatalf("phase %q", phase)
	}
}

// e2eGuestRefusals: a broken agent's asks, each refused by its rule.
func e2eGuestRefusals(t *testing.T, c rootdpb.RootHelperClient, ctx context.Context) {
	block := rootdpb.SandboxRulesOp_SANDBOX_RULES_OP_BLOCK_EGRESS
	policy := rootdpb.SandboxRulesOp_SANDBOX_RULES_OP_APPLY_EGRESS_POLICY
	for _, tc := range []struct {
		name string
		call func() error
		code codes.Code
	}{
		{"a TAP's host end (the node's address)", func() error {
			_, err := c.GuestRules(ctx, &rootdpb.GuestRulesRequest{GuestIp: "172.16.0.9", Op: block})
			return err
		}, codes.InvalidArgument},
		{"an address outside the TAP base", func() error {
			_, err := c.GuestRules(ctx, &rootdpb.GuestRulesRequest{GuestIp: "10.250.0.1", Op: block})
			return err
		}, codes.InvalidArgument},
		{"rule text for an address", func() error {
			_, err := c.GuestRules(ctx, &rootdpb.GuestRulesRequest{GuestIp: e2eGuest + " -j ACCEPT", Op: block})
			return err
		}, codes.InvalidArgument},
		{"rule text for a CIDR", func() error {
			_, err := c.GuestRules(ctx, &rootdpb.GuestRulesRequest{GuestIp: e2eGuest, Op: policy, AllowCidrs: []string{"0.0.0.0/0 -j ACCEPT"}})
			return err
		}, codes.InvalidArgument},
		{"an op the helper does not have", func() error {
			_, err := c.GuestRules(ctx, &rootdpb.GuestRulesRequest{GuestIp: e2eGuest, Op: 42})
			return err
		}, codes.InvalidArgument},
		{"a node port past the helper's own", func() error {
			_, err := c.SetGuestNodeGuard(ctx, &rootdpb.SetNodeGuardRequest{Allow: []*rootdpb.NodePort{{Proto: "tcp", Port: 22}}})
			return err
		}, codes.PermissionDenied},
		{"rule text on the floor", func() error {
			_, err := c.SetGuestEgressFloor(ctx, &rootdpb.SetEgressFloorRequest{Cidrs: []string{"10.0.0.0/8 -j ACCEPT"}})
			return err
		}, codes.InvalidArgument},
	} {
		err := tc.call()
		reason, refused := rootdpb.RefusalReason(err)
		t.Logf("%s: %v %q", tc.name, status.Code(err), reason)
		if !refused || status.Code(err) != tc.code {
			t.Errorf("%s = %v, want a refusal %v", tc.name, err, tc.code)
		}
	}
}

// e2eGuestTiming is one round of a guest's rules through the helper: a
// create's egress policy (allow two networks, deny one) and a destroy's
// four clears. TestGuestFirewallSingleModeTiming is the same round as
// single mode does it.
func e2eGuestTiming(t *testing.T, c rootdpb.RootHelperClient, ctx context.Context) {
	// sandboxd's client keeps its connection: the timed calls ride one
	// already made, as a create's do.
	if _, err := c.Version(ctx, &rootdpb.VersionRequest{}); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	lap := func() time.Duration { d := time.Since(start); start = time.Now(); return d }
	if _, err := c.GuestRules(ctx, &rootdpb.GuestRulesRequest{GuestIp: e2eOtherGuest, Op: rootdpb.SandboxRulesOp_SANDBOX_RULES_OP_APPLY_EGRESS_POLICY,
		AllowCidrs: []string{"10.250.0.0/24", "1.1.1.1/32"}, DenyCidrs: []string{"10.250.0.2/32"}}); err != nil {
		t.Fatal(err)
	}
	tCreate := lap()
	for _, o := range []rootdpb.SandboxRulesOp{rootdpb.SandboxRulesOp_SANDBOX_RULES_OP_CLEAR_BLOCK_EGRESS,
		rootdpb.SandboxRulesOp_SANDBOX_RULES_OP_CLEAR_BLOCK_INGRESS, rootdpb.SandboxRulesOp_SANDBOX_RULES_OP_CLEAR_HOLD_EGRESS,
		rootdpb.SandboxRulesOp_SANDBOX_RULES_OP_CLEAR_EGRESS_POLICY} {
		if _, err := c.GuestRules(ctx, &rootdpb.GuestRulesRequest{GuestIp: e2eOtherGuest, Op: o}); err != nil {
			t.Fatal(err)
		}
	}
	tDestroy := lap()
	fmt.Printf("timing\tsplit\tcreate=%.3f\tdestroy=%.3f\n", msOf(tCreate), msOf(tDestroy))
}

func msOf(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }

// TestGuestFirewallSingleModeTiming is e2eGuestTiming's round as privilege
// mode single does it: as root, in-process, with sandboxd's own netrules
// manager on the guests' chain (pkg/daemon wireFirecrackerEgress), the
// driver's calls in its order (applyCreateEgress, clearGuestRules).
func TestGuestFirewallSingleModeTiming(t *testing.T) {
	if os.Getenv("AEROL_E2E_GUEST_SINGLE") == "" || os.Geteuid() != 0 {
		t.Skip("a live run as root: set AEROL_E2E_GUEST_SINGLE")
	}
	m, err := netrules.NewWithOptions(true, "netlink", netrules.ChainAerolvmFC)
	if err != nil {
		t.Fatal(err)
	}
	m.SetBridgeSubnet("172.16.0.0/20")
	if err := m.EnsureChain(); err != nil {
		t.Fatal(err)
	}
	_ = m.PrepareBlockSets()
	start := time.Now()
	lap := func() time.Duration { d := time.Since(start); start = time.Now(); return d }
	allow, deny := []string{"10.250.0.0/24", "1.1.1.1/32"}, []string{"10.250.0.2/32"}
	if err := m.ApplyEgressPolicy(e2eOtherGuest, allow, deny); err != nil {
		t.Fatal(err)
	}
	tCreate := lap()
	for _, err := range []error{m.ClearBlockAllEgress(e2eOtherGuest), m.ClearBlockAllIngress(e2eOtherGuest),
		m.ClearHoldEgress(e2eOtherGuest), m.ClearEgressPolicy(e2eOtherGuest, allow, deny)} {
		if err != nil {
			t.Fatal(err)
		}
	}
	tDestroy := lap()
	fmt.Printf("timing\tsingle\tcreate=%.3f\tdestroy=%.3f\n", msOf(tCreate), msOf(tDestroy))
}
