package rootd

import (
	"errors"
	"net/netip"
	"slices"
	"testing"
	"time"

	"google.golang.org/grpc/codes"

	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
	"github.com/aerol-ai/microvm/internal/rootpolicy"
)

// TestFirewallHostCalls: the host step answers the fence's state and
// starts the re-assert timer; the node guard and the floor pass their
// rules, canonical, or are refused by name.
func TestFirewallHostCalls(t *testing.T) {
	withNodeDNS(t, "10.0.1.5")
	fw := newFakeFirewall()
	r := newRig(t, func(_ *Config, o *Options) {
		o.Network, o.Firewall, o.reassertEvery = newFakeNet(), fw, 5*time.Millisecond
	})
	c := rootdpb.NewRootHelperClient(r.conn)
	ctx := callCtx(t)
	fw.fence = errors.New("no table")
	resp, err := c.EnsureHost(ctx, &rootdpb.EnsureHostRequest{})
	if err != nil || resp.GetIpv6FenceError() != "no table" {
		t.Fatalf("EnsureHost = %v, %v", resp, err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for !slices.Contains(fw.recorded(), "reassert") {
		if time.Now().After(deadline) {
			t.Fatal("the re-assert timer never ran")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if _, err := c.SetNodeGuard(ctx, &rootdpb.SetNodeGuardRequest{Allow: []*rootdpb.NodePort{{Proto: "tcp", Port: 15080}, {Proto: "udp", Port: 53, Dst: "10.0.1.5"}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.SetEgressFloor(ctx, &rootdpb.SetEgressFloorRequest{Cidrs: []string{"10.20.1.2/16"}}); err != nil {
		t.Fatal(err)
	}
	if got := fw.recorded(); !slices.Contains(got, "guard [{tcp 15080 } {udp 53 10.0.1.5}]") || !slices.Contains(got, "floor [10.20.0.0/16]") {
		t.Fatalf("calls %q", got)
	}
	_, err = c.SetNodeGuard(ctx, &rootdpb.SetNodeGuardRequest{Allow: []*rootdpb.NodePort{{Proto: "icmp", Port: 1}}})
	wantRefusal(t, r, err, codes.InvalidArgument, string(rootpolicy.RuleNodePort))
	_, err = c.SetEgressFloor(ctx, &rootdpb.SetEgressFloorRequest{Cidrs: []string{"10.0.0.0/8 -j ACCEPT"}})
	wantRefusal(t, r, err, codes.InvalidArgument, string(rootpolicy.RuleCIDR))
	// A kernel failure is the helper's, not a refusal.
	fw.fail["guard"], fw.fail["floor"], fw.fail["ensure"] = errors.New("netlink"), errors.New("netlink"), errors.New("netlink")
	_, err = c.SetNodeGuard(ctx, &rootdpb.SetNodeGuardRequest{})
	wantCode(t, err, codes.Internal)
	_, err = c.SetEgressFloor(ctx, &rootdpb.SetEgressFloorRequest{})
	wantCode(t, err, codes.Internal)
	_, err = c.EnsureHost(ctx, &rootdpb.EnsureHostRequest{})
	wantCode(t, err, codes.Internal)
}

// TestReassertPace: each firewall keeps the re-assert pace it was built
// with (its timer's goroutine reads it, so nothing changes it after), and
// a server built without one takes the 30 s default.
func TestReassertPace(t *testing.T) {
	for _, tc := range []struct {
		name  string
		every time.Duration
		want  time.Duration
	}{
		{"unset", 0, defaultReassertEvery},
		{"below zero", -time.Second, defaultReassertEvery},
		{"set", 5 * time.Millisecond, 5 * time.Millisecond},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := reassertPace(tc.every); got != tc.want {
				t.Fatalf("reassertPace(%v) = %v, want %v", tc.every, got, tc.want)
			}
		})
	}
	r, _, _, _, _ := guestRig(t)
	if r.srv.fw.every != defaultReassertEvery || r.srv.gf.every != defaultReassertEvery {
		t.Fatalf("paces %v and %v, want %v", r.srv.fw.every, r.srv.gf.every, defaultReassertEvery)
	}
}

// TestSandboxRules: each op on an address the helper's CNI leased; writes
// need the lease, clears do not; CIDRs only with the policy ops.
func TestSandboxRules(t *testing.T) {
	r, c, _, fw := sandboxRig(t)
	ctx := callCtx(t)
	if _, err := c.RealizeNetns(ctx, &rootdpb.RealizeNetnsRequest{NetnsName: "sb-1"}); err != nil {
		t.Fatal(err)
	}
	for op := range rootdpb.SandboxRulesOp_name {
		o := rootdpb.SandboxRulesOp(op)
		if o == rootdpb.SandboxRulesOp_SANDBOX_RULES_OP_UNSPECIFIED {
			continue
		}
		req := &rootdpb.SandboxRulesRequest{ContainerIp: "10.88.0.2", Op: o}
		if policyOps[o] {
			req.AllowCidrs = []string{"1.2.3.4"}
		}
		if _, err := c.SandboxRules(ctx, req); err != nil {
			t.Fatalf("%v: %v", o, err)
		}
	}
	if n := len(fw.recorded()); n != len(writeOps)+len(clearOps) {
		t.Fatalf("%d rule calls: %q", n, fw.recorded())
	}
	resp, err := c.SandboxRules(ctx, &rootdpb.SandboxRulesRequest{ContainerIp: "10.88.0.2", Op: rootdpb.SandboxRulesOp_SANDBOX_RULES_OP_BLOCK_EGRESS})
	if err != nil || resp.GetInserted() {
		t.Fatalf("a second block = %v, %v; want not inserted", resp, err)
	}
	for _, tc := range []struct {
		name   string
		req    *rootdpb.SandboxRulesRequest
		code   codes.Code
		reason string
	}{
		{"no op", &rootdpb.SandboxRulesRequest{ContainerIp: "10.88.0.2"}, codes.InvalidArgument, ReasonBadRequest},
		{"CIDRs on a block", &rootdpb.SandboxRulesRequest{ContainerIp: "10.88.0.2", Op: rootdpb.SandboxRulesOp_SANDBOX_RULES_OP_BLOCK_EGRESS,
			AllowCidrs: []string{"1.2.3.4"}}, codes.InvalidArgument, ReasonBadRequest},
		{"a CIDR that is not one", &rootdpb.SandboxRulesRequest{ContainerIp: "10.88.0.2", Op: rootdpb.SandboxRulesOp_SANDBOX_RULES_OP_APPLY_EGRESS_POLICY,
			DenyCidrs: []string{"x"}}, codes.InvalidArgument, string(rootpolicy.RuleCIDR)},
		{"the bridge's own address", &rootdpb.SandboxRulesRequest{ContainerIp: "10.88.0.1", Op: rootdpb.SandboxRulesOp_SANDBOX_RULES_OP_BLOCK_EGRESS},
			codes.InvalidArgument, string(rootpolicy.RuleOf(must(rootpolicy.CheckSandboxAddress(netip.MustParsePrefix("10.88.0.0/16"), "10.88.0.1"))))},
		{"a write nobody holds", &rootdpb.SandboxRulesRequest{ContainerIp: "10.88.0.99", Op: rootdpb.SandboxRulesOp_SANDBOX_RULES_OP_HOLD_EGRESS},
			codes.PermissionDenied, string(rootpolicy.RuleLease)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := c.SandboxRules(ctx, tc.req)
			wantRefusal(t, r, err, tc.code, tc.reason)
		})
	}
	// A clear on an address nobody holds is cleanup, not a write.
	if _, err := c.SandboxRules(ctx, &rootdpb.SandboxRulesRequest{ContainerIp: "10.88.0.99", Op: rootdpb.SandboxRulesOp_SANDBOX_RULES_OP_CLEAR_HOLD_EGRESS}); err != nil {
		t.Fatal(err)
	}
	fw.fail[rootdpb.SandboxRulesOp_SANDBOX_RULES_OP_HOLD_EGRESS.String()] = errors.New("xtables lock")
	_, err = c.SandboxRules(ctx, &rootdpb.SandboxRulesRequest{ContainerIp: "10.88.0.2", Op: rootdpb.SandboxRulesOp_SANDBOX_RULES_OP_HOLD_EGRESS})
	wantCode(t, err, codes.Internal)
}

// TestFirewallNotOpen: a node whose firewall cannot open answers each
// firewall call FailedPrecondition, and tries again on the next call; a
// helper with no network serves none of them.
func TestFirewallNotOpen(t *testing.T) {
	fn := newFakeNet()
	opens := 0
	orig := openFirewallFn
	openFirewallFn = func(Config, NetworkHost) (FirewallHost, error) {
		opens++
		if opens == 1 {
			return nil, errors.New("no nf_tables")
		}
		return newFakeFirewall(), nil
	}
	t.Cleanup(func() { openFirewallFn = orig })
	r := newRig(t, func(_ *Config, o *Options) { o.Network = fn })
	c := rootdpb.NewRootHelperClient(r.conn)
	ctx := callCtx(t)
	_, err := c.EnsureHost(ctx, &rootdpb.EnsureHostRequest{})
	wantCode(t, err, codes.FailedPrecondition)
	if _, err := c.EnsureHost(ctx, &rootdpb.EnsureHostRequest{}); err != nil || opens != 2 {
		t.Fatalf("the second open: %v (%d opens)", err, opens)
	}
	v, err := c.Version(ctx, &rootdpb.VersionRequest{})
	if err != nil || !slices.Equal(v.GetParts(), []string{rootdpb.PartNetns, rootdpb.PartFirewall, rootdpb.PartFiles}) || !slices.Contains(v.GetFeatures(), rootdpb.FeaturePrepareSandbox) {
		t.Fatalf("Version = %v, %v", v, err)
	}
	none := newRig(t, nil)
	nc := rootdpb.NewRootHelperClient(none.conn)
	for _, call := range []func() error{
		func() error { _, err := nc.EnsureHost(ctx, &rootdpb.EnsureHostRequest{}); return err },
		func() error { _, err := nc.SetNodeGuard(ctx, &rootdpb.SetNodeGuardRequest{}); return err },
		func() error { _, err := nc.SetEgressFloor(ctx, &rootdpb.SetEgressFloorRequest{}); return err },
		func() error { _, err := nc.SandboxRules(ctx, &rootdpb.SandboxRulesRequest{}); return err },
		func() error { _, err := nc.PrepareSandbox(ctx, &rootdpb.PrepareSandboxRequest{}); return err },
		func() error { _, err := nc.ReleaseSandbox(ctx, &rootdpb.ReleaseSandboxRequest{}); return err },
	} {
		wantCode(t, call(), codes.Unimplemented)
	}
	if v, _ := nc.Version(ctx, &rootdpb.VersionRequest{}); !slices.Equal(v.GetParts(), []string{rootdpb.PartFiles}) {
		t.Fatalf("a helper with no network lists parts %v, want the container's files part alone", v.GetParts())
	}
}

// withNodeDNS makes ns this node's own resolver handed to sandboxes, for
// the test.
func withNodeDNS(t *testing.T, ns string) {
	orig := nodeDNSPorts
	nodeDNSPorts = func() []rootpolicy.NodePort {
		return []rootpolicy.NodePort{{Proto: "udp", Port: 53, Dst: ns}, {Proto: "tcp", Port: 53, Dst: ns}}
	}
	t.Cleanup(func() { nodeDNSPorts = orig })
}

// TestNodeGuardBoundIsSingleModes (PR 5 review 2): the agent may open on
// the node only what single mode would: DNS only on the node's own
// resolvers that sandboxes are handed, 80 and 443 only where the helper's
// settings give them; a wider guard is refused, and nothing is written.
func TestNodeGuardBoundIsSingleModes(t *testing.T) {
	withNodeDNS(t, "10.0.1.5")
	e := map[string]string{"SB_SANDBOX_NODE_INGRESS": "false"}
	ports, err := nodePortsFromEnv(func(k string) string { return e[k] }, false, false)
	if err != nil {
		t.Fatal(err)
	}
	fn, fw := newFakeNet(), newFakeFirewall()
	r := newRig(t, func(c *Config, o *Options) { o.Network, o.Firewall = fn, fw; c.Firewall.NodePorts = ports })
	c := rootdpb.NewRootHelperClient(r.conn)
	for _, p := range []*rootdpb.NodePort{
		{Proto: "tcp", Port: 443}, {Proto: "tcp", Port: 80},
		{Proto: "udp", Port: 53}, {Proto: "tcp", Port: 53}, // on every node address
		{Proto: "udp", Port: 53, Dst: "10.0.1.6"}, // an address that is no resolver
	} {
		_, err := c.SetNodeGuard(callCtx(t), &rootdpb.SetNodeGuardRequest{Allow: []*rootdpb.NodePort{p}})
		wantRefusal(t, r, err, codes.PermissionDenied, string(rootpolicy.RuleNodePort))
	}
	if _, err := c.SetNodeGuard(callCtx(t), &rootdpb.SetNodeGuardRequest{Allow: []*rootdpb.NodePort{
		{Proto: "udp", Port: 53, Dst: "10.0.1.5"}, {Proto: "tcp", Port: 53, Dst: "10.0.1.5"}, {Proto: "tcp", Port: 15080}}}); err != nil {
		t.Fatal(err)
	}
	if got := fw.recorded(); len(got) != 1 {
		t.Fatalf("calls %q, want the one allowed guard", got)
	}
}
