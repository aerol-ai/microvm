package rootd

import (
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"

	"github.com/aerol-ai/microvm/internal/network/tap/taphost"
	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
	"github.com/aerol-ai/microvm/internal/rootpolicy"
)

// guestRig serves a helper with Firecracker on, the guests' firewall a
// fake, and the sandboxes' network and firewall fakes too, so a test can
// tell which firewall a call reached. reassertEvery, when set, paces the
// re-assert timers.
func guestRig(t *testing.T, reassertEvery ...time.Duration) (*rig, rootdpb.RootHelperClient, *fakeFirewall, *fakeFirewall, *fakeTables) {
	t.Helper()
	tables, gfw, fw := &fakeTables{}, newFakeFirewall(), newFakeFirewall()
	fc := testFirecrackerConfig(t)
	fc.UID += 1000
	r := newRig(t, func(c *Config, o *Options) {
		c.Hosts = HostsConfig{LogPath: filepath.Join(t.TempDir(), "hosts.log"), Firecracker: fc}
		o.HostKernel = newFakeHostKernel()
		o.TapDevices = &fakeTaps{}
		o.TapTables = func() (taphost.IsolationBackend, error) { return tables, nil }
		o.TapSysctls = func() error { return nil }
		o.Network, o.Firewall, o.GuestFirewall = newFakeNet(), fw, gfw
		for _, every := range reassertEvery {
			o.reassertEvery = every
		}
	})
	return r, rootdpb.NewRootHelperClient(r.conn), gfw, fw, tables
}

// TestGuestFirewallCalls (M1 PR 14): EnsureGuestFirewall puts the guests'
// NAT and isolation in first, then their chain, and starts the re-assert
// timer; the node guard and the floor reach the guests' firewall, never
// the sandboxes', and pass the checks the sandboxes' do.
func TestGuestFirewallCalls(t *testing.T) {
	withNodeDNS(t, "10.0.1.5")
	r, c, gfw, fw, tables := guestRig(t, 5*time.Millisecond)
	ctx := callCtx(t)
	if _, err := c.EnsureGuestFirewall(ctx, &rootdpb.EnsureGuestFirewallRequest{}); err != nil {
		t.Fatal(err)
	}
	nat := false
	for _, rule := range tables.rules {
		nat = nat || strings.Contains(rule, "MASQUERADE")
	}
	if !nat || !slices.Contains(gfw.recorded(), "ensure") {
		t.Fatalf("NAT %v, guest firewall %q", tables.rules, gfw.recorded())
	}
	deadline := time.Now().Add(5 * time.Second)
	for !slices.Contains(gfw.recorded(), "reassert") {
		if time.Now().After(deadline) {
			t.Fatal("the guests' re-assert timer never ran")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if _, err := c.SetGuestNodeGuard(ctx, &rootdpb.SetNodeGuardRequest{Allow: []*rootdpb.NodePort{{Proto: "tcp", Port: 15080}, {Proto: "udp", Port: 53, Dst: "10.0.1.5"}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.SetGuestEgressFloor(ctx, &rootdpb.SetEgressFloorRequest{Cidrs: []string{"10.20.1.2/16"}}); err != nil {
		t.Fatal(err)
	}
	if got := gfw.recorded(); !slices.Contains(got, "guard [{tcp 15080 } {udp 53 10.0.1.5}]") || !slices.Contains(got, "floor [10.20.0.0/16]") {
		t.Fatalf("guest calls %q", got)
	}
	if got := fw.recorded(); len(got) != 0 {
		t.Fatalf("the sandboxes' firewall got %q", got)
	}
	for _, tc := range []struct {
		name   string
		call   func() error
		code   codes.Code
		reason rootpolicy.Rule
	}{
		{"a node port that is no port", func() error {
			_, err := c.SetGuestNodeGuard(ctx, &rootdpb.SetNodeGuardRequest{Allow: []*rootdpb.NodePort{{Proto: "icmp", Port: 1}}})
			return err
		}, codes.InvalidArgument, rootpolicy.RuleNodePort},
		{"a node port past the helper's own", func() error {
			_, err := c.SetGuestNodeGuard(ctx, &rootdpb.SetNodeGuardRequest{Allow: []*rootdpb.NodePort{{Proto: "tcp", Port: 22}}})
			return err
		}, codes.PermissionDenied, rootpolicy.RuleNodePort},
		{"rule text on the floor", func() error {
			_, err := c.SetGuestEgressFloor(ctx, &rootdpb.SetEgressFloorRequest{Cidrs: []string{"10.0.0.0/8 -j ACCEPT"}})
			return err
		}, codes.InvalidArgument, rootpolicy.RuleCIDR},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := len(kernelCalls(gfw))
			wantRefusal(t, r, tc.call(), tc.code, string(tc.reason))
			if got := kernelCalls(gfw); len(got) != before {
				t.Fatalf("a refused call reached the kernel: %q", got[before:])
			}
		})
	}
	gfw.fail["guard"], gfw.fail["floor"], gfw.fail["ensure"] = errors.New("netlink"), errors.New("netlink"), errors.New("netlink")
	_, err := c.SetGuestNodeGuard(ctx, &rootdpb.SetNodeGuardRequest{})
	wantCode(t, err, codes.Internal)
	_, err = c.SetGuestEgressFloor(ctx, &rootdpb.SetEgressFloorRequest{})
	wantCode(t, err, codes.Internal)
	_, err = c.EnsureGuestFirewall(ctx, &rootdpb.EnsureGuestFirewallRequest{})
	wantCode(t, err, codes.Internal)
}

// kernelCalls are the fake's calls but the timer's re-asserts, which run
// on their own.
func kernelCalls(f *fakeFirewall) []string {
	return slices.DeleteFunc(f.recorded(), func(c string) bool { return c == "reassert" })
}

// TestGuestRules: each op on a guest's address; CIDRs only with the policy
// ops, canonical; and a broken agent's requests refused, touching no rule.
func TestGuestRules(t *testing.T) {
	r, c, gfw, fw, _ := guestRig(t)
	ctx := callCtx(t)
	for op := range rootdpb.SandboxRulesOp_name {
		o := rootdpb.SandboxRulesOp(op)
		if o == rootdpb.SandboxRulesOp_SANDBOX_RULES_OP_UNSPECIFIED {
			continue
		}
		req := &rootdpb.GuestRulesRequest{GuestIp: "172.16.0.14", Op: o}
		if policyOps[o] {
			req.AllowCidrs, req.DenyCidrs = []string{"1.2.3.4"}, []string{"10.1.2.3/16"}
		}
		if _, err := c.GuestRules(ctx, req); err != nil {
			t.Fatalf("%v: %v", o, err)
		}
	}
	if n := len(gfw.recorded()); n != len(writeOps)+len(clearOps) {
		t.Fatalf("%d rule calls: %q", n, gfw.recorded())
	}
	if want := "SANDBOX_RULES_OP_APPLY_EGRESS_POLICY 172.16.0.14 [1.2.3.4/32] [10.1.0.0/16]"; !slices.Contains(gfw.recorded(), want) {
		t.Fatalf("calls %q lack %q", gfw.recorded(), want)
	}
	resp, err := c.GuestRules(ctx, &rootdpb.GuestRulesRequest{GuestIp: "172.16.0.14", Op: rootdpb.SandboxRulesOp_SANDBOX_RULES_OP_BLOCK_EGRESS})
	if err != nil || resp.GetInserted() {
		t.Fatalf("a second block = %v, %v; want not inserted", resp, err)
	}
	// A stopped VM keeps its slot and rules with no TAP up: a write on a
	// guest address needs no TAP.
	if _, err := c.GuestRules(ctx, &rootdpb.GuestRulesRequest{GuestIp: "172.16.3.254", Op: rootdpb.SandboxRulesOp_SANDBOX_RULES_OP_BLOCK_EGRESS}); err != nil {
		t.Fatal(err)
	}
	block := rootdpb.SandboxRulesOp_SANDBOX_RULES_OP_BLOCK_EGRESS
	policy := rootdpb.SandboxRulesOp_SANDBOX_RULES_OP_APPLY_EGRESS_POLICY
	for _, tc := range []struct {
		name   string
		req    *rootdpb.GuestRulesRequest
		code   codes.Code
		reason string
	}{
		{"no op", &rootdpb.GuestRulesRequest{GuestIp: "172.16.0.14"}, codes.InvalidArgument, ReasonBadRequest},
		{"an op past the list", &rootdpb.GuestRulesRequest{GuestIp: "172.16.0.14", Op: 99}, codes.InvalidArgument, ReasonBadRequest},
		{"CIDRs on a block", &rootdpb.GuestRulesRequest{GuestIp: "172.16.0.14", Op: block, AllowCidrs: []string{"1.2.3.4"}},
			codes.InvalidArgument, ReasonBadRequest},
		{"rule text as a CIDR", &rootdpb.GuestRulesRequest{GuestIp: "172.16.0.14", Op: policy, AllowCidrs: []string{"0.0.0.0/0 -j ACCEPT"}},
			codes.InvalidArgument, string(rootpolicy.RuleCIDR)},
		{"too many CIDRs", &rootdpb.GuestRulesRequest{GuestIp: "172.16.0.14", Op: policy,
			AllowCidrs: slices.Repeat([]string{"1.2.3.4"}, rootpolicy.MaxPolicyCIDRs+1)}, codes.InvalidArgument, string(rootpolicy.RuleCIDR)},
		{"a TAP's host end (the node)", &rootdpb.GuestRulesRequest{GuestIp: "172.16.0.13", Op: block}, codes.InvalidArgument, string(rootpolicy.RuleAddress)},
		{"a /30's broadcast", &rootdpb.GuestRulesRequest{GuestIp: "172.16.0.15", Op: block}, codes.InvalidArgument, string(rootpolicy.RuleAddress)},
		{"past the pool", &rootdpb.GuestRulesRequest{GuestIp: "172.16.4.2", Op: block}, codes.InvalidArgument, string(rootpolicy.RuleAddress)},
		{"a container's address", &rootdpb.GuestRulesRequest{GuestIp: "10.88.0.2", Op: block}, codes.InvalidArgument, string(rootpolicy.RuleAddress)},
		{"rule text as the address", &rootdpb.GuestRulesRequest{GuestIp: "172.16.0.14 -j ACCEPT", Op: block}, codes.InvalidArgument, string(rootpolicy.RuleAddress)},
		{"a clear on the node", &rootdpb.GuestRulesRequest{GuestIp: "172.16.0.1", Op: rootdpb.SandboxRulesOp_SANDBOX_RULES_OP_CLEAR_BLOCK_EGRESS},
			codes.InvalidArgument, string(rootpolicy.RuleAddress)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := len(gfw.recorded())
			_, err := c.GuestRules(ctx, tc.req)
			wantRefusal(t, r, err, tc.code, tc.reason)
			if got := gfw.recorded(); len(got) != before {
				t.Fatalf("a refused request reached the kernel: %q", got[before:])
			}
		})
	}
	if got := fw.recorded(); len(got) != 0 {
		t.Fatalf("the sandboxes' firewall got %q", got)
	}
	gfw.fail[rootdpb.SandboxRulesOp_SANDBOX_RULES_OP_HOLD_EGRESS.String()] = errors.New("xtables lock")
	_, err = c.GuestRules(ctx, &rootdpb.GuestRulesRequest{GuestIp: "172.16.0.14", Op: rootdpb.SandboxRulesOp_SANDBOX_RULES_OP_HOLD_EGRESS})
	wantCode(t, err, codes.Internal)
}

// TestGuestRulesBudget: a guest's policy replaces its last one in the
// count, and a node past its cap is refused new policy until some go.
func TestGuestRulesBudget(t *testing.T) {
	_, c, _, _, _ := guestRig(t)
	ctx := callCtx(t)
	policy := func(ip string, n int) error {
		_, err := c.GuestRules(ctx, &rootdpb.GuestRulesRequest{GuestIp: ip, Op: rootdpb.SandboxRulesOp_SANDBOX_RULES_OP_APPLY_EGRESS_POLICY,
			AllowCidrs: slices.Repeat([]string{"1.2.3.4"}, n)})
		return err
	}
	per := rootpolicy.MaxPolicyCIDRs
	full := maxNodePolicyRules / (per + 1)
	guest := func(i int) string {
		slot, err := taphost.SlotAt("172.16.0.0/20", 256, i)
		if err != nil {
			t.Fatal(err)
		}
		return slot.GuestIP
	}
	for i := range full {
		if err := policy(guest(i), per); err != nil {
			t.Fatalf("guest %d: %v", i, err)
		}
	}
	// The same guest again replaces its own count.
	if err := policy(guest(0), per); err != nil {
		t.Fatal(err)
	}
	wantCode(t, policy(guest(full), per), codes.ResourceExhausted)
	if _, err := c.GuestRules(ctx, &rootdpb.GuestRulesRequest{GuestIp: guest(0), Op: rootdpb.SandboxRulesOp_SANDBOX_RULES_OP_CLEAR_EGRESS_POLICY}); err != nil {
		t.Fatal(err)
	}
	if err := policy(guest(full), per); err != nil {
		t.Fatalf("after a clear: %v", err)
	}
}

// TestGuestFirewallFailsClosed: with the guests' NAT and isolation not in
// place, their firewall is not set up and no rule goes in.
func TestGuestFirewallFailsClosed(t *testing.T) {
	_, c, gfw, _, tables := guestRig(t)
	tables.err = errors.New("no iptables")
	_, err := c.EnsureGuestFirewall(callCtx(t), &rootdpb.EnsureGuestFirewallRequest{})
	wantCode(t, err, codes.Unavailable)
	if got := gfw.recorded(); len(got) != 0 {
		t.Fatalf("the guests' firewall was set up without their isolation: %q", got)
	}
}

// TestGuestFirewallNotOpen: a node whose guest firewall cannot open answers
// each call FailedPrecondition and tries again on the next; a helper with
// no Firecracker serves none of the four.
func TestGuestFirewallNotOpen(t *testing.T) {
	opens := 0
	orig := openGuestFirewallFn
	openGuestFirewallFn = func(Config, *FirecrackerHostsConfig) (FirewallHost, error) {
		opens++
		if opens == 1 {
			return nil, errors.New("no nf_tables")
		}
		return newFakeFirewall(), nil
	}
	t.Cleanup(func() { openGuestFirewallFn = orig })
	tables, fc := &fakeTables{}, testFirecrackerConfig(t)
	fc.UID += 1000
	r := newRig(t, func(c *Config, o *Options) {
		c.Hosts = HostsConfig{LogPath: filepath.Join(t.TempDir(), "hosts.log"), Firecracker: fc}
		o.HostKernel, o.TapDevices = newFakeHostKernel(), &fakeTaps{}
		o.TapTables = func() (taphost.IsolationBackend, error) { return tables, nil }
		o.TapSysctls = func() error { return nil }
	})
	c := rootdpb.NewRootHelperClient(r.conn)
	ctx := callCtx(t)
	_, err := c.GuestRules(ctx, &rootdpb.GuestRulesRequest{GuestIp: "172.16.0.2", Op: rootdpb.SandboxRulesOp_SANDBOX_RULES_OP_BLOCK_EGRESS})
	wantCode(t, err, codes.FailedPrecondition)
	if _, err := c.EnsureGuestFirewall(ctx, &rootdpb.EnsureGuestFirewallRequest{}); err != nil || opens != 2 {
		t.Fatalf("the second open: %v (%d opens)", err, opens)
	}
	v, err := c.Version(ctx, &rootdpb.VersionRequest{})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range guestFeatures {
		if !slices.Contains(v.GetFeatures(), f) {
			t.Errorf("a helper with Firecracker does not list %s: %v", f, v.GetFeatures())
		}
	}
	none := rootdpb.NewRootHelperClient(newRig(t, nil).conn)
	for _, call := range []func() error{
		func() error {
			_, err := none.EnsureGuestFirewall(ctx, &rootdpb.EnsureGuestFirewallRequest{})
			return err
		},
		func() error { _, err := none.SetGuestNodeGuard(ctx, &rootdpb.SetNodeGuardRequest{}); return err },
		func() error { _, err := none.SetGuestEgressFloor(ctx, &rootdpb.SetEgressFloorRequest{}); return err },
		func() error { _, err := none.GuestRules(ctx, &rootdpb.GuestRulesRequest{}); return err },
	} {
		wantCode(t, call(), codes.Unimplemented)
	}
}

// TestEnsureHostFencesGuests: the sandboxes' fence reports whether it
// covers the Firecracker TAPs, and their state, for the agent's create
// gate.
func TestEnsureHostFencesGuests(t *testing.T) {
	_, c, _, fw, _ := guestRig(t)
	ctx := callCtx(t)
	resp, err := c.EnsureHost(ctx, &rootdpb.EnsureHostRequest{})
	if err != nil || resp.GetFencesFirecracker() || resp.GetFirecrackerIpv6FenceError() != "" {
		t.Fatalf("a fence that leaves the TAPs out = %v, %v", resp, err)
	}
	fw.guests, fw.guestFence = true, errors.New("no table")
	resp, err = c.EnsureHost(ctx, &rootdpb.EnsureHostRequest{})
	if err != nil || !resp.GetFencesFirecracker() || resp.GetFirecrackerIpv6FenceError() != "no table" {
		t.Fatalf("EnsureHost = %v, %v", resp, err)
	}
	fw.guestFence = nil
	resp, err = c.EnsureHost(ctx, &rootdpb.EnsureHostRequest{})
	if err != nil || !resp.GetFencesFirecracker() || resp.GetFirecrackerIpv6FenceError() != "" {
		t.Fatalf("EnsureHost = %v, %v", resp, err)
	}
}
