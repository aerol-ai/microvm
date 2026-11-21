package rootd

// The helper firewall's guarantees across calls, offline (fakes, no root):
// a field the helper does not know is refused, and an address leaves its
// slot only with its rules gone.

import (
	"fmt"
	"slices"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protowire"

	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
)

// Version safety: every call refuses a field this helper does not know (the
// server's interceptor), nested messages included, so a newer agent's
// narrowing (a port on a policy, a source on a node port) is never dropped
// and the call done wider than asked.
func TestFirewallCallsRefuseUnknownFields(t *testing.T) {
	_, c, fn, fw := sandboxRig(t)
	ctx := callCtx(t)
	if _, err := c.RealizeNetns(ctx, &rootdpb.RealizeNetnsRequest{NetnsName: "sb-1"}); err != nil {
		t.Fatal(err)
	}
	_ = fn
	unknown := protowire.AppendVarint(protowire.AppendTag(nil, 99, protowire.VarintType), 1)

	rules := &rootdpb.SandboxRulesRequest{ContainerIp: "10.88.0.2", Op: rootdpb.SandboxRulesOp_SANDBOX_RULES_OP_APPLY_EGRESS_POLICY,
		AllowCidrs: []string{"1.2.3.4"}}
	rules.ProtoReflect().SetUnknown(unknown)
	_, errRules := c.SandboxRules(ctx, rules)

	np := &rootdpb.NodePort{Proto: "tcp", Port: 10250}
	np.ProtoReflect().SetUnknown(unknown) // e.g. a future "only from this source"
	_, errGuard := c.SetNodeGuard(ctx, &rootdpb.SetNodeGuardRequest{Allow: []*rootdpb.NodePort{np}})

	floor := &rootdpb.SetEgressFloorRequest{Cidrs: []string{"10.20.0.0/16"}}
	floor.ProtoReflect().SetUnknown(unknown)
	_, errFloor := c.SetEgressFloor(ctx, floor)

	host := &rootdpb.EnsureHostRequest{}
	host.ProtoReflect().SetUnknown(unknown)
	_, errHost := c.EnsureHost(ctx, host)

	t.Logf("helper acted on: %q", fw.recorded())
	for name, err := range map[string]error{"SandboxRules": errRules, "SetNodeGuard": errGuard, "SetEgressFloor": errFloor, "EnsureHost": errHost} {
		if codeOf(err) != codes.Unimplemented {
			t.Errorf("%s with a field this helper does not know: err=%v, want Unimplemented", name, err)
		}
	}
}

func codeOf(err error) codes.Code { return status.Code(err) }

// With the namespace part, a release clears the rules of the address the
// slot's lease holds, whatever address the agent names, before CNI DEL
// frees that lease: the next holder starts with no rules.
func TestReleaseClearsTheLeasedAddress(t *testing.T) {
	_, c, _, fw := sandboxRig(t)
	ctx := callCtx(t)
	resp, err := c.PrepareSandbox(ctx, &rootdpb.PrepareSandboxRequest{NetnsName: "sb-1", Parts: both,
		Firewall: &rootdpb.SandboxFirewall{BlockAllEgress: true}})
	if err != nil {
		t.Fatal(err)
	}
	real := resp.GetContainerIp()
	if _, err := c.ReleaseSandbox(ctx, &rootdpb.ReleaseSandboxRequest{NetnsName: "sb-1", ContainerIp: "10.88.0.77", Parts: both}); err != nil {
		t.Fatal(err)
	}
	t.Logf("helper calls: %q", fw.recorded())
	fw.mu.Lock()
	left := fw.blocked[real]
	fw.mu.Unlock()
	if left {
		t.Fatalf("slot sb-1 released and its lease on %s freed with its block-all still on it", real)
	}
}

// A create whose rules fail is undone: its rules cleared, then its
// namespace (CNI DEL frees the lease). When the clear fails the namespace
// and lease stay, so the address never goes back to the pool with rules.
func TestPrepareUndoKeepsTheAddressWhenTheClearFails(t *testing.T) {
	_, c, fn, fw := sandboxRig(t)
	fw.fail[rootdpb.SandboxRulesOp_SANDBOX_RULES_OP_APPLY_EGRESS_POLICY.String()] = fmt.Errorf("xtables lock")
	fw.fail["clear"] = fmt.Errorf("netlink: EBUSY")
	_, err := c.PrepareSandbox(callCtx(t), &rootdpb.PrepareSandboxRequest{NetnsName: "sb-1", Parts: both,
		Firewall: &rootdpb.SandboxFirewall{BlockAllEgress: true, AllowCidrs: []string{"1.2.3.4"}}})
	t.Logf("prepare: %v; network calls %q; rule calls %q", err, fn.recorded(), fw.recorded())
	// The fake's clear reports failure (EBUSY): the kernel still holds the
	// rules. The namespace must stay, so its lease does too.
	removed := slices.Contains(fn.recorded(), "remove sb-1 10.88.0.2")
	if removed {
		t.Fatal("the failed create's clear failed, yet its namespace was removed and its lease freed")
	}
}
