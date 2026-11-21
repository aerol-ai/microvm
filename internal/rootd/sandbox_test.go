package rootd

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"slices"
	"sync"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/encoding/protowire"

	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
	"github.com/aerol-ai/microvm/internal/rootpolicy"
)

// fakeFirewall is a FirewallHost in memory: it records each rule change.
type fakeFirewall struct {
	mu    sync.Mutex
	calls []string
	fail  map[string]error // by op name, or "clear"
	fence error
	// blocked are the addresses with a block-all rule.
	blocked map[string]bool
}

func newFakeFirewall() *fakeFirewall {
	return &fakeFirewall{fail: map[string]error{}, blocked: map[string]bool{}}
}

func (f *fakeFirewall) record(s string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, s)
}

func (f *fakeFirewall) recorded() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.calls)
}

func (f *fakeFirewall) EnsureHost(context.Context) (error, error) {
	f.record("ensure")
	return f.fence, f.fail["ensure"]
}

func (f *fakeFirewall) Reassert(context.Context) { f.record("reassert") }

func (f *fakeFirewall) SetNodeGuard(allow []rootpolicy.NodePort) (bool, error) {
	f.record(fmt.Sprintf("guard %v", allow))
	return false, f.fail["guard"]
}

func (f *fakeFirewall) SetFloor(cidrs []netip.Prefix) (bool, error) {
	f.record(fmt.Sprintf("floor %v", cidrs))
	return false, f.fail["floor"]
}

func (f *fakeFirewall) Rules(_ context.Context, op rootdpb.SandboxRulesOp, ip string, allow, deny []string) (bool, error) {
	f.record(fmt.Sprintf("%s %s %v %v", op, ip, allow, deny))
	if err := f.fail[op.String()]; err != nil {
		return false, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if op == rootdpb.SandboxRulesOp_SANDBOX_RULES_OP_BLOCK_EGRESS {
		inserted := !f.blocked[ip]
		f.blocked[ip] = true
		return inserted, nil
	}
	return false, nil
}

func (f *fakeFirewall) ClearAddress(ip string) error {
	f.record("clear " + ip)
	f.mu.Lock()
	delete(f.blocked, ip)
	f.mu.Unlock()
	return f.fail["clear"]
}

func sandboxRig(t *testing.T) (*rig, rootdpb.RootHelperClient, *fakeNet, *fakeFirewall) {
	t.Helper()
	fn, fw := newFakeNet(), newFakeFirewall()
	r := newRig(t, func(_ *Config, o *Options) { o.Network, o.Firewall = fn, fw })
	return r, rootdpb.NewRootHelperClient(r.conn), fn, fw
}

var both = []string{rootdpb.PartNetns, rootdpb.PartFirewall}

// TestPrepareSandboxCold: a cold create's root work in one call: the
// namespace, then block-all and the egress policy on the address CNI gave
// it, in canonical form.
func TestPrepareSandboxCold(t *testing.T) {
	_, c, fn, fw := sandboxRig(t)
	resp, err := c.PrepareSandbox(callCtx(t), &rootdpb.PrepareSandboxRequest{NetnsName: "sb-1", Parts: both,
		Firewall: &rootdpb.SandboxFirewall{BlockAllEgress: true, AllowCidrs: []string{"1.2.3.4"}, DenyCidrs: []string{"10.1.2.3/16"}}})
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetContainerIp() != "10.88.0.2" || resp.GetNetnsPath() == "" || !resp.GetBlockInserted() {
		t.Fatalf("answer %v", resp)
	}
	want := []string{
		"SANDBOX_RULES_OP_BLOCK_EGRESS 10.88.0.2 [] []",
		"SANDBOX_RULES_OP_APPLY_EGRESS_POLICY 10.88.0.2 [1.2.3.4/32] [10.1.0.0/16]",
	}
	if got := fw.recorded(); !slices.Equal(got, want) {
		t.Fatalf("rules %q, want %q", got, want)
	}
	if got := fn.recorded(); !slices.Equal(got, []string{"realize sb-1"}) {
		t.Fatalf("network %v", got)
	}
	// A repeat (a retry after a lost answer) builds nothing again and
	// reports the block as already there.
	again, err := c.PrepareSandbox(callCtx(t), &rootdpb.PrepareSandboxRequest{NetnsName: "sb-1", Parts: both,
		Firewall: &rootdpb.SandboxFirewall{BlockAllEgress: true}})
	if err != nil || again.GetContainerIp() != "10.88.0.2" || again.GetBlockInserted() {
		t.Fatalf("repeat %v %v", again, err)
	}
	if got := fn.recorded(); len(got) != 1 {
		t.Fatalf("a repeat built again: %v", got)
	}
}

// TestPrepareSandboxWarm: a warm slot's create sends only the firewall
// part, with the address the pool recorded; the helper writes rules only
// for an address its CNI leased to that very slot.
func TestPrepareSandboxWarm(t *testing.T) {
	r, c, _, fw := sandboxRig(t)
	ctx := callCtx(t)
	for _, n := range []string{"warm-1", "warm-2"} {
		if _, err := c.RealizeNetns(ctx, &rootdpb.RealizeNetnsRequest{NetnsName: n}); err != nil {
			t.Fatal(err)
		}
	}
	fw1 := []string{rootdpb.PartFirewall}
	resp, err := c.PrepareSandbox(ctx, &rootdpb.PrepareSandboxRequest{NetnsName: "warm-1", Parts: fw1, ContainerIp: "10.88.0.2",
		Firewall: &rootdpb.SandboxFirewall{BlockAllEgress: true}})
	if err != nil || !resp.GetBlockInserted() || resp.GetNetnsPath() != "" {
		t.Fatalf("warm = %v %v", resp, err)
	}
	// Another slot's address, an address nobody holds, and one outside
	// the range are refused, and touch no rule.
	before := len(fw.recorded())
	for _, tc := range []struct {
		ip     string
		code   codes.Code
		reason rootpolicy.Rule
	}{
		{"10.88.0.3", codes.PermissionDenied, rootpolicy.RuleLease},
		{"10.88.0.77", codes.PermissionDenied, rootpolicy.RuleLease},
		{"172.17.0.2", codes.InvalidArgument, rootpolicy.RuleOf(must(rootpolicy.CheckSandboxAddress(netip.MustParsePrefix("10.88.0.0/16"), "172.17.0.2")))},
	} {
		_, err := c.PrepareSandbox(ctx, &rootdpb.PrepareSandboxRequest{NetnsName: "warm-1", Parts: fw1, ContainerIp: tc.ip,
			Firewall: &rootdpb.SandboxFirewall{BlockAllEgress: true}})
		wantRefusal(t, r, err, tc.code, string(tc.reason))
	}
	if len(fw.recorded()) != before {
		t.Fatalf("a refused call changed rules: %v", fw.recorded()[before:])
	}
}

func must(_ netip.Addr, err error) error { return err }

// TestPrepareSandboxRequests: what the helper refuses before it acts, and
// what it answers as a version skew (Unimplemented, never a refusal).
func TestPrepareSandboxRequests(t *testing.T) {
	r, c, fn, fw := sandboxRig(t)
	ctx := callCtx(t)
	for _, tc := range []struct {
		name   string
		req    *rootdpb.PrepareSandboxRequest
		code   codes.Code
		reason string
	}{
		{"no parts", &rootdpb.PrepareSandboxRequest{NetnsName: "sb-1"}, codes.InvalidArgument, ReasonBadRequest},
		{"a part twice", &rootdpb.PrepareSandboxRequest{NetnsName: "sb-1", Parts: []string{"netns", "netns"}}, codes.InvalidArgument, ReasonBadRequest},
		{"rules without their part", &rootdpb.PrepareSandboxRequest{NetnsName: "sb-1", Parts: []string{"netns"},
			Firewall: &rootdpb.SandboxFirewall{BlockAllEgress: true}}, codes.InvalidArgument, ReasonBadRequest},
		{"an address with the netns part", &rootdpb.PrepareSandboxRequest{NetnsName: "sb-1", Parts: both, ContainerIp: "10.88.0.9"},
			codes.InvalidArgument, ReasonBadRequest},
		{"no address for a warm slot", &rootdpb.PrepareSandboxRequest{NetnsName: "sb-1", Parts: []string{"firewall"}},
			codes.InvalidArgument, ReasonBadRequest},
		{"a bad name", &rootdpb.PrepareSandboxRequest{NetnsName: "../x", Parts: both}, codes.InvalidArgument, string(rootpolicy.RuleNetns)},
		{"a CIDR that is not one", &rootdpb.PrepareSandboxRequest{NetnsName: "sb-1", Parts: both,
			Firewall: &rootdpb.SandboxFirewall{AllowCidrs: []string{"10.0.0.0/8 -j ACCEPT"}}}, codes.InvalidArgument, string(rootpolicy.RuleCIDR)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := c.PrepareSandbox(ctx, tc.req)
			wantRefusal(t, r, err, tc.code, tc.reason)
		})
	}
	refusals := len(r.refused())
	// A newer agent's part, or a field this helper does not know: the
	// helper is older, so it acts on nothing and says Unimplemented.
	_, err := c.PrepareSandbox(ctx, &rootdpb.PrepareSandboxRequest{NetnsName: "sb-1", Parts: []string{"netns", "cgroup"}})
	wantCode(t, err, codes.Unimplemented)
	newer := &rootdpb.PrepareSandboxRequest{NetnsName: "sb-1", Parts: both, Firewall: &rootdpb.SandboxFirewall{}}
	newer.GetFirewall().ProtoReflect().SetUnknown(protowire.AppendVarint(protowire.AppendTag(nil, 99, protowire.VarintType), 1))
	_, err = c.PrepareSandbox(ctx, newer)
	wantCode(t, err, codes.Unimplemented)
	rel := &rootdpb.ReleaseSandboxRequest{NetnsName: "sb-1", Parts: []string{"netns"}}
	rel.ProtoReflect().SetUnknown(protowire.AppendVarint(protowire.AppendTag(nil, 99, protowire.VarintType), 1))
	_, err = c.ReleaseSandbox(ctx, rel)
	wantCode(t, err, codes.Unimplemented)
	if len(r.refused()) != refusals || len(fn.recorded()) != 0 || len(fw.recorded()) != 0 {
		t.Fatalf("a skew was a refusal, or acted: %v %v %v", r.refused()[refusals:], fn.recorded(), fw.recorded())
	}
}

// TestPrepareSandboxUndo: a create whose rules fail leaves nothing: the
// rules it put in go, and so does the namespace it built.
func TestPrepareSandboxUndo(t *testing.T) {
	_, c, fn, fw := sandboxRig(t)
	fw.fail[rootdpb.SandboxRulesOp_SANDBOX_RULES_OP_APPLY_EGRESS_POLICY.String()] = errors.New("xtables lock")
	_, err := c.PrepareSandbox(callCtx(t), &rootdpb.PrepareSandboxRequest{NetnsName: "sb-1", Parts: both,
		Firewall: &rootdpb.SandboxFirewall{BlockAllEgress: true, AllowCidrs: []string{"1.2.3.4"}}})
	wantCode(t, err, codes.Internal)
	if got := fw.recorded(); got[len(got)-1] != "clear 10.88.0.2" {
		t.Fatalf("rules %v; want the address cleared last", got)
	}
	if got := fn.recorded(); !slices.Equal(got, []string{"realize sb-1", "remove sb-1 10.88.0.2"}) {
		t.Fatalf("network %v", got)
	}
}

// TestReleaseSandbox: the rules go before CNI DEL frees the address, so the
// address's next holder never loses its rules to this call. With the netns
// part the address is the slot's own (PR 5 review): one the agent names
// wrongly, another slot's included, is never cleared in its place.
func TestReleaseSandbox(t *testing.T) {
	r, c, fn, fw := sandboxRig(t)
	ctx := callCtx(t)
	if _, err := c.PrepareSandbox(ctx, &rootdpb.PrepareSandboxRequest{NetnsName: "sb-1", Parts: both,
		Firewall: &rootdpb.SandboxFirewall{BlockAllEgress: true}}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.RealizeNetns(ctx, &rootdpb.RealizeNetnsRequest{NetnsName: "sb-2"}); err != nil {
		t.Fatal(err)
	}
	// The firewall part alone still answers for the address it names.
	_, err := c.ReleaseSandbox(ctx, &rootdpb.ReleaseSandboxRequest{NetnsName: "sb-1", ContainerIp: "10.88.0.3", Parts: []string{rootdpb.PartFirewall}})
	wantRefusal(t, r, err, codes.PermissionDenied, string(rootpolicy.RuleLease))
	_, err = c.ReleaseSandbox(ctx, &rootdpb.ReleaseSandboxRequest{NetnsName: "sb-1", Parts: []string{rootdpb.PartFirewall}})
	wantRefusal(t, r, err, codes.InvalidArgument, ReasonBadRequest)
	fw.calls, fn.calls = nil, nil
	if _, err := c.ReleaseSandbox(ctx, &rootdpb.ReleaseSandboxRequest{NetnsName: "sb-1", ContainerIp: "10.88.0.3", Parts: both}); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(fw.recorded(), []string{"clear 10.88.0.2"}) || !slices.Equal(fn.recorded(), []string{"remove sb-1 10.88.0.2"}) {
		t.Fatalf("rules %v, network %v", fw.recorded(), fn.recorded())
	}
	// Gone is gone: a repeat is no error, and clears an address nobody
	// holds now.
	if _, err := c.ReleaseSandbox(ctx, &rootdpb.ReleaseSandboxRequest{NetnsName: "sb-1", ContainerIp: "10.88.0.2", Parts: both}); err != nil {
		t.Fatalf("repeat: %v", err)
	}
	if _, ok := fn.ns[filepath.Join(r.cfg.Policy.NetnsDir, "sb-1")]; ok {
		t.Fatal("the namespace is still there")
	}
}

// TestReleaseSandboxFindsItsAddress: a release with no address (a build
// the agent gave up on, whose answer it never saw) clears the rules of the
// address the slot's own namespace holds, then removes it; with no
// namespace there is no address, and nothing to clear.
func TestReleaseSandboxFindsItsAddress(t *testing.T) {
	_, c, fn, fw := sandboxRig(t)
	ctx := callCtx(t)
	if _, err := c.PrepareSandbox(ctx, &rootdpb.PrepareSandboxRequest{NetnsName: "sb-1", Parts: both,
		Firewall: &rootdpb.SandboxFirewall{BlockAllEgress: true}}); err != nil {
		t.Fatal(err)
	}
	fw.calls, fn.calls = nil, nil
	if _, err := c.ReleaseSandbox(ctx, &rootdpb.ReleaseSandboxRequest{NetnsName: "sb-1", Parts: both}); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(fw.recorded(), []string{"clear 10.88.0.2"}) || !slices.Equal(fn.recorded(), []string{"remove sb-1 10.88.0.2"}) {
		t.Fatalf("rules %v, network %v", fw.recorded(), fn.recorded())
	}
	fw.calls = nil
	if _, err := c.ReleaseSandbox(ctx, &rootdpb.ReleaseSandboxRequest{NetnsName: "sb-1", Parts: both}); err != nil || len(fw.recorded()) != 0 {
		t.Fatalf("again: %v, rules %v", err, fw.recorded())
	}
}
