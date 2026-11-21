package rootd

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc/codes"

	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
	"github.com/aerol-ai/microvm/internal/rootpolicy"
)

// The helper's firewall calls (plans/security-gaps-m1-m4.md §3.3,
// "Firewall"; M1 PR 5): the host rules for sandbox addresses, the node
// guard and floor, and the boot-time chain, block sets and IPv6 fence. The
// rules themselves are pkg/docker/netrules', the same code sandboxd runs in
// privilege mode single; the helper runs it as root on typed values it
// checks first (rootpolicy firewall.go) and writes back canonical:
//
//   - An address must be a sandbox's, in the helper's own range. A call
//     that writes rules for an address (a block, a hold, an egress policy)
//     needs the address leased, by the helper's own CNI, to a sandbox slot:
//     the kernel cannot vouch for a running gVisor sandbox's address (runsc
//     takes it into its own stack), the lease file can, and only root
//     writes it. Clears and lifts may name any sandbox address: removing a
//     rule from an address nobody holds is cleanup after a release. Which
//     live slot a call names stays the agent's bookkeeping (R9).
//   - The node guard's allow list opens ports in the helper's own
//     default-deny of the node; the floor always keeps the cloud metadata
//     endpoints, which the helper adds itself.
//   - Every input of the boot step (the bridge, its range, the chain) is
//     the helper's own.
//
// The helper keeps no state it cannot rebuild: the rules are the kernel's,
// and the node guard's and floor's lists are what the agent last sent,
// which the agent sends again on its own re-asserts. The helper's own
// timer puts chain, block sets, guard, floor and fence back if something
// takes them away, so they do not depend on the agent calling.

// FirewallHost is the kernel work behind the firewall calls: netrules and
// the IPv6 fence on Linux (openFirewall), a fake in tests. It acts on
// values the calls checked.
type FirewallHost interface {
	// EnsureHost sets the chain, block sets and IPv6 fence up, and answers
	// the fence's state (nil: it covers the sandboxes).
	EnsureHost(ctx context.Context) (fence error, err error)
	// Reassert is the timer's pass: put everything back if it went.
	Reassert(ctx context.Context)
	SetNodeGuard(allow []rootpolicy.NodePort) (repaired bool, err error)
	SetFloor(cidrs []netip.Prefix) (repaired bool, err error)
	// Rules changes one address's rules; inserted is a block's report.
	// The policy ops replace the address's whole policy, and stop between
	// writes once ctx ends.
	Rules(ctx context.Context, op rootdpb.SandboxRulesOp, ip string, allow, deny []string) (inserted bool, err error)
	// ClearAddress removes every rule kept for ip.
	ClearAddress(ip string) error
}

// writeOps write rules for an address, and need it leased to a slot.
var writeOps = map[rootdpb.SandboxRulesOp]bool{
	rootdpb.SandboxRulesOp_SANDBOX_RULES_OP_BLOCK_EGRESS:        true,
	rootdpb.SandboxRulesOp_SANDBOX_RULES_OP_BLOCK_INGRESS:       true,
	rootdpb.SandboxRulesOp_SANDBOX_RULES_OP_APPLY_EGRESS_POLICY: true,
	rootdpb.SandboxRulesOp_SANDBOX_RULES_OP_HOLD_EGRESS:         true,
}

// clearOps only remove rules.
var clearOps = map[rootdpb.SandboxRulesOp]bool{
	rootdpb.SandboxRulesOp_SANDBOX_RULES_OP_LIFT_BLOCK_EGRESS:   true,
	rootdpb.SandboxRulesOp_SANDBOX_RULES_OP_CLEAR_BLOCK_EGRESS:  true,
	rootdpb.SandboxRulesOp_SANDBOX_RULES_OP_CLEAR_BLOCK_INGRESS: true,
	rootdpb.SandboxRulesOp_SANDBOX_RULES_OP_CLEAR_EGRESS_POLICY: true,
	rootdpb.SandboxRulesOp_SANDBOX_RULES_OP_CLEAR_HOLD_EGRESS:   true,
}

// policyOps carry CIDR lists.
var policyOps = map[rootdpb.SandboxRulesOp]bool{
	rootdpb.SandboxRulesOp_SANDBOX_RULES_OP_APPLY_EGRESS_POLICY: true,
	rootdpb.SandboxRulesOp_SANDBOX_RULES_OP_CLEAR_EGRESS_POLICY: true,
}

// firewallFeatures are the calls firewall serves, as Version lists them.
var firewallFeatures = []string{rootdpb.FeatureEnsureHost, rootdpb.FeatureSetNodeGuard, rootdpb.FeatureSetEgressFloor,
	rootdpb.FeatureSandboxRules}

// reassertEvery paces the helper's own timer (as sandboxd's
// chainReassertInterval and ipv6fence.ReassertInterval did).
var reassertEvery = 30 * time.Second

// openFirewallFn opens the helper's own firewall; tests replace it.
var openFirewallFn = openFirewall

// firewall serves the firewall calls. Like network, it opens on its first
// call (latch and single flight), after the network it needs (the bridge
// and its range come from the CNI config).
type firewall struct {
	net   *network
	whole Config
	locks *keyedLocks

	ready atomic.Bool
	mu    sync.Mutex
	host  FirewallHost
	open  func(Config, NetworkHost) (FirewallHost, error)

	timerOnce sync.Once
	stopOnce  sync.Once
	stop      chan struct{}

	budget policyBudget
}

// The rule budget of egress policies (PR 5 review): an address's policy is
// replaced, never added to, and holds at most rootpolicy.MaxPolicyCIDRs
// entries; the node's policies together hold at most maxNodePolicyRules.
// Each rule makes every later write into the chain cost more, so a node
// past this is refused new policy, ResourceExhausted, until some go.
const maxNodePolicyRules = 32768

// policyBudget counts the policy rules this helper put on each address.
type policyBudget struct {
	mu    sync.Mutex
	byIP  map[string]int
	total int
}

// reserve records ip's policy as n rules, replacing what it had, or
// refuses when the node's policies would hold too many.
func (b *policyBudget) reserve(ip string, n int) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.byIP == nil {
		b.byIP = map[string]int{}
	}
	total := b.total - b.byIP[ip] + n
	if total > maxNodePolicyRules {
		return &fileError{code: codes.ResourceExhausted,
			msg: fmt.Sprintf("root helper: the node's egress policies would hold %d rules; at most %d", total, maxNodePolicyRules)}
	}
	b.total, b.byIP[ip] = total, n
	return nil
}

// release forgets ip's policy.
func (b *policyBudget) release(ip string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.total -= b.byIP[ip]
	delete(b.byIP, ip)
}

func newFirewall(cfg Config, net *network, injected FirewallHost, locks *keyedLocks) *firewall {
	if net == nil {
		return nil
	}
	f := &firewall{net: net, whole: cfg, locks: locks, host: injected, open: openFirewallFn, stop: make(chan struct{})}
	if injected != nil {
		f.ready.Store(true)
	}
	return f
}

func (f *firewall) opened() (FirewallHost, NetworkHost, error) {
	n, err := f.net.opened()
	if err != nil {
		return nil, nil, err
	}
	if f.ready.Load() {
		return f.host, n, nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.host != nil {
		return f.host, n, nil
	}
	h, err := f.open(f.whole, n)
	if err != nil {
		return nil, nil, &fileError{code: codes.FailedPrecondition, msg: "root helper: the host firewall is not set up on this node: " + err.Error()}
	}
	f.host = h
	f.ready.Store(true)
	return h, n, nil
}

// close stops the helper's own timer.
func (f *firewall) close() {
	if f != nil {
		f.stopOnce.Do(func() { close(f.stop) })
	}
}

// startTimer starts the re-assert timer once.
func (f *firewall) startTimer(h FirewallHost) {
	f.timerOnce.Do(func() {
		go func() {
			t := time.NewTicker(reassertEvery)
			defer t.Stop()
			for {
				select {
				case <-f.stop:
					return
				case <-t.C:
					h.Reassert(context.Background())
				}
			}
		}()
	})
}

func (f *firewall) ensureHost(ctx context.Context) (*rootdpb.EnsureHostResponse, error) {
	h, _, err := f.opened()
	if err != nil {
		return nil, err
	}
	unlock, err := f.locks.lock(ctx, "host/firewall")
	if err != nil {
		return nil, err
	}
	defer unlock()
	fence, err := h.EnsureHost(ctx)
	if err != nil {
		return nil, fmt.Errorf("root helper: host firewall: %w", err)
	}
	f.startTimer(h)
	resp := &rootdpb.EnsureHostResponse{}
	if fence != nil {
		resp.Ipv6FenceError = fence.Error()
	}
	return resp, nil
}

func (f *firewall) setNodeGuard(ctx context.Context, req *rootdpb.SetNodeGuardRequest) (*rootdpb.SetNodeGuardResponse, error) {
	in := make([]rootpolicy.NodePort, 0, len(req.GetAllow()))
	for _, p := range req.GetAllow() {
		in = append(in, rootpolicy.NodePort{Proto: p.GetProto(), Port: p.GetPort(), Dst: p.GetDst()})
	}
	allow, err := rootpolicy.CheckNodePorts(in)
	if err != nil {
		return nil, refusedRule(codes.InvalidArgument, err)
	}
	// The agent may narrow the helper's own list, never widen it (PR 5
	// review): every port it sends must be one the helper's settings
	// list, on every node address or on the one the agent names.
	if err := rootpolicy.CheckNodePortsWithin(allow, f.whole.Firewall.NodePorts); err != nil {
		return nil, refusedRule(codes.PermissionDenied, err)
	}
	h, _, err := f.opened()
	if err != nil {
		return nil, err
	}
	unlock2, err := f.locks.lock(ctx, "host/node-guard")
	if err != nil {
		return nil, err
	}
	defer unlock2()
	repaired, err := h.SetNodeGuard(allow)
	if err != nil {
		return nil, fmt.Errorf("root helper: node guard: %w", err)
	}
	return &rootdpb.SetNodeGuardResponse{Repaired: repaired}, nil
}

func (f *firewall) setFloor(ctx context.Context, req *rootdpb.SetEgressFloorRequest) (*rootdpb.SetEgressFloorResponse, error) {
	cidrs, err := rootpolicy.CheckFloorCIDRs(req.GetCidrs())
	if err != nil {
		return nil, refusedRule(codes.InvalidArgument, err)
	}
	h, _, err := f.opened()
	if err != nil {
		return nil, err
	}
	unlock3, err := f.locks.lock(ctx, "host/floor")
	if err != nil {
		return nil, err
	}
	defer unlock3()
	repaired, err := h.SetFloor(cidrs)
	if err != nil {
		return nil, fmt.Errorf("root helper: egress floor: %w", err)
	}
	return &rootdpb.SetEgressFloorResponse{Repaired: repaired}, nil
}

// addrKey is the per-object lock key of an address's rules (D11).
func addrKey(ip string) string { return "addr/" + ip }

// address checks ip is a sandbox address in the range and, with write,
// that the helper's CNI leased it to a slot: to holder exactly, when
// holder is set. Without write, a leased address must be holder's when
// holder is set (a release clears only its own slot's address).
func address(n NetworkHost, ip string, write bool, holder string) (string, error) {
	a, err := rootpolicy.CheckSandboxAddress(n.Subnet(), ip)
	if err != nil {
		return "", refusedRule(codes.InvalidArgument, err)
	}
	ip = a.String()
	name, leased, err := n.Leaseholder(a)
	if err != nil {
		return "", fmt.Errorf("root helper: lease of %s: %w", ip, err)
	}
	switch {
	case write && !leased:
		return "", &fileError{code: codes.PermissionDenied, reason: string(rootpolicy.RuleLease),
			msg: fmt.Sprintf("root helper: address %s is not leased to a sandbox; rules are written only for a sandbox's address", ip)}
	case leased && holder != "" && name != holder:
		return "", &fileError{code: codes.PermissionDenied, reason: string(rootpolicy.RuleLease),
			msg: fmt.Sprintf("root helper: address %s is leased to another slot, not %s", ip, holder)}
	}
	return ip, nil
}

// policyLists checks an egress policy's two lists, and their size
// together.
func policyLists(allow, deny []string) ([]string, []string, error) {
	if n := len(allow) + len(deny); n > rootpolicy.MaxPolicyCIDRs {
		return nil, nil, refusedRule(codes.InvalidArgument, rootpolicy.TooManyPolicyCIDRs(n))
	}
	a, err := rootpolicy.CheckRuleCIDRs(allow)
	if err != nil {
		return nil, nil, refusedRule(codes.InvalidArgument, err)
	}
	d, err := rootpolicy.CheckRuleCIDRs(deny)
	if err != nil {
		return nil, nil, refusedRule(codes.InvalidArgument, err)
	}
	return a, d, nil
}

func (f *firewall) sandboxRules(ctx context.Context, req *rootdpb.SandboxRulesRequest) (*rootdpb.SandboxRulesResponse, error) {
	op := req.GetOp()
	if !writeOps[op] && !clearOps[op] {
		return nil, badRequest("root helper: sandbox rules op %v is not one the helper does", op)
	}
	var allow, deny []string
	if policyOps[op] {
		var err error
		if allow, deny, err = policyLists(req.GetAllowCidrs(), req.GetDenyCidrs()); err != nil {
			return nil, err
		}
	} else if len(req.GetAllowCidrs()) > 0 || len(req.GetDenyCidrs()) > 0 {
		return nil, badRequest("root helper: %v takes no CIDRs", op)
	}
	h, n, err := f.opened()
	if err != nil {
		return nil, err
	}
	// The lock first, then the lease: a release holding this address's
	// lock cannot free the lease between the check and the rule.
	a, err := rootpolicy.CheckSandboxAddress(n.Subnet(), req.GetContainerIp())
	if err != nil {
		return nil, refusedRule(codes.InvalidArgument, err)
	}
	done, err := f.net.limit.enter(ctx)
	if err != nil {
		return nil, err
	}
	defer done()
	unlock4, err := f.locks.lock(ctx, addrKey(a.String()))
	if err != nil {
		return nil, err
	}
	defer unlock4()
	ip, err := address(n, req.GetContainerIp(), writeOps[op], "")
	if err != nil {
		return nil, err
	}
	if op == rootdpb.SandboxRulesOp_SANDBOX_RULES_OP_APPLY_EGRESS_POLICY {
		if err := f.budget.reserve(ip, len(allow)+len(deny)+1); err != nil {
			return nil, err
		}
	}
	inserted, err := h.Rules(ctx, op, ip, allow, deny)
	if op == rootdpb.SandboxRulesOp_SANDBOX_RULES_OP_CLEAR_EGRESS_POLICY && err == nil {
		f.budget.release(ip)
	}
	if err != nil {
		return nil, fmt.Errorf("root helper: %v on %s: %w", op, ip, err)
	}
	return &rootdpb.SandboxRulesResponse{Inserted: inserted}, nil
}

// servedParts are the parts this helper serves, as Version lists them.
func (f *firewall) servedParts() []string {
	if f == nil {
		return nil
	}
	return slices.Clone(rootdpb.Parts())
}
