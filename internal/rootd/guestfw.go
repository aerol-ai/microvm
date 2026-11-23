package rootd

import (
	"context"
	"fmt"
	"time"

	"google.golang.org/grpc/codes"

	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
	"github.com/aerol-ai/microvm/internal/rootpolicy"
)

// The Firecracker guests' firewall (M1 PR 14): EnsureGuestFirewall,
// SetGuestNodeGuard, SetGuestEgressFloor and GuestRules. In privilege mode
// single sandboxd keeps it (pkg/daemon wireFirecrackerEgress): the
// AEROLVM-FC chain with its accepts for the TAP base, its block sets, a
// node guard and a deny floor for that base, and each guest's block-all,
// egress policy, ingress block and hold. In split the helper keeps it, with
// the same netrules code, from its own settings:
//
//   - every range and chain is the helper's own: the TAP base and pool
//     size of its Firecracker settings, single mode's chain for guests;
//   - a rule's address must be a guest's: the guest end of one of the
//     pool's /30s, as the helper lays the pool out (rootpolicy
//     CheckGuestAddress), never a TAP's host end, which is the node's;
//   - the node guard's ports and the floor's networks pass the checks the
//     sandboxes' firewall makes (firewall.go): the agent may narrow the
//     helper's own node ports, never widen them, and the floor always
//     holds the cloud metadata endpoints;
//   - the guests' NAT and isolation (taps.go) go in before the chain, so
//     no guest rule is ever written on a node where guests reach each
//     other.
//
// Which slot belongs to which sandbox stays the agent's bookkeeping (plan
// R9). A stopped VM keeps its slot, and its rules, with no TAP up, so the
// helper does not ask for a TAP before a write, as it asks the sandboxes'
// CNI for a lease: the address's shape is what it can vouch for. Rules for
// a guest address no VM holds drop nothing but that address's traffic,
// and every one lands below the floor's and the node guard's jumps.
//
// The IPv6 fence on the TAPs is the sandboxes' fence (firewall_linux.go,
// EnsureHost): it is one nft table, put in whole.

// guestFeatures are the calls the helper lists when it serves Firecracker.
var guestFeatures = []string{rootdpb.FeatureEnsureGuestFirewall, rootdpb.FeatureSetGuestNodeGuard,
	rootdpb.FeatureSetGuestEgressFloor, rootdpb.FeatureGuestRules}

// openGuestFirewallFn opens the guests' firewall; tests replace it.
var openGuestFirewallFn = openGuestFirewall

// guestFirewall serves the guests' firewall calls: a firewall (its latch,
// its timer, its node guard and floor calls, its policy budget) with no
// network, over the helper's own TAP pool.
type guestFirewall struct {
	*firewall
	fc    *FirecrackerHostsConfig
	taps  *tapCalls
	limit *callLimit
}

// newGuestFirewall is nil when the helper serves no Firecracker.
func newGuestFirewall(cfg Config, taps *tapCalls, injected FirewallHost, locks *keyedLocks, every time.Duration) *guestFirewall {
	if taps == nil {
		return nil
	}
	fc, open := taps.cfg, openGuestFirewallFn
	f := &firewall{whole: cfg, locks: locks, key: "guest/", host: injected, stop: make(chan struct{}), every: reassertPace(every),
		open: func(c Config, _ NetworkHost) (FirewallHost, error) { return open(c, fc) }}
	if injected != nil {
		f.ready.Store(true)
	}
	return &guestFirewall{firewall: f, fc: fc, taps: taps, limit: newCallLimit(maxNetworkCalls, maxNetworkWaiting)}
}

func (g *guestFirewall) close() {
	if g != nil {
		g.firewall.close()
	}
}

// ensure puts the guests' NAT and isolation in, then their chain, block
// sets and floor, and starts the timer that puts them back.
func (g *guestFirewall) ensure(ctx context.Context) (*rootdpb.EnsureGuestFirewallResponse, error) {
	if err := g.taps.ensureNetwork(); err != nil {
		return nil, &fileError{code: codes.Unavailable,
			msg: "root helper: the Firecracker guests' NAT and isolation are not in place, so their firewall is not set up: " + err.Error()}
	}
	if _, err := g.ensureHost(ctx); err != nil {
		return nil, err
	}
	return &rootdpb.EnsureGuestFirewallResponse{}, nil
}

// guestAddrKey is the per-object lock key of a guest address's rules (D11).
func guestAddrKey(ip string) string { return "guest-addr/" + ip }

func (g *guestFirewall) rules(ctx context.Context, req *rootdpb.GuestRulesRequest) (*rootdpb.GuestRulesResponse, error) {
	op := req.GetOp()
	if !writeOps[op] && !clearOps[op] {
		return nil, badRequest("root helper: guest rules op %v is not one the helper does", op)
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
	slot, err := rootpolicy.CheckGuestAddress(g.fc.TapBase, g.fc.TapPoolSize, req.GetGuestIp())
	if err != nil {
		return nil, refusedRule(codes.InvalidArgument, err)
	}
	ip := slot.GuestIP
	h, _, err := g.opened()
	if err != nil {
		return nil, err
	}
	done, err := g.limit.enter(ctx)
	if err != nil {
		return nil, err
	}
	defer done()
	unlock, err := g.locks.lock(ctx, guestAddrKey(ip))
	if err != nil {
		return nil, err
	}
	defer unlock()
	if op == rootdpb.SandboxRulesOp_SANDBOX_RULES_OP_APPLY_EGRESS_POLICY {
		if err := g.budget.reserve(ip, len(allow)+len(deny)+1); err != nil {
			return nil, err
		}
	}
	inserted, err := h.Rules(ctx, op, ip, allow, deny)
	if op == rootdpb.SandboxRulesOp_SANDBOX_RULES_OP_CLEAR_EGRESS_POLICY && err == nil {
		g.budget.release(ip)
	}
	if err != nil {
		return nil, fmt.Errorf("root helper: %v on guest %s: %w", op, ip, err)
	}
	return &rootdpb.GuestRulesResponse{Inserted: inserted}, nil
}
