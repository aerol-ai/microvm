package netrules

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"sync"
)

// ChainAerolvmNode is the node guard: sandboxes are default-denied from the
// node they run on. Every packet a sandbox subnet sends to the node itself
// (its bridge gateways, its private and any locally bound public address:
// whatever reaches INPUT) is dropped unless it answers a connection the host
// opened (sandboxd to the toolbox) or goes to a port on the allowlist the
// service computes (the egress gateway's DNS and proxy ports, and the few
// others setup/config-defaults.md lists).
//
// It replaces an enumerated list of ports to drop (the control-port guard):
// a node also runs services AerolVM does not know about (an EDR agent, a log
// shipper, a node exporter, a SIEM forwarder), and every one of them was
// reachable from every default sandbox.
//
// Layout, all in the filter table:
//
//	INPUT          first rule: -j AEROLVM-NODE (kept first, like the floor's jump)
//	AEROLVM-NODE   1: conntrack RELATED,ESTABLISHED -j RETURN
//	               then per sandbox subnet: -s <subnet> -j AEROLVM-NODE-<hash>-A|B
//	AEROLVM-NODE-<hash>-A|B
//	               -s <subnet> [-d <addr>] -p tcp|udp --dport N -j RETURN (the allowlist)
//	               -s <subnet> -j DROP
//
// Its own chain, not rules in AEROLVM-INPUT, so no per-sandbox rule can sit
// above it: an allowlist RETURN for a CIDR that covers the node's address
// (AEROLVM-INPUT's inputPolicyReturnSpec) would otherwise skip the guard.
// RETURN, never ACCEPT, so a host firewall such as ufw still decides what it
// lets in.
const ChainAerolvmNode = "AEROLVM-NODE"

// nodeGuardComment tags the guard's own rules in its per-subnet chains.
const nodeGuardComment = "sbx-node-guard"

var (
	// ErrNodeGuardDisabled means network rules are off on this node, so
	// nothing keeps sandboxes off the node's own services.
	ErrNodeGuardDisabled = errors.New("netrules: network rules are disabled; sandboxes can reach every service on this node")
	// ErrNodeGuardUnsupported means the rule backend cannot manage chains.
	ErrNodeGuardUnsupported = errors.New("netrules: backend cannot manage the node guard chains")
)

// NodePort is one thing sandboxes may still reach on their own node.
type NodePort struct {
	// Proto is "tcp" or "udp".
	Proto string
	// Port is the destination port, 1-65535.
	Port uint16
	// Dst narrows the entry to one node address (a resolver the sandboxes
	// are pointed at); the zero value allows the port on every address.
	Dst netip.Addr
}

// String is "tcp/15080", or "udp/53@10.0.1.5" for one address.
func (p NodePort) String() string {
	s := p.Proto + "/" + strconv.Itoa(int(p.Port))
	if p.Dst.IsValid() {
		s += "@" + p.Dst.String()
	}
	return s
}

func (p NodePort) valid() error {
	switch {
	case p.Proto != "tcp" && p.Proto != "udp":
		return fmt.Errorf("node guard entry %s: protocol must be tcp or udp", p)
	case p.Port == 0:
		return fmt.Errorf("node guard entry %s: port must be 1-65535", p)
	case p.Dst.IsValid() && !p.Dst.Is4():
		return fmt.Errorf("node guard entry %s: the guard is IPv4", p)
	}
	return nil
}

func (p NodePort) spec(src string) []string {
	s := []string{"-s", src}
	if p.Dst.IsValid() {
		s = append(s, "-d", p.Dst.String())
	}
	return append(s, "-p", p.Proto, "--dport", strconv.Itoa(int(p.Port)), "-m", "comment", "--comment", nodeGuardComment, "-j", "RETURN")
}

func nodeDropSpec(src string) []string {
	return []string{"-s", src, "-m", "comment", "--comment", nodeGuardComment, "-j", "DROP"}
}

func nodeJumpSpec(src, chain string) []string {
	return []string{"-s", src, "-j", chain}
}

// NodeChainsFor is the pair of chains one sandbox subnet's guard alternates
// between: a new allowlist is built in the one nothing jumps to, then the
// jump moves, so a change never leaves the subnet unguarded (a flush and
// refill of one chain would, briefly). 23 characters, inside iptables' 28.
func NodeChainsFor(subnet netip.Prefix) [2]string {
	sum := sha256.Sum256([]byte(subnet.Masked().String()))
	base := ChainAerolvmNode + "-" + hex.EncodeToString(sum[:4])
	return [2]string{base + "-A", base + "-B"}
}

// nodeBackend is the chain management the guard needs: both shipped
// backends implement all of it.
type nodeBackend interface {
	RuleBackend
	bootstrapBackend
	inputBootstrapBackend
	floorBackend
}

// nodeMu serializes guard changes: AEROLVM-NODE is shared by every Manager
// in the process (docker, containerd, Firecracker), and a change is several
// rule operations.
var nodeMu sync.Mutex

// nodeGuardState is what SetNodeGuard installed, for ReassertNodeGuard.
type nodeGuardState struct {
	subnet netip.Prefix
	allow  []NodePort
}

// SetNodeGuard default-denies sandboxes on subnet from the node itself,
// except allow. Replacing the allowlist is safe while sandboxes run: the new
// list goes into the subnet's idle chain, the jump moves to it, then the old
// chain is emptied. In between, a packet passes both chains, so it gets
// through only if both allow it (fail closed, never open). Idempotent: the
// service calls it at boot and whenever the allowlist changes.
func (m *Manager) SetNodeGuard(subnet netip.Prefix, allow []NodePort) error {
	if m == nil || !m.Enabled() {
		return ErrNodeGuardDisabled
	}
	if !subnet.IsValid() || !subnet.Addr().Is4() {
		return fmt.Errorf("netrules: node guard needs an IPv4 sandbox subnet, got %q", subnet)
	}
	for _, p := range allow {
		if err := p.valid(); err != nil {
			return err
		}
	}
	nb, ok := m.ipt.(nodeBackend)
	if !ok {
		return ErrNodeGuardUnsupported
	}
	nodeMu.Lock()
	defer nodeMu.Unlock()
	subnet = subnet.Masked()
	if err := ensureNodeChains(nb, subnet); err != nil {
		return err
	}
	src := subnet.String()
	chains := NodeChainsFor(subnet)
	activeA, err := nb.Exists("filter", ChainAerolvmNode, nodeJumpSpec(src, chains[0])...)
	if err != nil {
		return fmt.Errorf("node guard: check active chain: %w", err)
	}
	next, prev := chains[0], chains[1]
	if activeA {
		next, prev = chains[1], chains[0]
	}
	// Fill next. Each rule goes in at the top, so the drop goes first and
	// ends up last.
	if err := nb.FlushChain(next); err != nil {
		return fmt.Errorf("node guard: flush %s: %w", next, err)
	}
	if err := nb.Insert("filter", next, 1, nodeDropSpec(src)...); err != nil {
		return fmt.Errorf("node guard: drop rule: %w", err)
	}
	for _, p := range slices.Backward(allow) {
		if err := nb.Insert("filter", next, 1, p.spec(src)...); err != nil {
			return fmt.Errorf("node guard: allow %s: %w", p, err)
		}
	}
	// Jump to next, just below the established-return rule, before the old
	// jump goes.
	jumped, err := nb.Exists("filter", ChainAerolvmNode, nodeJumpSpec(src, next)...)
	if err != nil {
		return fmt.Errorf("node guard: check jump: %w", err)
	}
	if !jumped {
		if err := nb.Insert("filter", ChainAerolvmNode, 2, nodeJumpSpec(src, next)...); err != nil {
			return fmt.Errorf("node guard: jump to %s: %w", next, err)
		}
	}
	if err := m.deleteUntilGone("filter", ChainAerolvmNode, nodeJumpSpec(src, prev)...); err != nil {
		return fmt.Errorf("node guard: remove the jump to %s: %w", prev, err)
	}
	if err := nb.FlushChain(prev); err != nil {
		return fmt.Errorf("node guard: flush %s: %w", prev, err)
	}
	m.nodeGuard.Store(&nodeGuardState{subnet: subnet, allow: slices.Clone(allow)})
	return nil
}

// ReassertNodeGuard puts the guard back if something removed it: the INPUT
// jump (a host firewall reload that rewrote INPUT, or one that put its own
// rules above ours), the established-return rule, the subnet's jump, or the
// drop at the end of its chain (a flush). Cheap when nothing is missing: a
// handful of rule checks. repaired reports that the guard was rebuilt. A
// no-op until SetNodeGuard has succeeded once.
func (m *Manager) ReassertNodeGuard() (repaired bool, err error) {
	if m == nil || !m.Enabled() {
		return false, nil
	}
	st := m.nodeGuard.Load()
	if st == nil {
		return false, nil
	}
	nb, ok := m.ipt.(nodeBackend)
	if !ok {
		return false, ErrNodeGuardUnsupported
	}
	intact, err := func() (bool, error) {
		nodeMu.Lock()
		defer nodeMu.Unlock()
		if err := ensureNodeChains(nb, st.subnet); err != nil {
			return false, err
		}
		src := st.subnet.String()
		for _, c := range NodeChainsFor(st.subnet) {
			jumped, err := nb.Exists("filter", ChainAerolvmNode, nodeJumpSpec(src, c)...)
			if err != nil {
				return false, fmt.Errorf("node guard: check jump to %s: %w", c, err)
			}
			if !jumped {
				continue
			}
			dropped, err := nb.Exists("filter", c, nodeDropSpec(src)...)
			if err != nil {
				return false, fmt.Errorf("node guard: check %s: %w", c, err)
			}
			if dropped {
				return true, nil
			}
		}
		return false, nil
	}()
	if err != nil || intact {
		return false, err
	}
	return true, m.SetNodeGuard(st.subnet, st.allow)
}

// ensureNodeChains creates AEROLVM-NODE with its established-return first
// rule, makes the jump to it the first rule of INPUT, and creates the
// subnet's two chains. Both must exist before any rule names them: iptables
// refuses even to check (-C) a jump to a chain that is not there. Callers
// hold nodeMu.
func ensureNodeChains(nb nodeBackend, subnet netip.Prefix) error {
	if err := nb.EnsureInputChain(ChainAerolvmNode); err != nil {
		return fmt.Errorf("node guard: bootstrap %s: %w", ChainAerolvmNode, err)
	}
	if err := nb.EnsureJumpChain("INPUT", ChainAerolvmNode); err != nil {
		return fmt.Errorf("node guard: keep the INPUT jump first: %w", err)
	}
	for _, c := range NodeChainsFor(subnet) {
		if err := nb.EnsureUserChain(c); err != nil {
			return fmt.Errorf("node guard chain %s: %w", c, err)
		}
	}
	return nil
}
