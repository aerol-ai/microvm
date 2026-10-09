package tap

import (
	"fmt"
	"net/netip"
)

// natComment marks the masquerade rule so operators can find it
// (`iptables -t nat -S POSTROUTING | grep aerolvm-fc-masq`).
const natComment = "aerolvm-fc-masq"

// NATBackend is the iptables subset EnsureNAT drives; *iptables.IPTables
// (coreos/go-iptables) satisfies it.
type NATBackend interface {
	Exists(table, chain string, rulespec ...string) (bool, error)
	Append(table, chain string, rulespec ...string) error
}

// EnsureNAT masquerades Firecracker guests' outbound traffic
// (plans/egress-domain-filtering.md Phase 4). A TAP slot is a routed /30,
// not a bridge, so a guest's packets leave the host with its private
// source and no reply ever finds it; nothing in the repo or the
// provisioning set up SNAT for them (the TODOS.md "Audit Firecracker
// outbound NAT path" gap). Traffic between guests stays unmasqueraded.
// Idempotent: run at every daemon start.
func EnsureNAT(be NATBackend, baseCIDR string) error {
	p, err := netip.ParsePrefix(baseCIDR)
	if err != nil || !p.Addr().Is4() {
		return fmt.Errorf("tap nat: %q is not an IPv4 CIDR", baseCIDR)
	}
	cidr := p.Masked().String()
	spec := []string{"-s", cidr, "!", "-d", cidr, "-m", "comment", "--comment", natComment, "-j", "MASQUERADE"}
	ok, err := be.Exists("nat", "POSTROUTING", spec...)
	if err != nil {
		return fmt.Errorf("tap nat: check masquerade: %w", err)
	}
	if ok {
		return nil
	}
	if err := be.Append("nat", "POSTROUTING", spec...); err != nil {
		return fmt.Errorf("tap nat: add masquerade: %w", err)
	}
	return nil
}
