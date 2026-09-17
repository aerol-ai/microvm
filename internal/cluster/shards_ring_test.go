package cluster

import (
	"testing"

	"github.com/aerol-ai/microvm/internal/config"
)

// ringMembersClient reports different membership from LocalMembers (gossip)
// and Members (control-plane snapshot), which is exactly the Agent's shape.
type ringMembersClient struct {
	Client
	local  []Member
	remote []Member
}

func (c *ringMembersClient) LocalMembers() []Member { return c.local }
func (c *ringMembersClient) Members() []Member      { return c.remote }

func ingressMembers(ids ...string) []Member {
	out := make([]Member, 0, len(ids))
	for _, id := range ids {
		out = append(out, Member{NodeID: id, Alive: true, Role: config.NodeRoleIngress, PublicHost: id + ".example.test"})
	}
	return out
}

// TestIngressRingMembersPrefersLocalGossip pins the one view both halves of
// the shard-aware ingress path hash. Installation acts on local gossip, so a
// lookup that hashed a control-plane snapshot instead could hand the upstream
// a node that never installed the shard.
func TestIngressRingMembersPrefersLocalGossip(t *testing.T) {
	c := &ringMembersClient{
		local:  ingressMembers("n1", "n2", "n3"),
		remote: ingressMembers("n1", "n2", "n3", "n4"),
	}
	got := IngressRingMembers(c)
	if len(got) != 3 {
		t.Fatalf("IngressRingMembers = %d members, want the 3 from local gossip", len(got))
	}

	// A node whose gossip is not up yet still answers, from the control plane.
	c.local = nil
	if got := IngressRingMembers(c); len(got) != 4 {
		t.Fatalf("empty-gossip fallback = %d members, want the 4 from the control plane", len(got))
	}
	if got := IngressRingMembers(nil); got != nil {
		t.Fatalf("nil client = %v, want nil", got)
	}
}

// TestIngressRingVersionTracksMembership pins the observability half: equal
// membership hashes equal, and any change to the ingress-eligible set changes
// the version so divergence between ingress nodes is visible.
func TestIngressRingVersionTracksMembership(t *testing.T) {
	a := IngressRingVersion(ingressMembers("n1", "n2", "n3"))
	if a == "" {
		t.Fatal("ring version is empty for a populated ring")
	}
	// Order must not matter — two nodes list members in whatever order gossip
	// gave them.
	if b := IngressRingVersion(ingressMembers("n3", "n1", "n2")); b != a {
		t.Fatalf("ring version is order-sensitive: %q vs %q", a, b)
	}
	if b := IngressRingVersion(ingressMembers("n1", "n2", "n3", "n4")); b == a {
		t.Fatal("ring version did not change when a member joined")
	}
	if b := IngressRingVersion(ingressMembers("n1", "n2")); b == a {
		t.Fatal("ring version did not change when a member left")
	}
	if got := IngressRingVersion(nil); got != "" {
		t.Fatalf("empty ring version = %q, want empty", got)
	}
}

// TestIngressRouteCarriesRingVersion pins that the served route names the ring
// it was computed from.
func TestIngressRouteCarriesRingVersion(t *testing.T) {
	members := ingressMembers("n1", "n2", "n3")
	route := IngressRouteForSandbox(members, "sb-ring")
	if route.RingVersion != IngressRingVersion(members) {
		t.Fatalf("route ring version = %q, want %q", route.RingVersion, IngressRingVersion(members))
	}
}
