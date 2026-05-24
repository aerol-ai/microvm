package cluster

import (
	"testing"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/models"
)

func TestAggregateIngressTargets_HostnameOnly(t *testing.T) {
	members := []Member{
		{NodeID: "a", Role: config.NodeRoleIngress, PublicHost: "ingress.example.com", Alive: true},
		{NodeID: "b", Role: config.NodeRoleIngress, PublicHost: "ingress.example.com", Alive: true},
	}
	got := aggregateIngressTargets(members)
	if got.Hostname != "ingress.example.com" || len(got.IPs) != 0 {
		t.Fatalf("want single hostname target, got %+v", got)
	}
	if got.Source != models.IngressTargetSourceHostname {
		t.Fatalf("Source=%q, want hostname", got.Source)
	}
}

func TestAggregateIngressTargets_IPsOnly(t *testing.T) {
	members := []Member{
		{NodeID: "a", Role: config.NodeRoleIngress, PublicHost: "203.0.113.10", Alive: true},
		{NodeID: "b", Role: config.NodeRoleIngress, PublicHost: "203.0.113.11", Alive: true},
		{NodeID: "c", Role: config.NodeRoleIngress, PublicHost: "203.0.113.10", Alive: true}, // dup
	}
	got := aggregateIngressTargets(members)
	if got.Hostname != "" {
		t.Fatalf("hostname=%q, want empty", got.Hostname)
	}
	if len(got.IPs) != 2 || got.IPs[0] != "203.0.113.10" || got.IPs[1] != "203.0.113.11" {
		t.Fatalf("want sorted deduped IPs, got %+v", got.IPs)
	}
	if got.Source != models.IngressTargetSourceIPs {
		t.Fatalf("Source=%q, want ips", got.Source)
	}
}

func TestAggregateIngressTargets_MixedHostnameAndIPs(t *testing.T) {
	members := []Member{
		{NodeID: "a", Role: config.NodeRoleIngress, PublicHost: "ingress.example.com", Alive: true},
		{NodeID: "b", Role: config.NodeRoleIngress, PublicHost: "203.0.113.10", Alive: true},
	}
	got := aggregateIngressTargets(members)
	if got.Hostname != "ingress.example.com" || len(got.IPs) != 1 {
		t.Fatalf("expected both hostname and IP, got %+v", got)
	}
	if got.Source != models.IngressTargetSourceMixed {
		t.Fatalf("Source=%q, want mixed", got.Source)
	}
}

func TestAggregateIngressTargets_ExcludesDeadMembers(t *testing.T) {
	members := []Member{
		{NodeID: "a", Role: config.NodeRoleIngress, PublicHost: "ingress.example.com", Alive: false},
		{NodeID: "b", Role: config.NodeRoleIngress, PublicHost: "203.0.113.10", Alive: true},
	}
	got := aggregateIngressTargets(members)
	if got.Hostname != "" {
		t.Fatalf("dead member's hostname leaked: %q", got.Hostname)
	}
	if len(got.IPs) != 1 || got.IPs[0] != "203.0.113.10" {
		t.Fatalf("want only the live member's IP, got %+v", got.IPs)
	}
}

func TestAggregateIngressTargets_ExcludesNonIngressRoles(t *testing.T) {
	// Worker-only nodes don't run a public listener so users mustn't point
	// DNS at them. Server-only (control plane) likewise.
	members := []Member{
		{NodeID: "w", Role: config.NodeRoleWorker, PublicHost: "203.0.113.99", Alive: true},
		{NodeID: "s", Role: config.NodeRoleServer, PublicHost: "203.0.113.100", Alive: true},
		{NodeID: "i", Role: config.NodeRoleIngress, PublicHost: "203.0.113.10", Alive: true},
	}
	got := aggregateIngressTargets(members)
	if len(got.IPs) != 1 || got.IPs[0] != "203.0.113.10" {
		t.Fatalf("non-ingress roles leaked into target: %+v", got)
	}
}

func TestAggregateIngressTargets_TreatsEmptyRoleAsMixed(t *testing.T) {
	// Pre-role-flag builds gossip Role="" — must still contribute so a
	// rolling upgrade doesn't silently drop ingress nodes.
	members := []Member{
		{NodeID: "old", Role: "", PublicHost: "ingress.example.com", Alive: true},
	}
	got := aggregateIngressTargets(members)
	if got.Hostname != "ingress.example.com" {
		t.Fatalf("empty-role member should contribute, got %+v", got)
	}
}

func TestAggregateIngressTargets_MixedRoleCounts(t *testing.T) {
	members := []Member{
		{NodeID: "m", Role: config.NodeRoleMixed, PublicHost: "203.0.113.10", Alive: true},
		{NodeID: "wi", Role: "worker,ingress", PublicHost: "203.0.113.11", Alive: true},
	}
	got := aggregateIngressTargets(members)
	if len(got.IPs) != 2 {
		t.Fatalf("mixed and combined-ingress roles should count, got %+v", got)
	}
}

func TestAggregateIngressTargets_EmptyPublicHostSkipped(t *testing.T) {
	members := []Member{
		{NodeID: "a", Role: config.NodeRoleIngress, PublicHost: "", Alive: true},
		{NodeID: "b", Role: config.NodeRoleIngress, PublicHost: "ingress.example.com", Alive: true},
	}
	got := aggregateIngressTargets(members)
	if got.Hostname != "ingress.example.com" {
		t.Fatalf("upgraded member's hostname should still appear when peers are empty, got %+v", got)
	}
}

func TestAggregateIngressTargets_NoLiveIngressReturnsUnknown(t *testing.T) {
	members := []Member{
		{NodeID: "w", Role: config.NodeRoleWorker, PublicHost: "x", Alive: true},
	}
	got := aggregateIngressTargets(members)
	if got.Source != models.IngressTargetSourceUnknown {
		t.Fatalf("Source=%q, want unknown when no ingress nodes contribute", got.Source)
	}
}

func TestAggregateIngressTargets_PicksLexicallyFirstHostname(t *testing.T) {
	// Two distinct ingress hostnames is unusual — we surface the first
	// alphabetically so the result is deterministic and tests can pin it.
	members := []Member{
		{NodeID: "a", Role: config.NodeRoleIngress, PublicHost: "zeta.example.com", Alive: true},
		{NodeID: "b", Role: config.NodeRoleIngress, PublicHost: "alpha.example.com", Alive: true},
	}
	got := aggregateIngressTargets(members)
	if got.Hostname != "alpha.example.com" {
		t.Fatalf("Hostname=%q, want alpha.example.com (deterministic ordering)", got.Hostname)
	}
}

func TestNoopIngressTargets_HasPublicHost(t *testing.T) {
	n := NewNoop("self", "http://self", "ingress.example.com")
	got := n.IngressTargets()
	if got.Hostname != "ingress.example.com" || got.Source != models.IngressTargetSourceHostname {
		t.Fatalf("unexpected Noop target: %+v", got)
	}
}

func TestNoopIngressTargets_NoPublicHostReturnsUnknown(t *testing.T) {
	n := NewNoop("self", "http://self", "")
	got := n.IngressTargets()
	if got.Source != models.IngressTargetSourceUnknown {
		t.Fatalf("Source=%q, want unknown when publicHost unset", got.Source)
	}
}
