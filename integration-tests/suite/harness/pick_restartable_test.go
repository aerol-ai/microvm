package harness

import "testing"

func TestPickRestartableNodeSparesTheSeedAndTheIngress(t *testing.T) {
	n := func(name, role string, seed bool) IntegrationNode {
		return IntegrationNode{Name: name, Role: role, Seed: seed, PublicIP: "10.0.0.1"}
	}
	cases := []struct {
		name  string
		nodes []IntegrationNode
		want  string
	}{
		// The T18 hetero order: ingress listed first after the seed.
		{"hetero picks a worker, not the only ingress", []IntegrationNode{
			n("server-1", "server", true), n("ingress-1", "ingress", false), n("server-2", "server", false), n("worker-x", "worker", false),
		}, "worker-x"},
		{"a non-seed server beats the ingress", []IntegrationNode{
			n("server-1", "server", true), n("ingress-1", "ingress", false), n("server-2", "server", false),
		}, "server-2"},
		{"mixed 3-node picks the first joiner", []IntegrationNode{
			n("node1", "mixed", true), n("node2", "mixed", false), n("node3", "mixed", false),
		}, "node2"},
		{"ingress only when nothing else but the seed", []IntegrationNode{
			n("server-1", "server", true), n("ingress-1", "ingress", false),
		}, "ingress-1"},
		{"single node falls back to the seed", []IntegrationNode{n("node1", "mixed", true)}, "node1"},
		{"unreachable nodes are never picked", []IntegrationNode{
			n("node1", "mixed", true), {Name: "ghost", Role: "worker"},
		}, "node1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := PickRestartableNode(&IntegrationTargets{Nodes: tc.nodes})
			if !ok || got.Name != tc.want {
				t.Fatalf("picked %q (ok=%v), want %q", got.Name, ok, tc.want)
			}
		})
	}
	if _, ok := PickRestartableNode(nil); ok {
		t.Fatal("nil targets must pick nothing")
	}
}
