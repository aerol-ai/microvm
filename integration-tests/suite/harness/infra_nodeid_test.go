package harness

import "testing"

func TestIntegrationNodeForClusterID(t *testing.T) {
	targets := &IntegrationTargets{Nodes: []IntegrationNode{{Name: "node3"}, {Name: "node13"}, {Name: "worker-x"}}}
	for id, want := range map[string]string{
		"node3": "node3",
		"aerolvm-itest-cluster-3-mixed-routing-node3":  "node3",
		"aerolvm-itest-cluster-3-mixed-routing-node13": "node13",
		"aerolvm-itest-hetero-worker-x":                "worker-x",
		"somethingnode3":                               "",
		"":                                             "",
	} {
		n, ok := IntegrationNodeForClusterID(targets, id)
		if n.Name != want || ok != (want != "") {
			t.Errorf("%q -> %q ok=%v, want %q", id, n.Name, ok, want)
		}
	}
	if _, ok := IntegrationNodeForClusterID(nil, "x"); ok {
		t.Error("nil targets matched")
	}
}
