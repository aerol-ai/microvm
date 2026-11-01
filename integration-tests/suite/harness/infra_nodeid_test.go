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

// Terraform's integration_targets carries api_load_balancer as an object, or
// null when the scenario has no balancer. UC-356 reads the balancer's IP and
// the 443 target group from it; null must load as nil, not as a zero value
// whose empty IP a case could mistake for "resolves to nothing".
func TestLoadIntegrationTargetsReadsTheLoadBalancer(t *testing.T) {
	t.Setenv("AEROL_INTEGRATION_TARGETS", `{"domain":"lb.itest.example.com","api_load_balancer":{"ip":"198.51.100.7","dns_name":"x.elb.us-east-1.amazonaws.com","l4_host":"tcp.lb.itest.example.com","health_check_port":21280,"target_group_arns":{"443":"arn:aws:elasticloadbalancing:us-east-1:111122223333:targetgroup/x/abc","80":"arn:80","2220":"arn:2220"}},"nodes":[]}`)
	got := LoadIntegrationTargets()
	if got == nil || got.APILoadBalancer == nil {
		t.Fatalf("api_load_balancer not loaded: %+v", got)
	}
	lb := got.APILoadBalancer
	if lb.IP != "198.51.100.7" || lb.L4Host != "tcp.lb.itest.example.com" || lb.HealthCheckPort != 21280 || lb.TargetGroupARNs["443"] != "arn:aws:elasticloadbalancing:us-east-1:111122223333:targetgroup/x/abc" {
		t.Fatalf("api_load_balancer = %+v", lb)
	}

	t.Setenv("AEROL_INTEGRATION_TARGETS", `{"domain":"x.example.com","api_load_balancer":null,"nodes":[]}`)
	if got := LoadIntegrationTargets(); got == nil || got.APILoadBalancer != nil {
		t.Fatalf("a scenario without a balancer must load api_load_balancer as nil: %+v", got)
	}
}
