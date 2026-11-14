package webhook

import (
	"os"
	"slices"
	"strings"
	"testing"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	policyv1 "k8s.io/api/policy/v1"
	"sigs.k8s.io/yaml"

	v1 "github.com/aerol-ai/microvm/operator/api/v1alpha1"
)

// The chart holds worker pods against eviction twice (R13): a
// PodDisruptionBudget that allows none, and the guard's webhook rule for
// pods/eviction. Without both, kubectl drain or a managed node group update
// evicts a worker before its sandboxes move: an eviction never reaches the
// DELETE rule. CI renders templates/operator.yaml and points
// AEROLVM_CHART_OPERATOR at it; without it the test skips.
func TestChartGuardsWorkerEvictions(t *testing.T) {
	path := os.Getenv("AEROLVM_CHART_OPERATOR")
	if path == "" {
		t.Skip("AEROLVM_CHART_OPERATOR not set: no rendered chart to check")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	const workerNS = "aerolvm-workers"
	var pdbs []policyv1.PodDisruptionBudget
	var hooks []admissionregistrationv1.ValidatingWebhook
	for _, doc := range strings.Split("\n"+string(raw), "\n---") {
		var head struct {
			Kind string `json:"kind"`
		}
		if err := yaml.Unmarshal([]byte(doc), &head); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		switch head.Kind {
		case "PodDisruptionBudget":
			var p policyv1.PodDisruptionBudget
			if err := yaml.UnmarshalStrict([]byte(doc), &p); err != nil {
				t.Fatal(err)
			}
			pdbs = append(pdbs, p)
		case "ValidatingWebhookConfiguration":
			var c admissionregistrationv1.ValidatingWebhookConfiguration
			if err := yaml.UnmarshalStrict([]byte(doc), &c); err != nil {
				t.Fatal(err)
			}
			hooks = append(hooks, c.Webhooks...)
		}
	}

	// The budget: one, in the worker namespace, none allowed, over exactly
	// this cluster's worker pods (two budgets over one pod break eviction).
	if len(pdbs) != 1 {
		t.Fatalf("the chart renders %d PodDisruptionBudgets, want 1 over the worker pods", len(pdbs))
	}
	p := pdbs[0]
	if p.Namespace != workerNS {
		t.Errorf("the budget is in %q, want %q", p.Namespace, workerNS)
	}
	if p.Spec.MaxUnavailable == nil || p.Spec.MaxUnavailable.IntValue() != 0 || p.Spec.MaxUnavailable.String() != "0" || p.Spec.MinAvailable != nil {
		t.Errorf("the budget must allow no eviction (maxUnavailable: 0): %+v", p.Spec)
	}
	sel := p.Spec.Selector
	if sel == nil || len(sel.MatchExpressions) != 0 || sel.MatchLabels["app.kubernetes.io/name"] != "aerolvm" ||
		sel.MatchLabels["app.kubernetes.io/component"] != v1.RoleWorker || sel.MatchLabels["aerolvm.io/cluster"] == "" || len(sel.MatchLabels) != 3 {
		t.Errorf("the budget must select this cluster's worker pods by the labels the operator stamps: %+v", sel)
	}

	// The webhook rules: deletes by label, evictions by namespace (an
	// Eviction carries no pod labels, so an objectSelector never matches
	// it), both to the guard, both failing open.
	var del, evict *admissionregistrationv1.ValidatingWebhook
	for i := range hooks {
		for _, r := range hooks[i].Rules {
			switch {
			case slices.Contains(r.Operations, admissionregistrationv1.Delete) && slices.Contains(r.Resources, "pods"):
				del = &hooks[i]
			case slices.Contains(r.Operations, admissionregistrationv1.Create) && slices.Contains(r.Resources, "pods/eviction"):
				evict = &hooks[i]
			}
		}
	}
	if del == nil || evict == nil {
		t.Fatalf("the chart's webhook must guard pod DELETE and pods/eviction CREATE (delete: %v, eviction: %v)", del != nil, evict != nil)
	}
	for name, h := range map[string]*admissionregistrationv1.ValidatingWebhook{"delete": del, "eviction": evict} {
		if h.ClientConfig.Service == nil || h.ClientConfig.Service.Path == nil || *h.ClientConfig.Service.Path != Path {
			t.Errorf("the %s rule must call %s", name, Path)
		}
		if h.FailurePolicy == nil || *h.FailurePolicy != admissionregistrationv1.Ignore {
			t.Errorf("the %s rule must fail open (failurePolicy Ignore), so an operator outage never blocks a repair", name)
		}
		if h.NamespaceSelector == nil || h.NamespaceSelector.MatchLabels["kubernetes.io/metadata.name"] != workerNS {
			t.Errorf("the %s rule must be limited to the worker namespace: %+v", name, h.NamespaceSelector)
		}
	}
	if evict.ObjectSelector != nil && (len(evict.ObjectSelector.MatchLabels) != 0 || len(evict.ObjectSelector.MatchExpressions) != 0) {
		t.Errorf("the eviction rule has an objectSelector, which an Eviction never matches: %+v", evict.ObjectSelector)
	}
}
