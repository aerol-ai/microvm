package controller

import (
	"os"
	"slices"
	"strings"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	"sigs.k8s.io/yaml"
)

// clusterScoped are the resources the operator reads that live outside any
// namespace: the chart must grant them in its ClusterRole. A new one in a
// +kubebuilder:rbac marker goes here too.
var clusterScoped = []string{"nodes", "nodeclaims", "servicecidrs"}

// The chart grants the operator every right its +kubebuilder:rbac markers
// ask for (config/rbac/role.yaml, generated): cluster-scoped ones in its
// ClusterRole, the rest in both namespaces it works in, and the default
// namespace's in a Role there. A right only the markers have fails live,
// on a real cluster, and nowhere else. CI renders templates/operator.yaml
// and points AEROLVM_CHART_OPERATOR at it; without it the test skips.
func TestChartGrantsGeneratedRBAC(t *testing.T) {
	path := os.Getenv("AEROLVM_CHART_OPERATOR")
	if path == "" {
		t.Skip("AEROLVM_CHART_OPERATOR not set: no rendered chart to check")
	}
	chart := readRBAC(t, path)
	gen := readRBAC(t, "../../config/rbac/role.yaml")
	const releaseNS, workerNS = "aerolvm-system", "aerolvm-workers"
	for _, g := range gen.clusterRoles {
		for _, rule := range g.Rules {
			eachRight(rule, func(group, res, verb string) {
				if slices.Contains(clusterScoped, strings.Split(res, "/")[0]) {
					if !grants(chart.clusterRoles, group, res, verb, nil) {
						t.Errorf("the chart's ClusterRole lacks %s %s/%s", verb, group, res)
					}
					return
				}
				for _, ns := range []string{releaseNS, workerNS} {
					if !grants(chart.clusterRoles, group, res, verb, nil) && !grants(chart.roles[ns], group, res, verb, nil) {
						t.Errorf("the chart lacks %s %s/%s in %s", verb, group, res, ns)
					}
				}
			})
		}
	}
	for ns, roles := range gen.roles {
		for _, r := range roles {
			for _, rule := range r.Rules {
				eachRight(rule, func(group, res, verb string) {
					if !grants(chart.roles[ns], group, res, verb, rule.ResourceNames) {
						t.Errorf("the chart lacks %s %s/%s %v in %s", verb, group, res, rule.ResourceNames, ns)
					}
				})
			}
		}
	}
}

type rbacDocs struct {
	clusterRoles []rbacv1.ClusterRole
	roles        map[string][]rbacv1.ClusterRole // by namespace; a Role's rules
}

func readRBAC(t *testing.T, path string) rbacDocs {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	out := rbacDocs{roles: map[string][]rbacv1.ClusterRole{}}
	for _, doc := range strings.Split("\n"+string(raw), "\n---") {
		var head struct {
			Kind     string `json:"kind"`
			Metadata struct {
				Namespace string `json:"namespace"`
			} `json:"metadata"`
		}
		if err := yaml.Unmarshal([]byte(doc), &head); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		var r rbacv1.ClusterRole
		switch head.Kind {
		case "ClusterRole", "Role":
			if err := yaml.Unmarshal([]byte(doc), &r); err != nil {
				t.Fatalf("%s: %v", path, err)
			}
		default:
			continue
		}
		if head.Kind == "ClusterRole" {
			out.clusterRoles = append(out.clusterRoles, r)
		} else {
			out.roles[head.Metadata.Namespace] = append(out.roles[head.Metadata.Namespace], r)
		}
	}
	return out
}

func eachRight(rule rbacv1.PolicyRule, f func(group, res, verb string)) {
	for _, g := range rule.APIGroups {
		for _, res := range rule.Resources {
			for _, v := range rule.Verbs {
				f(g, res, v)
			}
		}
	}
}

// grants reports whether one of roles allows verb on group/res, for every
// one of names (none: on all of them).
func grants(roles []rbacv1.ClusterRole, group, res, verb string, names []string) bool {
	for _, r := range roles {
		for _, rule := range r.Rules {
			if !slices.Contains(rule.APIGroups, group) || !slices.Contains(rule.Resources, res) || !slices.Contains(rule.Verbs, verb) {
				continue
			}
			if len(rule.ResourceNames) == 0 {
				return true
			}
			if len(names) > 0 && !slices.ContainsFunc(names, func(n string) bool { return !slices.Contains(rule.ResourceNames, n) }) {
				return true
			}
		}
	}
	return false
}
