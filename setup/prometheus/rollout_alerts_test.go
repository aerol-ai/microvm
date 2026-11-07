package prometheus_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestRolloutAlertRules lints the rollout alert group
// (plans/kubectl-style-cluster-ops.md §10.1): the four alerts exist with
// their severities, every rule is complete, every metric it queries is
// registered in the Go tree, labels are the positional key an expvar map
// exports, and every runbook_url lands on a heading of
// setup/runbooks/cluster-upgrades.md.
func TestRolloutAlertRules(t *testing.T) {
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "setup", "prometheus", "sandboxd-alerts.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var rules ruleFile
	if err := yaml.Unmarshal(raw, &rules); err != nil {
		t.Fatalf("sandboxd-alerts.yml does not parse: %v", err)
	}
	runbook, err := os.ReadFile(filepath.Join(root, "setup", "runbooks", "cluster-upgrades.md"))
	if err != nil {
		t.Fatal(err)
	}
	anchors := map[string]bool{}
	for _, line := range strings.Split(string(runbook), "\n") {
		if strings.HasPrefix(line, "## ") {
			anchors[strings.ToLower(strings.ReplaceAll(strings.TrimPrefix(line, "## "), " ", "-"))] = true
		}
	}
	want := map[string]string{
		"SandboxdRolloutFailed":            "critical",
		"SandboxdRolloutStuck":             "warning",
		"SandboxdRolloutNodeWaiting":       "warning",
		"SandboxdMemberBelowActiveVersion": "warning",
	}
	registered := goMetricLiterals(t, root)
	metricRE := regexp.MustCompile(`aerolvm_[a-z0-9_]+`)
	labelRE := regexp.MustCompile(`\{([a-z_0-9]+)=`)
	const runbookURL = "https://github.com/aerol-ai/microvm/blob/main/setup/runbooks/cluster-upgrades.md#"
	seen := map[string]bool{}
	for _, g := range rules.Groups {
		if g.Name != "sandboxd.rollouts" {
			continue
		}
		for _, r := range g.Rules {
			seen[r.Alert] = true
			if sev, ok := want[r.Alert]; !ok || r.Labels["severity"] != sev {
				t.Errorf("%s: unexpected, or severity %q", r.Alert, r.Labels["severity"])
			}
			if r.Expr == "" || r.For == "" || r.Labels["component"] != "rollout" || r.Annotations["summary"] == "" || r.Annotations["description"] == "" {
				t.Errorf("%s: incomplete rule %+v", r.Alert, r)
			}
			anchor, ok := strings.CutPrefix(r.Annotations["runbook_url"], runbookURL)
			if !ok || !anchors[anchor] {
				t.Errorf("%s: runbook_url %q is not a heading of cluster-upgrades.md", r.Alert, r.Annotations["runbook_url"])
			}
			for _, name := range metricRE.FindAllString(r.Expr, -1) {
				if !registered[name] {
					t.Errorf("%s queries %s, which no Go file registers", r.Alert, name)
				}
			}
			for _, m := range labelRE.FindAllStringSubmatch(r.Expr, -1) {
				if m[1] != "key" {
					t.Errorf("%s uses label %s; expvar maps export only key", r.Alert, m[1])
				}
			}
		}
	}
	for name := range want {
		if !seen[name] {
			t.Errorf("alert %s missing", name)
		}
	}
}
