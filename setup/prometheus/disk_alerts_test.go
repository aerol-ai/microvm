package prometheus_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestSandboxDiskAlertRule lints C27's sandbox volume alert: it exists, is
// complete, queries only registered metrics, and its runbook_url lands on a
// heading of setup/runbooks/slo-breach.md.
func TestSandboxDiskAlertRule(t *testing.T) {
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "setup", "prometheus", "sandboxd-alerts.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var rules ruleFile
	if err := yaml.Unmarshal(raw, &rules); err != nil {
		t.Fatal(err)
	}
	runbook, err := os.ReadFile(filepath.Join(root, "setup", "runbooks", "slo-breach.md"))
	if err != nil {
		t.Fatal(err)
	}
	anchors := map[string]bool{}
	for _, line := range strings.Split(string(runbook), "\n") {
		for _, prefix := range []string{"## ", "### "} {
			if strings.HasPrefix(line, prefix) {
				anchors[strings.ToLower(strings.ReplaceAll(strings.TrimPrefix(line, prefix), " ", "-"))] = true
			}
		}
	}
	registered := goMetricLiterals(t, root)
	metricRE := regexp.MustCompile(`aerolvm_[a-z0-9_]+`)
	const runbookURL = "https://github.com/aerol-ai/microvm/blob/main/setup/runbooks/slo-breach.md#"

	found := false
	for _, g := range rules.Groups {
		for _, r := range g.Rules {
			if r.Alert != "SandboxdSandboxDiskHigh" {
				continue
			}
			found = true
			if r.Expr == "" || r.For == "" || r.Labels["severity"] != "warning" || r.Labels["component"] != "capacity" ||
				r.Annotations["summary"] == "" || r.Annotations["description"] == "" {
				t.Fatalf("incomplete rule %+v", r)
			}
			// A host without a disk probe reports a zero total; the rule
			// must skip it rather than divide by zero.
			if !strings.Contains(r.Expr, "aerolvm_host_pressure_sandbox_disk_total_mb > 0") || !strings.Contains(r.Expr, "> 0.8") {
				t.Fatalf("expr %q must fire above 80%% used and skip hosts without a probe", r.Expr)
			}
			for _, m := range metricRE.FindAllString(r.Expr, -1) {
				if !registered[m] {
					t.Fatalf("queries %s, which no Go code registers", m)
				}
			}
			anchor, ok := strings.CutPrefix(r.Annotations["runbook_url"], runbookURL)
			if !ok || !anchors[anchor] {
				t.Fatalf("runbook_url %q does not land on a slo-breach.md heading", r.Annotations["runbook_url"])
			}
		}
	}
	if !found {
		t.Fatal("alert SandboxdSandboxDiskHigh missing")
	}
}
