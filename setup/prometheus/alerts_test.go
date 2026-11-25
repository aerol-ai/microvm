package prometheus_test

import (
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

type ruleFile struct {
	Groups []struct {
		Name  string `yaml:"name"`
		Rules []struct {
			Alert       string            `yaml:"alert"`
			Expr        string            `yaml:"expr"`
			For         string            `yaml:"for"`
			Labels      map[string]string `yaml:"labels"`
			Annotations map[string]string `yaml:"annotations"`
		} `yaml:"rules"`
	} `yaml:"groups"`
}

func repoRoot(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Join(filepath.Dir(filename), "..", "..")
}

// TestIdentityAlertRules lints the identity-and-access alert group
// (plans/identity-and-access.md §5.15, CEO review D22): the six alerts (the
// mirror one at two severities) exist, every rule is complete, every metric
// it queries is registered in the Go tree, and every runbook_url lands on a
// heading of setup/runbooks/identity-and-access.md.
func TestIdentityAlertRules(t *testing.T) {
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "setup", "prometheus", "sandboxd-alerts.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var rules ruleFile
	if err := yaml.Unmarshal(raw, &rules); err != nil {
		t.Fatalf("sandboxd-alerts.yml does not parse: %v", err)
	}
	runbook, err := os.ReadFile(filepath.Join(root, "setup", "runbooks", "identity-and-access.md"))
	if err != nil {
		t.Fatal(err)
	}
	anchors := map[string]bool{}
	for _, line := range strings.Split(string(runbook), "\n") {
		if strings.HasPrefix(line, "## ") {
			anchors[strings.ToLower(strings.ReplaceAll(strings.TrimPrefix(line, "## "), " ", "-"))] = true
		}
	}
	registered := goMetricLiterals(t, root)
	metricRE := regexp.MustCompile(`aerolvm_[a-z0-9_]+`)
	const runbookURL = "https://github.com/aerol-ai/microvm/blob/main/setup/runbooks/identity-and-access.md#"

	want := map[string]string{
		"SandboxdBreakGlassPATUse":             "warning",
		"SandboxdPATScopeDrift":                "warning",
		"SandboxdIdentityMirrorStale":          "warning",
		"SandboxdIdentityMirrorRefusingTokens": "critical",
		"SandboxdIdentityJWKSFailing":          "warning",
		"SandboxdIdentityFileDrift":            "warning",
		"SandboxdIdentityFileLoadErrors":       "warning",
	}
	seen := map[string]bool{}
	for _, g := range rules.Groups {
		if g.Name != "sandboxd.identity-and-access" {
			continue
		}
		for _, r := range g.Rules {
			seen[r.Alert] = true
			if sev, ok := want[r.Alert]; !ok {
				t.Errorf("unexpected alert %q in the identity group", r.Alert)
			} else if r.Labels["severity"] != sev {
				t.Errorf("%s: severity %q, want %q", r.Alert, r.Labels["severity"], sev)
			}
			if r.Expr == "" || r.For == "" || r.Labels["component"] != "identity" ||
				r.Annotations["summary"] == "" || r.Annotations["description"] == "" {
				t.Errorf("%s: incomplete rule %+v", r.Alert, r)
			}
			anchor, ok := strings.CutPrefix(r.Annotations["runbook_url"], runbookURL)
			if !ok || !anchors[anchor] {
				t.Errorf("%s: runbook_url %q is not a heading of identity-and-access.md", r.Alert, r.Annotations["runbook_url"])
			}
			for _, name := range metricRE.FindAllString(r.Expr, -1) {
				if !registered[name] {
					t.Errorf("%s queries %s, which no Go file registers", r.Alert, name)
				}
			}
			// The auth metrics are expvar maps: positional key/key2 labels.
			if strings.Contains(r.Expr, "kind=") || strings.Contains(r.Expr, "origin=") || strings.Contains(r.Expr, "reason=") {
				t.Errorf("%s uses a label sandboxd does not export (key/key2 only): %s", r.Alert, r.Expr)
			}
		}
	}
	var missing []string
	for name := range want {
		if !seen[name] {
			missing = append(missing, name)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("identity alerts missing: %v", missing)
	}
}

// goMetricLiterals collects every "aerolvm_…" string literal in the
// non-test Go files under cmd/, internal/ and pkg/.
func goMetricLiterals(t *testing.T, root string) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	literal := regexp.MustCompile(`"(aerolvm_[a-z0-9_]+)"`)
	for _, dir := range []string{"cmd", "internal", "pkg"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return err
			}
			src, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			for _, m := range literal.FindAllStringSubmatch(string(src), -1) {
				out[m[1]] = true
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return out
}

// TestClusterJoinAlertRules lints the join and cert-renewal alerts
// (plans/kubectl-style-cluster-ops.md §10.1): both exist, are complete, and
// every aerolvm_ metric they query is registered in the Go tree.
func TestClusterJoinAlertRules(t *testing.T) {
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "setup", "prometheus", "sandboxd-alerts.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var rules ruleFile
	if err := yaml.Unmarshal(raw, &rules); err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"SandboxdClusterCertRenewalFailing": false, "SandboxdClusterJoinsFailing": false}
	metrics := goMetricLiterals(t, root)
	metric := regexp.MustCompile(`aerolvm_[a-z0-9_]+`)
	for _, g := range rules.Groups {
		for _, r := range g.Rules {
			if _, ok := want[r.Alert]; !ok {
				continue
			}
			want[r.Alert] = true
			if r.Expr == "" || r.For == "" || r.Labels["severity"] == "" || r.Annotations["summary"] == "" || r.Annotations["description"] == "" || r.Annotations["runbook_url"] == "" {
				t.Fatalf("%s is incomplete: %+v", r.Alert, r)
			}
			for _, m := range metric.FindAllString(r.Expr, -1) {
				if !metrics[m] {
					t.Fatalf("%s queries %s, which no Go code registers", r.Alert, m)
				}
			}
		}
	}
	for name, seen := range want {
		if !seen {
			t.Fatalf("alert %s missing", name)
		}
	}
}

// TestKeyCustodyAlertRules lints the key-custody alert group
// (plans/customer-key-custody.md Section 8): the four alerts exist with
// their severities, every rule is complete, every metric it queries is
// registered in the Go tree, labels are the positional key/key2/key3 an
// expvar map exports, and every runbook_url lands on a heading of
// setup/runbooks/secrets-and-audit.md.
func TestKeyCustodyAlertRules(t *testing.T) {
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "setup", "prometheus", "sandboxd-alerts.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var rules ruleFile
	if err := yaml.Unmarshal(raw, &rules); err != nil {
		t.Fatalf("sandboxd-alerts.yml does not parse: %v", err)
	}
	runbook, err := os.ReadFile(filepath.Join(root, "setup", "runbooks", "secrets-and-audit.md"))
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
	labelRE := regexp.MustCompile(`([a-z_0-9]+)(=~|!=|=)"`)
	const runbookURL = "https://github.com/aerol-ai/microvm/blob/main/setup/runbooks/secrets-and-audit.md#"

	want := map[string]string{
		"SandboxdServerKeyPlaintext":     "warning",
		"SandboxdKeyRevoked":             "critical",
		"SandboxdKeyVersionRetiredInUse": "warning",
		"SandboxdKeyStoreThrottling":     "warning",
	}
	seen := map[string]bool{}
	for _, g := range rules.Groups {
		if g.Name != "sandboxd.key-custody" {
			continue
		}
		for _, r := range g.Rules {
			seen[r.Alert] = true
			if sev, ok := want[r.Alert]; !ok {
				t.Errorf("unexpected alert %q in the key-custody group", r.Alert)
			} else if r.Labels["severity"] != sev {
				t.Errorf("%s: severity %q, want %q", r.Alert, r.Labels["severity"], sev)
			}
			if r.Expr == "" || r.For == "" || r.Labels["component"] != "key-custody" ||
				r.Annotations["summary"] == "" || r.Annotations["description"] == "" {
				t.Errorf("%s: incomplete rule %+v", r.Alert, r)
			}
			anchor, ok := strings.CutPrefix(r.Annotations["runbook_url"], runbookURL)
			if !ok || !anchors[anchor] {
				t.Errorf("%s: runbook_url %q is not a heading of secrets-and-audit.md", r.Alert, r.Annotations["runbook_url"])
			}
			for _, name := range metricRE.FindAllString(r.Expr, -1) {
				if !registered[name] {
					t.Errorf("%s queries %s, which no Go file registers", r.Alert, name)
				}
			}
			for _, m := range labelRE.FindAllStringSubmatch(r.Expr, -1) {
				if m[1] != "key" && m[1] != "key2" && m[1] != "key3" {
					t.Errorf("%s uses label %q; sandboxd exports key/key2/key3 only", r.Alert, m[1])
				}
			}
		}
	}
	var missing []string
	for name := range want {
		if !seen[name] {
			missing = append(missing, name)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("key-custody alerts missing: %v", missing)
	}
}

// TestRootHelperRefusalAlertRule lints the root helper group
// (plans/security-gaps-m1-m4.md §3.3, eng review D9): the one alert pages
// at once on any refusal, it is complete, the metric it reads is
// registered in the Go tree, it groups by the positional key/key2 an
// expvar map exports (call and reason), it keeps the clause that fires on
// a counter's first refusal, and its runbook_url lands on a heading of
// setup/runbooks/secrets-and-audit.md. promtool proves the expression in
// TestRootHelperRefusalAlertFires.
func TestRootHelperRefusalAlertRule(t *testing.T) {
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "setup", "prometheus", "sandboxd-alerts.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var rules ruleFile
	if err := yaml.Unmarshal(raw, &rules); err != nil {
		t.Fatalf("sandboxd-alerts.yml does not parse: %v", err)
	}
	runbook, err := os.ReadFile(filepath.Join(root, "setup", "runbooks", "secrets-and-audit.md"))
	if err != nil {
		t.Fatal(err)
	}
	anchors := map[string]bool{}
	for _, line := range strings.Split(string(runbook), "\n") {
		for _, prefix := range []string{"## ", "### "} {
			if heading, ok := strings.CutPrefix(line, prefix); ok {
				anchors[githubAnchor(heading)] = true
			}
		}
	}
	registered := goMetricLiterals(t, root)
	metricRE := regexp.MustCompile(`aerolvm_[a-z0-9_]+`)
	byRE := regexp.MustCompile(`by \(([^)]*)\)`)
	const runbookURL = "https://github.com/aerol-ai/microvm/blob/main/setup/runbooks/secrets-and-audit.md#"

	var found int
	for _, g := range rules.Groups {
		if g.Name != "sandboxd.root-helper" {
			continue
		}
		for _, r := range g.Rules {
			if r.Alert != "SandboxdRootHelperRefusal" {
				t.Errorf("unexpected alert %q in the root helper group", r.Alert)
				continue
			}
			found++
			// One refusal is a page: no waiting, and the top severity.
			if r.For != "0m" || r.Labels["severity"] != "critical" || r.Labels["component"] != "root-helper" ||
				r.Annotations["summary"] == "" || r.Annotations["description"] == "" {
				t.Errorf("incomplete or delayed rule %+v", r)
			}
			anchor, ok := strings.CutPrefix(r.Annotations["runbook_url"], runbookURL)
			if !ok || !anchors[anchor] {
				t.Errorf("runbook_url %q is not a heading of secrets-and-audit.md", r.Annotations["runbook_url"])
			}
			names := metricRE.FindAllString(r.Expr, -1)
			if len(names) == 0 {
				t.Errorf("the expression reads no aerolvm_ metric: %s", r.Expr)
			}
			for _, name := range names {
				if name != "aerolvm_rootd_refusals_total" || !registered[name] {
					t.Errorf("queries %s; want aerolvm_rootd_refusals_total, registered in the Go tree", name)
				}
			}
			for _, m := range byRE.FindAllStringSubmatch(r.Expr, -1) {
				for _, label := range strings.Split(m[1], ",") {
					if l := strings.TrimSpace(label); l != "instance" && l != "key" && l != "key2" {
						t.Errorf("groups by %q; sandboxd exports key/key2 only", l)
					}
				}
			}
			// increase() sees no rise on a series' first sample, and a
			// refusal's series is born at 1: without this clause the first
			// refusal on a node, usually the only one, never fires.
			if !strings.Contains(r.Expr, "unless aerolvm_rootd_refusals_total offset 5m") {
				t.Errorf("the expression lost its first-refusal clause: %s", r.Expr)
			}
		}
	}
	if found != 1 {
		t.Fatalf("SandboxdRootHelperRefusal found %d times in group sandboxd.root-helper, want 1", found)
	}
}

// TestRootHelperRefusalAlertFires runs promtool's unit tests for the alert
// (testdata/sandboxd-rootd-refusals.test.yaml): a node's first refusal, a
// later one and one after a sandboxd restart each fire, and a flat counter
// does not. It runs them on the setup file and again on the chart's copy,
// whose group has no 30s interval of its own. It needs promtool on PATH (or
// PROMTOOL), and skips without it unless AEROLVM_CHART_TOOLS=require; the
// go-tests CI job installs promtool and requires it.
func TestRootHelperRefusalAlertFires(t *testing.T) {
	root := repoRoot(t)
	promtool := chartTool(t, "PROMTOOL", "promtool")
	tests := filepath.Join(root, "setup", "prometheus", "testdata", "sandboxd-rootd-refusals.test.yaml")
	t.Run("setup", func(t *testing.T) {
		if _, err := runTool(t, root, promtool, "test", "rules", tests); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("chart", func(t *testing.T) {
		raw, err := os.ReadFile(tests)
		if err != nil {
			t.Fatal(err)
		}
		const setupRules = "  - ../sandboxd-alerts.yml\n"
		if n := strings.Count(string(raw), setupRules); n != 1 {
			t.Fatalf("%s names ../sandboxd-alerts.yml %d times in rule_files, want 1", tests, n)
		}
		chartTests := filepath.Join(t.TempDir(), "chart-rootd-refusals.test.yaml")
		swapped := strings.Replace(string(raw), setupRules, "  - "+chartRulesPath(root)+"\n", 1)
		if err := os.WriteFile(chartTests, []byte(swapped), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := runTool(t, root, promtool, "test", "rules", chartTests); err != nil {
			t.Fatal(err)
		}
	})
}

// TestChartCarriesSetupAlertsAsIs checks the alerts the Helm chart carries
// from setup/prometheus/sandboxd-alerts.yml (chartSetupAlerts). Each is in
// both files once, and the chart's copy has the same expression (spacing
// aside), for, labels and annotations, runbook link included. Any other
// name in both files fails too: the chart would page under a setup alert's
// name with another rule. Each copy has a pointer entry in the chart's
// runbook, setup/runbooks/kubernetes.md, which lists every alert the chart
// ships. It needs no tools, so it runs in go-tests whenever a rule changes.
func TestChartCarriesSetupAlertsAsIs(t *testing.T) {
	root := repoRoot(t)
	setup := alertsByName(t, filepath.Join(root, "setup", "prometheus", "sandboxd-alerts.yml"))
	chart := alertsByName(t, chartRulesPath(root))
	runbook, err := os.ReadFile(filepath.Join(root, "setup", "runbooks", "kubernetes.md"))
	if err != nil {
		t.Fatal(err)
	}
	headings := map[string]bool{}
	for _, line := range strings.Split(string(runbook), "\n") {
		if name, ok := strings.CutPrefix(line, "## "); ok {
			headings[strings.TrimSpace(name)] = true
		}
	}

	names := make([]string, 0, len(chartSetupAlerts))
	for name := range chartSetupAlerts {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if _, ok := setup[name]; !ok {
			t.Errorf("chartSetupAlerts names %s, which setup/prometheus/sandboxd-alerts.yml does not define", name)
		}
		if _, ok := chart[name]; !ok {
			t.Errorf("the chart's rules (charts/aerolvm/monitoring/rules.yaml) lack %s from setup/prometheus/sandboxd-alerts.yml", name)
		}
		if !headings[name] {
			t.Errorf("setup/runbooks/kubernetes.md has no '## %s' entry for the chart's copy", name)
		}
	}
	for name, c := range chart {
		s, ok := setup[name]
		if !ok {
			continue
		}
		if !chartSetupAlerts[name] {
			t.Errorf("%s is in the chart and in setup/prometheus: add it to chartSetupAlerts or rename one", name)
		}
		c.Expr, s.Expr = strings.Join(strings.Fields(c.Expr), " "), strings.Join(strings.Fields(s.Expr), " ")
		if !reflect.DeepEqual(c, s) {
			t.Errorf("%s: the chart's copy differs from setup/prometheus/sandboxd-alerts.yml\nchart: %+v\nsetup: %+v", name, c, s)
		}
	}
}

// alertsByName reads a rule file's alerts by name, failing on a name
// defined twice.
func alertsByName(t *testing.T, path string) map[string]k8sRule {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var file k8sRuleFile
	if err := yaml.Unmarshal(raw, &file); err != nil {
		t.Fatalf("%s does not parse: %v", path, err)
	}
	out := map[string]k8sRule{}
	for _, g := range file.Groups {
		for _, r := range g.Rules {
			if r.Alert == "" {
				continue
			}
			if _, dup := out[r.Alert]; dup {
				t.Errorf("%s defines %s twice", path, r.Alert)
			}
			out[r.Alert] = r
		}
	}
	if len(out) == 0 {
		t.Fatalf("%s has no alerts", path)
	}
	return out
}

// githubAnchor is the fragment GitHub gives a markdown heading: lower
// case, spaces to hyphens, and every other character but letters, digits,
// hyphens and underscores dropped.
func githubAnchor(heading string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(strings.TrimSpace(heading)) {
		switch {
		case r == ' ':
			b.WriteByte('-')
		case r == '-' || r == '_' || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'):
			b.WriteRune(r)
		}
	}
	return b.String()
}
