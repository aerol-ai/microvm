package prometheus_test

import (
	"os"
	"path/filepath"
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
