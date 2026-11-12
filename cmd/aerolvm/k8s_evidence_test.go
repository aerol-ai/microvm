package main

import (
	"context"
	"html"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The evidence pack (P7) lists exactly the rules verify checks, in order:
// what the pack promises a bank is what the command proves. Change a rule
// and the pack in the same commit.
func TestEvidencePackListsVerifyRules(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "charts", "aerolvm", "EVIDENCE.md"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	start, end := strings.Index(text, "<!-- verify-rules:start -->"), strings.Index(text, "<!-- verify-rules:end -->")
	if start < 0 || end < start {
		t.Fatal("EVIDENCE.md has no verify-rules block")
	}
	var listed []string
	for _, line := range strings.Split(text[start:end], "\n") {
		if item, ok := strings.CutPrefix(strings.TrimSpace(line), "- "); ok {
			listed = append(listed, html.UnescapeString(item))
		}
	}
	if strings.Join(listed, "\n") != strings.Join(k8sVerifyRules, "\n") {
		t.Fatalf("EVIDENCE.md lists:\n  %s\nverify checks:\n  %s", strings.Join(listed, "\n  "), strings.Join(k8sVerifyRules, "\n  "))
	}
}

// Every check verify reports on a full cluster-mode install is a rule in
// the registry, and every rule is reported: the registry is the whole list.
func TestVerifyReportsEveryRule(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range k8sVerify(context.Background(), clusterK8s().env(), k8sClusterOpts) {
		name := c.Name
		for _, rt := range k8sClusterOpts.probeRuntimes {
			name = strings.Replace(name, "a "+rt+" sandbox", "a <runtime> sandbox", 1)
		}
		seen[name] = true
	}
	for _, rule := range k8sVerifyRules {
		if !seen[rule] {
			t.Errorf("rule %q was not reported", rule)
		}
		delete(seen, rule)
	}
	for name := range seen {
		t.Errorf("check %q is not in k8sVerifyRules", name)
	}
}
