package safety

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// The Helm values page (docs/src/content/docs/kubernetes/values.mdx) is the
// one reference for the chart's settings. The two hand-kept tables it
// replaced had drifted from charts/aerolvm/values.yaml: worker.stateVolume
// was described in prose but in neither table, and several cluster.*
// settings were missing. So both directions are checked:
//
//   - every setting in values.yaml is named on the page, in backticks, or
//     its direct parent is (`cluster.servers.storage` covers its size and
//     storageClassName);
//   - every dotted setting the page names exists in values.yaml, so a
//     renamed or misspelled one fails here instead of in a reader's install.
//
// Kubernetes-shaped values (resources, nodeSelector, a volume source...) are
// one setting each: the page names the value, not its inner fields.

var opaqueValueKeys = map[string]bool{
	"resources": true, "nodeSelector": true, "tolerations": true, "affinity": true,
	"annotations": true, "labels": true, "podLabels": true, "issuerRef": true,
	"containerdVolume": true, "stateVolume": true,
}

func TestHelmValuesPageCoversValuesYAML(t *testing.T) {
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "charts", "aerolvm", "values.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var values map[string]any
	if err := yaml.Unmarshal(raw, &values); err != nil {
		t.Fatal(err)
	}
	page, err := os.ReadFile(filepath.Join(root, "docs", "src", "content", "docs", "kubernetes", "values.mdx"))
	if err != nil {
		t.Fatal(err)
	}

	leaves, inner := map[string]bool{}, map[string]bool{}
	walkValues(values, "", leaves, inner)
	named := namedValues(string(page), values)

	var missing []string
	for leaf := range leaves {
		parent := leaf[:max(strings.LastIndex(leaf, "."), 0)]
		if !named[leaf] && (parent == "" || !named[parent]) {
			missing = append(missing, leaf)
		}
	}
	sort.Strings(missing)
	for _, m := range missing {
		t.Errorf("values.yaml has %s, but the Helm values page names neither it nor its parent", m)
	}

	var unknown []string
	for n := range named {
		if !leaves[n] && !inner[n] {
			unknown = append(unknown, n)
		}
	}
	sort.Strings(unknown)
	for _, u := range unknown {
		t.Errorf("the Helm values page names `%s`, which values.yaml does not have", u)
	}
}

// walkValues records every setting path: leaves (a scalar, a list, an empty
// map or an opaque Kubernetes value) and the maps above them.
func walkValues(node map[string]any, prefix string, leaves, inner map[string]bool) {
	for k, v := range node {
		path := k
		if prefix != "" {
			path = prefix + "." + k
		}
		m, isMap := v.(map[string]any)
		if !isMap || len(m) == 0 || opaqueValueKeys[k] {
			leaves[path] = true
			continue
		}
		inner[path] = true
		walkValues(m, path, leaves, inner)
	}
}

// namedValues is every backticked setting on the page: a dotted path whose
// first part is a top-level key of values.yaml, or a top-level scalar alone
// (`mode`).
func namedValues(page string, values map[string]any) map[string]bool {
	out := map[string]bool{}
	for _, m := range regexp.MustCompile("`([A-Za-z][A-Za-z0-9]*(?:\\.[A-Za-z][A-Za-z0-9]*)*)`").FindAllStringSubmatch(page, -1) {
		path := m[1]
		top, rest, dotted := strings.Cut(path, ".")
		v, ok := values[top]
		if !ok {
			continue
		}
		if _, isMap := v.(map[string]any); dotted && rest != "" || !isMap {
			out[path] = true
		}
	}
	return out
}
