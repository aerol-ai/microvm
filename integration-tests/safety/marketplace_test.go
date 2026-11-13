package safety

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"
)

// The marketplace packages (packaging/marketplace) are checked by hand only
// when a listing is submitted, so these keep them in step with the chart
// in between: a renamed setting, a new image or a form field the ARM
// template does not take would otherwise surface at review time.

func readJSON(t *testing.T, path string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return out
}

// Every setting the EKS add-on schema offers is a setting the chart has.
func TestEKSAddonSchemaMatchesTheChart(t *testing.T) {
	root := repoRoot(t)
	schema := readJSON(t, filepath.Join(root, "packaging", "marketplace", "aws-eks-addon", "configuration-schema.json"))
	values, err := os.ReadFile(filepath.Join(root, "charts", "aerolvm", "values.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var walk func(props map[string]any, path []string)
	walk = func(props map[string]any, path []string) {
		for key, v := range props {
			p := append(slices.Clone(path), key)
			indent := strings.Repeat("  ", len(p)-1)
			if !regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(indent+key) + `:`).Match(values) {
				t.Errorf("the add-on schema offers %s, which charts/aerolvm/values.yaml does not have", strings.Join(p, "."))
			}
			if m, ok := v.(map[string]any); ok {
				if sub, ok := m["properties"].(map[string]any); ok {
					walk(sub, p)
				}
			}
		}
	}
	walk(schema["properties"].(map[string]any), nil)
	if req, _ := schema["required"].([]any); !slices.Contains(req, any("apiToken")) {
		t.Error("the add-on schema must require apiToken: an add-on cannot keep a token the chart makes")
	}
}

// The Azure package names every image the chart uses, and its ARM template
// takes every value its portal form hands over.
func TestAzurePackageMatchesTheChart(t *testing.T) {
	root := repoRoot(t)
	dir := filepath.Join(root, "packaging", "marketplace", "azure")

	var used []string
	err := filepath.WalkDir(filepath.Join(root, "charts", "aerolvm", "templates"), func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		for _, m := range regexp.MustCompile(`"aerolvm\.image" \(dict "root" \S+ "name" "([a-z-]+)"\)`).FindAllSubmatch(raw, -1) {
			if !slices.Contains(used, string(m[1])) {
				used = append(used, string(m[1]))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(used)
	azure, err := os.ReadFile(filepath.Join(dir, "values-azure.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var named []string
	for _, m := range regexp.MustCompile(`(?m)^      ([a-z-]+):\n        registry: \S+\n        image: \S+\n        digest: ""`).FindAllSubmatch(azure, -1) {
		named = append(named, string(m[1]))
	}
	sort.Strings(named)
	if len(used) == 0 || !slices.Equal(used, named) {
		t.Errorf("the chart uses images %v; values-azure.yaml names %v", used, named)
	}

	form := readJSON(t, filepath.Join(dir, "createUiDefinition.json"))
	outputs := form["parameters"].(map[string]any)["outputs"].(map[string]any)
	tmpl := readJSON(t, filepath.Join(dir, "mainTemplate.json"))
	params := tmpl["parameters"].(map[string]any)
	for name := range outputs {
		if _, ok := params[name]; !ok {
			t.Errorf("the portal form outputs %s, which mainTemplate.json does not take", name)
		}
	}

	manifest, err := os.ReadFile(filepath.Join(dir, "manifest.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"clusterArmTemplate: ./mainTemplate.json", "uiDefinition: ./createUiDefinition.json", "helmChart: ./aerolvm"} {
		if !strings.Contains(string(manifest), want) {
			t.Errorf("manifest.yaml lacks %q (cpa's keys; build.sh lays the chart out as ./aerolvm)", want)
		}
	}
}
