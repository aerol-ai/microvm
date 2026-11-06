package createpolicy

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
)

const full = `version: 1
images:
  allowed_registries: [GHCR.io, index.docker.io, "registry.corp:5000"]
  allowed: ["python:3.12*", "docker.io/acme/*", "aerolvm-snapshot/*"]
runtimes: [gvisor, firecracker]
limits:
  max_cpu: 4
  max_memory_mb: 8192
  max_disk_gb: 50
require_non_root: true
allow_gpu: false
`

func mustParse(t *testing.T, doc string) *Policy {
	t.Helper()
	p, err := Parse([]byte(doc))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return p
}

func ruleOf(t *testing.T, err error) string {
	t.Helper()
	if err == nil {
		return ""
	}
	if !errors.Is(err, models.ErrCreatePolicyDenied) {
		t.Fatalf("refusal %v must match models.ErrCreatePolicyDenied", err)
	}
	var pe *models.CreatePolicyError
	if !errors.As(err, &pe) {
		t.Fatalf("refusal %v is not a *models.CreatePolicyError", err)
	}
	return pe.Rule
}

func TestParseFull(t *testing.T) {
	p := mustParse(t, full)
	if p.Hash() == "" || !p.RequireNonRoot() || !p.HasImageRules() {
		t.Fatalf("parsed policy lost settings: hash=%q nonroot=%v images=%v", p.Hash(), p.RequireNonRoot(), p.HasImageRules())
	}
	for _, host := range []string{"ghcr.io", "docker.io", "registry.corp:5000"} {
		if !p.registries[host] {
			t.Errorf("registry %s must be normalized into the set, got %v", host, p.registries)
		}
	}
}

func TestNilAndEmptyPolicyAllowEverything(t *testing.T) {
	big := Create{Image: "nginx", ImageRules: true, Runtime: "docker", CPU: 64, MemoryMB: 1 << 20, DiskGB: 4096, GPU: true}
	var nilPolicy *Policy
	for name, p := range map[string]*Policy{"nil": nilPolicy, "version only": mustParse(t, "version: 1\n")} {
		if err := p.CheckCreate(big); err != nil {
			t.Errorf("%s policy refused %v", name, err)
		}
		if p.RequireNonRoot() || p.HasImageRules() {
			t.Errorf("%s policy must have no rules", name)
		}
	}
	if nilPolicy.Hash() != "" {
		t.Fatal("nil policy has no hash")
	}
}

// TestCheckCreatePerRule walks every rule with one allowed and one refused
// create, and checks the refusal names the rule.
func TestCheckCreatePerRule(t *testing.T) {
	p := mustParse(t, full)
	ok := Create{Image: "python:3.12", ImageRules: true, Runtime: "gvisor", CPU: 2, MemoryMB: 1024, DiskGB: 10}
	cases := []struct {
		name string
		edit func(*Create)
		rule string // "" = allowed
	}{
		{"baseline", func(*Create) {}, ""},
		{"allowed runtime firecracker", func(c *Create) { c.Runtime = "firecracker" }, ""},
		{"runtime not listed", func(c *Create) { c.Runtime = "docker" }, RuleRuntimes},
		{"runtime empty", func(c *Create) { c.Runtime = "" }, RuleRuntimes},
		{"image by short pattern", func(c *Create) { c.Image = "python:3.12-slim" }, ""},
		{"image by full spelling of short pattern", func(c *Create) { c.Image = "index.docker.io/library/python:3.12" }, ""},
		{"image by full pattern", func(c *Create) { c.Image = "acme/app:v1" }, ""},
		{"image by registry", func(c *Create) { c.Image = "ghcr.io/anyone/tool@sha256:" + strings.Repeat("a", 64) }, ""},
		{"image by registry with port", func(c *Create) { c.Image = "registry.corp:5000/team/app" }, ""},
		{"docker hub via registry list", func(c *Create) { c.Image = "nginx" }, ""},
		{"local snapshot by pattern", func(c *Create) { c.Image = "aerolvm-snapshot/abc:latest"; c.LocalOnly = true }, ""},
		{"image id refused", func(c *Create) { c.Image = "sha256:abcd"; c.ImageID = true }, RuleImages},
		{"invalid reference refused", func(c *Create) { c.Image = "Not A Ref" }, RuleImages},
		{"image rules skipped for wasm", func(c *Create) { c.Image = "evil.example/x"; c.ImageRules = false }, ""},
		{"cpu at limit", func(c *Create) { c.CPU = 4 }, ""},
		{"cpu above limit", func(c *Create) { c.CPU = 4.5 }, RuleMaxCPU},
		{"memory above limit", func(c *Create) { c.MemoryMB = 8193 }, RuleMaxMemoryMB},
		{"disk above limit", func(c *Create) { c.DiskGB = 51 }, RuleMaxDiskGB},
		{"gpu refused", func(c *Create) { c.GPU = true }, RuleAllowGPU},
	}
	for _, tc := range cases {
		c := ok
		tc.edit(&c)
		if got := ruleOf(t, p.CheckCreate(c)); got != tc.rule {
			t.Errorf("%s: rule = %q, want %q", tc.name, got, tc.rule)
		}
	}
}

func TestCheckImageRules(t *testing.T) {
	registriesOnly := mustParse(t, "version: 1\nimages:\n  allowed_registries: [docker.io]\n")
	patternsOnly := mustParse(t, "version: 1\nimages:\n  allowed: [\"ghcr.io/acme/*\"]\n")
	cases := []struct {
		name      string
		p         *Policy
		image     string
		localOnly bool
		allowed   bool
	}{
		{"hub image passes by registry", registriesOnly, "alpine:3.20", false, true},
		{"other registry refused", registriesOnly, "ghcr.io/acme/app", false, false},
		// A local commit parses as docker.io but was never pulled from it.
		{"local-only image needs a pattern", registriesOnly, "aerolvm-build/node-x/abc:latest", true, false},
		{"pattern matches nested path", patternsOnly, "ghcr.io/acme/team/app:1", true, true},
		{"pattern is anchored", patternsOnly, "evil.io/ghcr.io/acme/app", false, false},
		{"hub image refused without a rule", patternsOnly, "python:3.12", false, false},
	}
	for _, tc := range cases {
		err := tc.p.CheckImage(tc.image, tc.localOnly, false)
		if (err == nil) != tc.allowed {
			t.Errorf("%s: CheckImage(%q) = %v, want allowed=%v", tc.name, tc.image, err, tc.allowed)
		}
		if err != nil && !strings.Contains(err.Error(), `"images"`) {
			t.Errorf("%s: refusal must name the images rule: %v", tc.name, err)
		}
	}
}

func TestCheckSizeZeroIsUnchanged(t *testing.T) {
	p := mustParse(t, full)
	if err := p.CheckSize(0, 0, 0); err != nil {
		t.Fatalf("a resize that changes nothing must pass: %v", err)
	}
	if got := ruleOf(t, p.CheckSize(0, 0, 60)); got != RuleMaxDiskGB {
		t.Fatalf("disk-only resize rule = %q", got)
	}
	var nilPolicy *Policy
	if err := nilPolicy.CheckSize(1e9, 1<<30, 1<<30); err != nil {
		t.Fatal(err)
	}
}

func TestParseRefusesBadFiles(t *testing.T) {
	cases := map[string]string{
		"not yaml":            "version: [1",
		"wrong version":       "version: 2\n",
		"missing version":     "runtimes: [docker]\n",
		"unknown key":         "version: 1\nmax_cpu: 4\n",
		"typo in nested key":  "version: 1\nlimits:\n  max_cpus: 4\n",
		"empty runtimes":      "version: 1\nruntimes: []\n",
		"empty images":        "version: 1\nimages:\n  allowed: []\n",
		"empty registries":    "version: 1\nimages:\n  allowed_registries: []\n",
		"unknown runtime":     "version: 1\nruntimes: [podman]\n",
		"blank runtime":       "version: 1\nruntimes: [\"\"]\n",
		"registry with path":  "version: 1\nimages:\n  allowed_registries: [ghcr.io/acme]\n",
		"registry with star":  "version: 1\nimages:\n  allowed_registries: [\"*.io\"]\n",
		"registry scheme":     "version: 1\nimages:\n  allowed_registries: [\"https://ghcr.io\"]\n",
		"blank pattern":       "version: 1\nimages:\n  allowed: [\" \"]\n",
		"pattern with space":  "version: 1\nimages:\n  allowed: [\"a b\"]\n",
		"negative cpu":        "version: 1\nlimits:\n  max_cpu: -1\n",
		"nan cpu":             "version: 1\nlimits:\n  max_cpu: .nan\n",
		"infinite cpu":        "version: 1\nlimits:\n  max_cpu: .inf\n",
		"negative memory":     "version: 1\nlimits:\n  max_memory_mb: -1\n",
		"negative disk":       "version: 1\nlimits:\n  max_disk_gb: -5\n",
		"non-bool non-root":   "version: 1\nrequire_non_root: sometimes\n",
		"non-bool gpu switch": "version: 1\nallow_gpu: maybe\n",
	}
	for name, doc := range cases {
		if _, err := Parse([]byte(doc)); err == nil {
			t.Errorf("%s: Parse accepted %q", name, doc)
		}
	}
	long := "version: 1\nruntimes: [" + strings.TrimSuffix(strings.Repeat("docker,", maxListEntries+1), ",") + "]\n"
	if _, err := Parse([]byte(long)); err == nil || !strings.Contains(err.Error(), "at most") {
		t.Fatalf("an over-long list must be refused, got %v", err)
	}
}

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	if _, err := Load(filepath.Join(dir, "missing.yaml")); err == nil {
		t.Fatal("a missing file must not load")
	}
	path := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(path, []byte(full), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := Load(path)
	if err != nil || !p.RequireNonRoot() {
		t.Fatalf("Load = %v, %v", p, err)
	}
}

func TestGlobMatch(t *testing.T) {
	cases := []struct {
		pattern, s string
		want       bool
	}{
		{"*", "", true},
		{"*", "anything/at:all", true},
		{"", "", true},
		{"", "x", false},
		{"python:3.12*", "python:3.12-slim", true},
		{"python:3.12*", "python:3.11", false},
		{"ghcr.io/*/app:*", "ghcr.io/a/b/app:1", true},
		{"a*b*c", "aXXbYYc", true},
		{"a*b*c", "aXXbYY", false},
		{"**", "x", true},
		{"exact", "exact", true},
		{"exact", "exactly", false},
		// Backtracking: the first "b" is not the one the pattern needs.
		{"*bc", "abbc", true},
	}
	for _, tc := range cases {
		if got := globMatch(tc.pattern, tc.s); got != tc.want {
			t.Errorf("globMatch(%q, %q) = %v, want %v", tc.pattern, tc.s, got, tc.want)
		}
	}
}
