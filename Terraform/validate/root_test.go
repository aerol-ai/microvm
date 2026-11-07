package validate

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// Terraform/ is a module used by URL (plans/kubectl-style-cluster-ops.md §7)
// and Terraform/root is the root a checkout runs (scripts/terraform.sh, the
// integration harness). These tests keep the two in step offline: a variable
// the root forgets to pass would silently fall back to the module's default
// for every scenario that sets it, and an output it forgets would break the
// harness's `terraform output` reads.

func readTF(t *testing.T, rel ...string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(append([]string{".."}, rel...)...))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// moduleFiles returns the module's own .tf files (not root/ or examples/).
func moduleFiles(t *testing.T) map[string]string {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join("..", "*.tf"))
	if err != nil || len(paths) == 0 {
		t.Fatalf("no module .tf files: %v", err)
	}
	out := map[string]string{}
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		out[filepath.Base(p)] = string(b)
	}
	return out
}

var (
	variableRe = regexp.MustCompile(`(?m)^variable "([a-z0-9_]+)"`)
	outputRe   = regexp.MustCompile(`(?ms)^output "([a-z0-9_]+)" \{(.*?)^\}`)
	resourceRe = regexp.MustCompile(`(?m)^resource "([a-z0-9_]+)" "([a-z0-9_]+)"`)
	passRe     = regexp.MustCompile(`(?m)^\s+([a-z0-9_]+)\s+= var\.([a-z0-9_]+)$`)
	movedRe    = regexp.MustCompile(`(?m)^moved \{\s*from = ([a-z0-9_.]+)\s*to\s+= ([a-z0-9_.]+)\s*\}`)
	sensRe     = regexp.MustCompile(`(?m)^\s*sensitive\s*=\s*true`)
)

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func TestModuleHasNoRootOnlyBlocks(t *testing.T) {
	// A backend or provider block in the module would stop it being used by
	// URL (no backend) or with count and for_each (no provider config).
	backendRe := regexp.MustCompile(`(?m)^\s*backend\s+"`)
	providerRe := regexp.MustCompile(`(?m)^provider\s+"`)
	for name, body := range moduleFiles(t) {
		if backendRe.MatchString(body) {
			t.Errorf("%s names a backend; only Terraform/root may", name)
		}
		if providerRe.MatchString(body) {
			t.Errorf("%s configures a provider; only a root may", name)
		}
	}
}

func TestRootVariablesMatchTheModule(t *testing.T) {
	// The root declares every module variable with the same type, default and
	// checks, so a tfvars file reads the same through it.
	if readTF(t, "root", "variables.tf") != readTF(t, "variables.tf") {
		t.Fatal("Terraform/root/variables.tf differs from Terraform/variables.tf; run: cp Terraform/variables.tf Terraform/root/variables.tf")
	}
}

func TestRootPassesEveryVariable(t *testing.T) {
	want := map[string]bool{}
	for _, body := range moduleFiles(t) {
		for _, m := range variableRe.FindAllStringSubmatch(body, -1) {
			want[m[1]] = true
		}
	}
	if !want["one_line_join"] || !want["nodes"] {
		t.Fatalf("module variables look wrong: %v", sortedKeys(want))
	}
	main := readTF(t, "root", "main.tf")
	if !strings.Contains(main, `source = "../"`) {
		t.Fatal(`Terraform/root/main.tf must call the module with source = "../" (the harness rewrites that line for module-url scenarios)`)
	}
	got := map[string]bool{}
	for _, m := range passRe.FindAllStringSubmatch(main, -1) {
		if m[1] != m[2] {
			t.Errorf("main.tf passes var.%s as %s", m[2], m[1])
		}
		got[m[1]] = true
	}
	for v := range want {
		if !got[v] {
			t.Errorf("Terraform/root/main.tf does not pass %s = var.%s", v, v)
		}
	}
	for v := range got {
		if !want[v] {
			t.Errorf("Terraform/root/main.tf passes %s, which the module does not declare", v)
		}
	}
	// The root declares what variables.tf does not: one_line_join, with
	// the old join as its default (Terraform/root/join.tf says why).
	join := readTF(t, "root", "join.tf")
	if !regexp.MustCompile(`(?s)variable "one_line_join" \{.*default\s+= false`).MatchString(join) {
		t.Error("Terraform/root/join.tf must declare one_line_join with default = false, so a cluster built from a checkout keeps its machines")
	}
	module := hclVariable(readTF(t, "join.tf"), "one_line_join")
	if !regexp.MustCompile(`default\s+= true`).MatchString(module) {
		t.Error("the module's one_line_join must default to true: one-line joins are how it joins nodes")
	}
	// A root that passes null (the harness's module-url root does) must get
	// the default, not a null the bootstrap template can't branch on.
	if !regexp.MustCompile(`nullable\s+= false`).MatchString(module) {
		t.Error("the module's one_line_join must be nullable = false")
	}
}

// hclVariable returns the variable block named name, or "".
func hclVariable(src, name string) string {
	start := strings.Index(src, `variable "`+name+`" {`)
	if start < 0 {
		return ""
	}
	end := strings.Index(src[start:], "\n}\n")
	if end < 0 {
		return src[start:]
	}
	return src[start : start+end+2]
}

func TestRootForwardsEveryOutput(t *testing.T) {
	want := map[string]bool{} // name -> sensitive
	for _, body := range moduleFiles(t) {
		for _, m := range outputRe.FindAllStringSubmatch(body, -1) {
			want[m[1]] = sensRe.MatchString(m[2])
		}
	}
	got := map[string]bool{}
	for _, m := range outputRe.FindAllStringSubmatch(readTF(t, "root", "outputs.tf"), -1) {
		if !strings.Contains(m[2], "module.aerolvm."+m[1]) {
			t.Errorf("root output %s is not module.aerolvm.%s", m[1], m[1])
		}
		got[m[1]] = sensRe.MatchString(m[2])
	}
	for name, sens := range want {
		gs, ok := got[name]
		switch {
		case !ok:
			t.Errorf("Terraform/root/outputs.tf does not forward output %q", name)
		case gs != sens:
			t.Errorf("root output %q sensitive=%t, module says %t", name, gs, sens)
		}
	}
	for name := range got {
		if _, ok := want[name]; !ok {
			t.Errorf("root output %q has no module output behind it", name)
		}
	}
}

func TestRootMovesOnlyModuleResources(t *testing.T) {
	resources := map[string]bool{}
	for _, body := range moduleFiles(t) {
		for _, m := range resourceRe.FindAllStringSubmatch(body, -1) {
			resources[m[1]+"."+m[2]] = true
		}
	}
	moved := movedRe.FindAllStringSubmatch(readTF(t, "root", "moved.tf"), -1)
	if len(moved) == 0 {
		t.Fatal("Terraform/root/moved.tf has no moved blocks")
	}
	seen := map[string]bool{}
	for _, m := range moved {
		from, to := m[1], m[2]
		if to != "module.aerolvm."+from {
			t.Errorf("moved %s -> %s: want module.aerolvm.%s", from, to, from)
		}
		if !resources[from] {
			t.Errorf("moved block for %s, which the module does not declare", from)
		}
		seen[from] = true
	}
	// Every resource a checkout could have in state before the move. New
	// resources added later need no block: no old state holds them.
	for _, must := range []string{
		"aws_instance.seed", "aws_instance.joiner", "aws_vpc.this", "aws_s3_bucket.bundle",
		"aws_security_group.node", "aws_security_group.join", "random_id.bundle_suffix",
		"random_string.join_token_id", "random_password.join_token_secret",
	} {
		if !resources[must] {
			t.Errorf("the module no longer declares %s; update this list", must)
		}
		if !seen[must] {
			t.Errorf("no moved block for %s", must)
		}
	}
}
